"""Live-mode controller for dart-agent.

Connects Claude to dart-mcp over a stdio subprocess. Claude sees only the
typed forensic tools registered in dart-mcp; it cannot execute arbitrary
code because there is no execute_shell for it to call.

Authentication is resolved by dart_agent.auth. The documented path for real
Claude calls is ANTHROPIC_API_KEY; --dry-run exercises the same MCP plumbing
with a scripted model and no external credential.

Usage:
    python3 -m dart_agent --mode live --case my-case --out /tmp/out \\
        --prompt "Investigate the bundled IP-KVM evidence"

Default model is claude-haiku-4-5-20251001. Override with --model or DART_MODEL env:
    python3 -m dart_agent --mode live --model claude-sonnet-4-6 ...

If --dry-run is given, the controller executes a scripted fake-LLM that
simulates the same tool-calling sequence. This lets CI exercise the live
plumbing with no credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path

# Lazy imports for anthropic + mcp so dry-run can work even without them
_ANTHROPIC_AVAILABLE = False
_MCP_AVAILABLE = False
try:
    import anthropic  # noqa: F401
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    pass
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    _MCP_AVAILABLE = True
except ImportError:
    pass


# Hybrid-architecture guardrail: heavy data is the tool's job; meaning
# is the LLM's job. If a tool returns a wall of text
# (tens of thousands of event-log lines, a giant timeline dump), feeding
# it verbatim to the model blows the context window, costs a fortune, and
# invites hallucination as the model loses the thread. Instead we cap the
# result and tell the model — in-band — to narrow the query rather than
# trying to eyeball the raw dump.
#
# The cap is in characters (a cheap proxy for tokens; ~4 chars/token).
# 24_000 chars ≈ 6k tokens, generous for a structured finding set but far
# below the point where a single tool result dominates the window.
_MCP_RESULT_CHAR_CAP = 24_000

_TRUNCATION_NOTICE = (
    "\n\n...(result truncated: this tool returned more data than fits the "
    "analysis budget. Do NOT try to read the full dump here — instead "
    "re-call the tool with a smaller `limit`, a tighter time window, or a "
    "more specific filter, or use a DuckDB/Python-backed correlation tool "
    "that returns only the matching rows. Heavy filtering is the tool's "
    "job; your job is to interpret the filtered result.)"
)


def _truncate_tool_result(text: str, cap: int = _MCP_RESULT_CHAR_CAP) -> str:
    """Cap an oversized tool result and append a guidance notice.

    Returns the text unchanged when it's within budget. When it exceeds
    the cap, keeps the leading `cap` characters (the start of a JSON
    document carries the schema + first records, which is what the model
    needs to decide how to narrow) and appends the truncation notice.
    """
    if len(text) <= cap:
        return text
    return text[:cap] + _TRUNCATION_NOTICE


def _with_cache_breakpoint(tools: list[dict]) -> list[dict]:
    """Mark the last tool definition with an ephemeral cache breakpoint.

    Prompt caching caches the request prefix up to the
    last cache_control marker. By tagging the FINAL tool, the cached prefix
    spans the system prompt + every tool definition — the large, identical
    part of every iteration. Returns a shallow copy so the caller's list
    isn't mutated; tool dicts themselves are copied only for the one we
    tag. A no-op (returns the list unchanged) when there are no tools.
    """
    if not tools:
        return tools
    out = list(tools)
    last = dict(out[-1])
    last["cache_control"] = {"type": "ephemeral"}
    out[-1] = last
    return out


SYSTEM_PROMPT = """You are Agentic-DART, a senior DFIR analyst.

You have access to a set of typed, read-only forensic functions exposed by
the dart-mcp server. These functions are the ONLY way you can interact
with evidence. You cannot execute shell commands. You cannot write files.
You cannot make network calls. These restrictions are architectural — the
functions simply are not available to you.

Your toolkit has TWO layers:

  1. Native pure-Python tools (e.g. get_amcache, extract_mft_timeline,
     parse_prefetch, parse_unified_log, parse_auditd_log). These run
     without external dependencies and always work.

  2. SIFT Workstation tool adapters (prefix `sift_`). These wrap the
     canonical SIFT toolchain — Volatility 3, MFTECmd, EvtxECmd, PECmd,
     RECmd, AmcacheParser, YARA, Plaso. Use these when you need their
     specific capability (e.g. memory forensics, batch ASEP enumeration,
     YARA matching). If a SIFT binary is missing, the adapter raises
     SiftToolNotFoundError — fall back to the native tool covering the
     same artifact (e.g. native get_amcache instead of sift_amcacheparser_parse).

Your playbook:
  1. Build a TIMELINE by calling timeline functions first (get_amcache,
     extract_mft_timeline, parse_prefetch). For memory captures, lead
     with sift_vol3_windows_pslist + sift_vol3_windows_cmdline +
     sift_vol3_windows_malfind.
  2. Form TWO competing hypotheses — primary and alternative.
  3. CROSS-VALIDATE against a different data source (USB, ShellBags,
     persistence, event logs). For Windows event-log triage prefer
     sift_evtxecmd_filter_eids over raw analyze_event_logs.
  4. If you find a CONTRADICTION, you must address it. Do not smooth it over.
  5. EVERY finding you report must reference at least one tool call.

Produce findings with ids like F-001, F-013. When you are done, emit a
JSON block starting with "REPORT:" containing:
  {"findings": [{"id": "F-013", "title": "...", "confidence": 0.82,
                 "evidence_summary": "...", "tool_calls": [...]}],
   "primary_hypothesis": "...", "iterations": N}
"""


def _extract_findings(final_text: str) -> list[dict]:
    """Recover the findings list from the model's final 'REPORT:' JSON block.

    The system prompt asks for `REPORT:` followed by a JSON object carrying a
    "findings" array. Models routinely wrap that JSON in a ```json fence, so
    accept both fenced and bare forms. Returns [] when no parseable report is
    present (e.g. the run hit max_iterations before the final message)."""
    if not final_text:
        return []
    marker = final_text.rfind("REPORT:")
    blob = final_text[marker + len("REPORT:"):] if marker >= 0 else final_text
    # Strip a leading markdown fence (```json ... ```), if present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", blob, flags=re.DOTALL)
    if fence:
        blob = fence.group(1)
    start = blob.find("{")
    if start < 0:
        return []
    # Walk to the matching close brace so trailing prose doesn't break parsing.
    depth = 0
    end = -1
    in_str = False
    esc = False
    for i, ch in enumerate(blob[start:], start):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
    # Primary path: the whole REPORT object is well-formed and closed.
    if end >= 0:
        try:
            data = json.loads(blob[start:end])
            findings = data.get("findings")
            if isinstance(findings, list):
                return [f for f in findings if isinstance(f, dict)]
        except json.JSONDecodeError:
            pass  # fall through to the salvage path below

    # Salvage path: the model produced a valid findings array but the OUTER
    # object was truncated (e.g. max_tokens cut off the trailing timeline/
    # remediation sections, so the closing braces never arrived). A truncated
    # report with ten perfectly-good findings must not score as zero. Locate
    # the "findings" key, then brace/bracket-match just its array value so a
    # cut-off tail does not discard everything before it.
    return _salvage_findings_array(blob)


def _salvage_findings_array(blob: str) -> list[dict]:
    """Best-effort recovery of the findings array from a truncated REPORT.

    Finds the '"findings": [' key and walks to the matching ']' (string- and
    escape-aware). If even the array itself is truncated, progressively drops
    the last comma-separated element until the prefix parses, so a report cut
    off in the middle of finding N still yields findings 1..N-1.
    """
    key = re.search(r'"findings"\s*:\s*\[', blob)
    if not key:
        return []
    arr_start = key.end() - 1  # index of the '['
    depth = 0
    in_str = False
    esc = False
    arr_end = -1
    for i, ch in enumerate(blob[arr_start:], arr_start):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    arr_end = i + 1
                    break
    if arr_end >= 0:
        # The array closed cleanly even though the outer object did not.
        try:
            arr = json.loads(blob[arr_start:arr_end])
            if isinstance(arr, list):
                return [f for f in arr if isinstance(f, dict)]
        except json.JSONDecodeError:
            pass

    # The array itself was truncated. Peel back to the last complete object by
    # trimming after successive '}' boundaries until a prefix + ']' parses.
    tail = blob[arr_start:]
    close_positions = [i for i, ch in enumerate(tail) if ch == "}"]
    for cut in reversed(close_positions):
        candidate = tail[: cut + 1] + "]"
        try:
            arr = json.loads(candidate)
            if isinstance(arr, list):
                return [f for f in arr if isinstance(f, dict)]
        except json.JSONDecodeError:
            continue
    return []


@dataclass
class LiveRunState:
    case: str
    out_dir: Path
    max_iterations: int = 12
    iteration: int = 0
    messages: list[dict] = field(default_factory=list)
    tool_call_log: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    # Token usage accumulators. Populated from each `messages.create` response's
    # .usage object so the operator can see, at end of run, how much the loop
    # cost in tokens (and which fraction was served from the prompt cache).
    # Operational visibility only — no pricing math here; the analyst can
    # cross-reference Anthropic console pricing if a USD figure is needed.
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0


async def _run_with_real_claude(prompt: str, state: LiveRunState,
                                 model: str, anthropic_tools: list[dict],
                                 session) -> str:
    """Drive the conversation with the real Anthropic API.

    Uses the configured Anthropic credential source from dart_agent.auth.
    """
    from .auth import build_anthropic_client
    client = build_anthropic_client()
    if client is None:
        raise RuntimeError("No Anthropic credentials available.")

    state.messages.append({"role": "user", "content": prompt})

    while state.iteration < state.max_iterations:
        state.iteration += 1
        resp = client.messages.create(
            model=model,
            # The final turn emits the full REPORT JSON: a findings array plus
            # timeline, attack_chain, remediation, and a MITRE tactic summary.
            # At 4096 a rich multi-finding report was being truncated mid-JSON,
            # which made _extract_findings fall back to [] (a present-but-
            # unparseable report scored as zero findings). 16384 leaves ample
            # headroom for the largest reports the agent produces here.
            max_tokens=16384,
            # Prompt caching: the system prompt and the
            # tool definitions are large and IDENTICAL on every iteration of
            # the forensic reasoning loop. Marking the last one with
            # cache_control: ephemeral lets the API cache everything up to
            # that point — system + tools — so subsequent iterations re-read
            # the cache instead of re-billing those input tokens (~90%
            # cheaper on the cached prefix, and faster). The cache key is the
            # exact prefix bytes, so this is safe: a cache miss just falls
            # back to a normal full-price call. We put the marker on the LAST
            # tool so the cached prefix spans system + every tool.
            system=[{
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            tools=_with_cache_breakpoint(anthropic_tools),
            messages=state.messages,
        )

        # Accumulate per-iteration token usage so the operator can see the
        # full cost (and cache-hit ratio) at end of run. Each field falls
        # back to 0 when the API response omits it (older SDK versions or
        # the dry-run mock).
        usage = getattr(resp, "usage", None)
        if usage is not None:
            state.input_tokens += getattr(usage, "input_tokens", 0) or 0
            state.output_tokens += getattr(usage, "output_tokens", 0) or 0
            state.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
            state.cache_creation_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0

        # Accumulate assistant message
        assistant_blocks = []
        tool_use_blocks = []
        text_blocks = []
        for block in resp.content:
            assistant_blocks.append(block.model_dump()
                                     if hasattr(block, "model_dump") else block)
            if block.type == "tool_use":
                tool_use_blocks.append(block)
            elif block.type == "text":
                text_blocks.append(block.text)

        state.messages.append({"role": "assistant", "content": assistant_blocks})

        # No tool calls → conversation ends
        if not tool_use_blocks:
            return "\n".join(text_blocks)

        # Execute all tool calls via MCP session
        tool_results = []
        for tu in tool_use_blocks:
            state.tool_call_log.append({
                "iteration": state.iteration,
                "tool": tu.name,
                "input": tu.input,
            })
            try:
                mcp_result = await session.call_tool(tu.name, tu.input)
                result_text = mcp_result.content[0].text \
                    if mcp_result.content else "{}"
                # Hybrid-architecture guardrail: cap oversized results so a
                # single huge dump can't blow the context window or invite
                # the model to hallucinate over a wall of raw rows.
                result_text = _truncate_tool_result(result_text)
            except Exception as e:
                result_text = json.dumps({"error": type(e).__name__,
                                          "detail": str(e)[:300]})
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": result_text,
            })

        state.messages.append({"role": "user", "content": tool_results})

    # Iteration budget exhausted while the model was still calling tools. Give
    # it one final turn WITHOUT tools and an explicit instruction to stop
    # investigating and synthesize the REPORT from the evidence gathered so far.
    # Without this, a model that spends all max_iterations exploring (common on
    # evidence-rich cases) returns no REPORT at all and scores zero findings —
    # not because it found nothing, but because it never got asked to conclude.
    state.messages.append({
        "role": "user",
        "content": (
            "You have reached the investigation step limit. Do NOT request any "
            "more tools. Based on the evidence you have already collected in "
            "this conversation, produce your final analysis now as the "
            "'REPORT:' JSON block specified in your instructions (findings "
            "array with id/title/severity/mitre_tactics, plus timeline, "
            "attack_chain, and remediation). Report only what the evidence so "
            "far supports."
        ),
    })
    final_resp = client.messages.create(
        model=model,
        max_tokens=16384,
        system=[{
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        # No tools on the synthesis turn: force a text REPORT, not another
        # tool call.
        messages=state.messages,
    )
    usage = getattr(final_resp, "usage", None)
    if usage is not None:
        state.input_tokens += getattr(usage, "input_tokens", 0) or 0
        state.output_tokens += getattr(usage, "output_tokens", 0) or 0
        state.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
        state.cache_creation_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
    final_text = "\n".join(b.text for b in final_resp.content if b.type == "text")
    state.messages.append({
        "role": "assistant",
        "content": [b.model_dump() if hasattr(b, "model_dump") else b
                    for b in final_resp.content],
    })
    return final_text or "(max_iterations reached, no final report)"


async def _run_with_mock_claude(prompt: str, state: LiveRunState,
                                 session) -> str:
    """Deterministic simulation of a Claude tool-calling conversation,
    for CI / dry-run scenarios without an API key.

    Walks the same conceptual path a real Claude run would: timeline →
    cross-validation → contradiction → widen window → conclude.
    """
    scripted_calls = [
        ("get_amcache",
         {"hive_path": "disk/Windows/AppCompat/Programs/Amcache.hve"}),
        ("analyze_usb_history",
         {"system_hive": "disk/Windows/System32/config/SYSTEM",
          "setupapi_log": "disk/Windows/INF/setupapi.dev.log"}),
        ("correlate_timeline",
         {"events": [
             {"ts": "2026-03-15 14:19:47", "source": "usb",
              "type": "usb_insert", "target": "DESKTOP-7K2L"},
             {"ts": "2026-03-15 14:22:00", "source": "security_log",
              "type": "logon", "actor": "analyst", "target": "DESKTOP-7K2L"},
         ], "window_seconds": 600}),
        ("parse_shimcache",
         {"system_hive": "disk/Windows/System32/config/SYSTEM"}),
    ]

    findings_log = []
    tool_outputs = {}
    for tool_name, args in scripted_calls:
        if state.iteration >= state.max_iterations:
            break
        state.iteration += 1
        try:
            mcp_result = await session.call_tool(tool_name, args)
            result_text = mcp_result.content[0].text \
                if mcp_result.content else "{}"
            result = json.loads(result_text)
        except Exception as e:
            result = {"error": type(e).__name__, "detail": str(e)[:300]}
            result_text = json.dumps(result)

        state.tool_call_log.append({
            "iteration": state.iteration,
            "tool": tool_name,
            "input": args,
            "output_preview": result_text[:200],
        })
        tool_outputs[tool_name] = result
        findings_log.append(
            f"[mock] iter {state.iteration}: {tool_name} → "
            f"{'OK' if 'error' not in result else 'ERR'}"
        )

    usb_result = tool_outputs.get("analyze_usb_history", {})
    corr_result = tool_outputs.get("correlate_timeline", {})
    usb_hits = usb_result.get("ip_kvm_indicators", []) if isinstance(usb_result, dict) else []
    corr_hits = corr_result.get("kvm_precedes_logon", []) if isinstance(corr_result, dict) else []
    if usb_hits and corr_hits:
        state.findings = [{
            "id": "F-013",
            "title": "IP-KVM insertion preceded an operator logon",
            "confidence": 0.82,
            "evidence_summary": (
                "analyze_usb_history returned IP-KVM indicators and "
                "correlate_timeline returned a kvm_precedes_logon match."
            ),
            "tool_calls": [c["tool"] for c in state.tool_call_log],
        }]
    else:
        state.findings = []
    return "\n".join(findings_log) + "\n\nREPORT: " + json.dumps({
        "findings": state.findings,
        "primary_hypothesis": (
            "Remote-hands insider via IP-KVM" if state.findings
            else "No dry-run finding emitted without corroborating tool output"
        ),
        "iterations": state.iteration,
    })


async def live_run(case: str, out_dir: str, prompt: str,
                   model: str, max_iter: int, dry_run: bool) -> int:
    state = LiveRunState(
        case=case, out_dir=Path(out_dir), max_iterations=max_iter,
    )
    state.out_dir.mkdir(parents=True, exist_ok=True)

    if not _MCP_AVAILABLE:
        print("ERROR: mcp package not installed. pip install mcp", file=sys.stderr)
        return 2

    # Decide mode early so we can print a banner.
    # Live mode is available when a configured credential source exists.
    try:
        from .auth import has_any_credentials
        _have_creds = has_any_credentials()
    except Exception:
        _have_creds = bool(os.environ.get("ANTHROPIC_API_KEY"))
    use_real = _have_creds and not dry_run
    if use_real and not _ANTHROPIC_AVAILABLE:
        print("WARNING: credentials present but anthropic SDK not installed; "
              "falling back to dry-run.", file=sys.stderr)
        use_real = False
    print(f"[live] case={case}  mode={'REAL-CLAUDE' if use_real else 'DRY-RUN'}  "
          f"max_iter={max_iter}", file=sys.stderr)

    # Launch dart-mcp as a stdio subprocess
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "dart_mcp.server_stdio"],
        env={**os.environ},
    )

    async with AsyncExitStack() as stack:
        # Open stdio transport to dart-mcp
        read, write = await stack.enter_async_context(stdio_client(server_params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()

        # Discover tools via MCP protocol (verifies the wire works)
        tools_resp = await session.list_tools()
        mcp_tool_names = [t.name for t in tools_resp.tools]
        print(f"[live] MCP handshake OK — {len(mcp_tool_names)} tools visible",
              file=sys.stderr)
        print(f"[live] tools: {', '.join(mcp_tool_names)}", file=sys.stderr)

        if use_real:
            # Convert MCP tool schemas to Anthropic tool-use format
            anthropic_tools = [{
                "name": t.name,
                "description": t.description,
                "input_schema": t.inputSchema,
            } for t in tools_resp.tools]
            final_text = await _run_with_real_claude(
                prompt, state, model, anthropic_tools, session,
            )
            # The mock path fills state.findings itself; the real path must
            # recover them from the model's final "REPORT:" JSON block.
            if not state.findings:
                state.findings = _extract_findings(final_text)
        else:
            final_text = await _run_with_mock_claude(prompt, state, session)

    # Write logs
    (state.out_dir / "live_transcript.txt").write_text(final_text)
    (state.out_dir / "live_tool_calls.jsonl").write_text(
        "\n".join(json.dumps(c) for c in state.tool_call_log) + "\n"
    )
    (state.out_dir / "live_summary.json").write_text(json.dumps({
        "case": case,
        "mode": "real-claude" if use_real else "dry-run",
        "iterations": state.iteration,
        "tool_call_count": len(state.tool_call_log),
        "findings": state.findings,
        # Token accounting — zero in dry-run because the mock doesn't return
        # a usage object. In real-claude mode these come from each API
        # response's .usage and let the operator verify that prompt caching
        # is actually firing (cache_read_tokens should dominate input_tokens
        # from iteration 2 onward).
        "usage": {
            "input_tokens": state.input_tokens,
            "output_tokens": state.output_tokens,
            "cache_read_tokens": state.cache_read_tokens,
            "cache_creation_tokens": state.cache_creation_tokens,
        },
    }, indent=2))

    print(f"[live] done — {state.iteration} iterations, "
          f"{len(state.tool_call_log)} tool calls", file=sys.stderr)
    # Print token usage only when there's something to show (skip in dry-run
    # where the mock doesn't report usage). cache_read / (input + cache_read)
    # is the cache-hit ratio across the whole loop.
    total_in = state.input_tokens + state.cache_read_tokens + state.cache_creation_tokens
    if total_in > 0:
        cache_pct = (state.cache_read_tokens * 100 // total_in) if total_in else 0
        print(f"[live] tokens — in={state.input_tokens} "
              f"out={state.output_tokens} "
              f"cache_read={state.cache_read_tokens} "
              f"cache_create={state.cache_creation_tokens} "
              f"(cache-hit {cache_pct}% of input)", file=sys.stderr)
    print(f"[live] outputs in: {state.out_dir}", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="dart-agent live-mode controller")
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prompt", default="Investigate the bundled evidence and "
                                        "report any findings with high severity.")
    ap.add_argument("--model",
                    default=os.environ.get("DART_MODEL", "claude-haiku-4-5-20251001"))
    ap.add_argument("--max-iterations", type=int, default=12)
    ap.add_argument("--dry-run", action="store_true",
                    help="Use scripted mock Claude (no API key needed).")
    args = ap.parse_args(argv)

    return asyncio.run(live_run(
        case=args.case, out_dir=args.out, prompt=args.prompt,
        model=args.model, max_iter=args.max_iterations, dry_run=args.dry_run,
    ))


if __name__ == "__main__":
    sys.exit(main())
