# Live mode — Claude API + dfir-mcp over stdio

`dfir-agent` ships in two modes: **deterministic** (a scripted analyst policy,
no API key needed) and **live** (Claude drives the investigation, connected to
`dfir-mcp` over JSON-RPC stdio). This page documents live mode end-to-end: why
both modes exist, what the live loop does, how to authenticate and run it,
what it writes, what Claude can and cannot do inside it, and the wire-level
tests that prove the boundary holds. `live` mode is what you use when a real
case comes in.

## Why both modes exist

| | Deterministic | Live |
|---|---|---|
| LLM | None — scripted policy | Claude (default `claude-haiku-4-5-20251001`) |
| API key required | No | `ANTHROPIC_API_KEY` (or the OAuth token for Haiku — see below) |
| Use case | CI, reproducibility, air-gapped runs, the accuracy rig check | Real DFIR work, judgment-heavy cases, the model benchmarks |
| Network egress | None | Outbound HTTPS to `api.anthropic.com` |
| Read-only MCP boundary | Same | Same |

The typed, read-only MCP surface is *identical* across modes. The only
difference is who picks the next call: the YAML playbook policy, or Claude.

## What `live` mode actually does

```
┌────────────────────────┐                  ┌──────────────────────────┐
│   dfir_agent           │  MCP over stdio  │ dfir_mcp.server_stdio    │
│   (Anthropic API       │ ◄───────────────►│ (subprocess; typed       │
│    tool-use loop)      │  JSON-RPC        │  forensic functions —    │
│                        │                  │  native + SIFT adapters) │
└──────────┬─────────────┘                  └────────────┬─────────────┘
           │                                             │
           │ HTTPS                                       │ file read
           ▼                                             ▼
    api.anthropic.com                           DFIR_EVIDENCE_ROOT (read-only)
```

The agent:

1. Spawns `python -m dfir_mcp.server_stdio` as a subprocess with stdio piped.
2. Performs the JSON-RPC `initialize` handshake.
3. Calls `tools/list` — Claude sees exactly **73** typed forensic functions
   (48 native + 25 SIFT Workstation adapters), nothing more. The full list is
   in the [MCP function catalog](./mcp-function-catalog.md) and the
   [SIFT adapter layer](./sift-adapter-layer.md).
4. Hands that tool list (converted to Anthropic's tool-use schema) to Claude
   and loops:
   - Sends the conversation so far as a `messages.create` request with
     `tools=[...the 73...]`.
   - Claude returns one or more `tool_use` blocks, each selecting a tool and
     its arguments.
   - The agent forwards each call to `dfir-mcp` over stdio and appends a
     record to `live_tool_calls.jsonl`.
   - The output goes back to Claude as a `tool_result` message.
5. Stops when Claude answers with no further `tool_use` block, or when
   `--max-iterations` is reached. In the second case the agent gives Claude
   one final turn *without* tools and an explicit instruction to synthesise
   the `REPORT:` JSON block from the evidence gathered so far, so a run that
   spends its whole budget exploring still produces a report rather than
   zero findings.

Claude cannot see anything beyond the typed MCP surface. Not because we told
it not to, but because the MCP server does not expose anything else.

## Setup

```bash
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
bash scripts/install.sh

# Authenticate with an Anthropic API key:
export ANTHROPIC_API_KEY="sk-ant-..."
```

The user-facing runner is `python3 analyze.py --case <tier>/case-NN`. It is
live-only, authenticates via `ANTHROPIC_API_KEY`, and fails fast before doing
any work if the key is not set. `analyze.py --list` shows the discovered cases
and needs no key. Install details are in the
[operator guide](./operator-guide.md); the short path is in the
[quick start](./QUICKSTART.md).

### Authentication

The documented live-mode credential path is an Anthropic API key. If you run
`python3 -m dfir_agent` directly rather than through `analyze.py`, also set
the evidence root and the package paths:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export DFIR_EVIDENCE_ROOT=/path/to/evidence
export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"

python3 -m dfir_agent --mode live \
    --case my-case \
    --out /tmp/my-case-out \
    --prompt "Investigate evidence root for IP-KVM insider pattern. Report findings with audit IDs." \
    --model claude-haiku-4-5-20251001 \
    --max-iterations 10
```

The default model is `claude-haiku-4-5-20251001`. Override it with `--model`
or the `DFIR_MODEL` environment variable when you need a different
currently-supported Claude model (for example `claude-sonnet-4-6` for higher
fidelity).

### Model-aware authentication

Added in v1.2.0. `dfir-agent` resolves credentials **by model**
(`dfir_agent.auth`), so you never have to think about which token a given
model needs:

- **Haiku** (`claude-haiku-4-5-…`, the default) prefers the local **OAuth
  subscription token** left by a Claude Code login, and falls back to the
  metered API key — for always-on, low-cost iteration.
- **Sonnet / Opus** (`--model claude-sonnet-4-6`, `claude-opus-…`) use the
  **metered API key only** — the subscription does not serve those models, so
  a missing key surfaces as "key required" rather than a silently broken
  OAuth path — for high-fidelity analysis and benchmarks.

The chosen credential source prints next to the model on every run, and the
`dfir-auth` command reports both at a glance:

```bash
dfir-auth          # shows which token resolves for each model tier
```

`dfir-auth` is a shell alias that `scripts/install.sh` writes; it runs
`python3 dfir_agent/src/dfir_agent/auth.py`, which you can also call directly.
This keeps the always-on agent loop on a flat subscription while reserving
metered API spend for the runs that need top-tier reasoning.

### Registering dfir-mcp with Claude Code

To register `dfir-mcp` with Claude Code (so you can call the surface
interactively):

```bash
claude mcp add agentic-dfir -s user -- python3 -m dfir_mcp.server_stdio
```

Then in your Claude Code session:

```
/mcp call agentic-dfir get_amcache --hive_path disk/Windows/AppCompat/Programs/Amcache.hve
/mcp call agentic-dfir parse_prefetch --prefetch_path disk/Windows/Prefetch/CHROME.EXE-<hash>.pf
```

## Running the agent loop in live mode

```bash
# Evidence root is set via env var (not a CLI flag)
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence

python3 -m dfir_agent \
    --case CASE-2026-001 \
    --out ./out/case-2026-001 \
    --mode live \
    --max-iterations 25
```

`--max-iterations` is a safety ceiling on the tool-call loop, not a target:
the agent stops on its own as soon as it has enough to report, and simple
cases finish in a handful of iterations. `python3 -m dfir_agent` defaults the
ceiling to 10; `analyze.py` defaults it to 25 so the most complex cases have
headroom. When the ceiling is hit the agent still asks for a final report (see
step 5 above).

### Without any credentials (CI, offline reproduction)

Pass `--dry-run`. Everything runs the same — MCP subprocess, stdio handshake,
real tool calls — except Claude is replaced with a scripted mock that walks a
plausible tool-call sequence. Useful for:

- CI pipelines where no credentials should live
- Verifying the MCP plumbing without spending tokens
- Running the same plumbing Claude will use in a deterministic test

```bash
python3 -m dfir_agent --mode live --case test --out /tmp/out --dry-run
```

The mock never claims a finding the tools did not support: if the IP-KVM
indicator is present but the correlation call returns nothing, it emits no
finding and says so in the transcript.

## Outputs

Live mode writes three files to `--out`:

| File | Contents |
|---|---|
| `live_summary.json` | case id, mode (`real-claude` or `dry-run`), iterations, `tool_call_count`, final findings, and a `usage` block with `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_creation_tokens` |
| `live_tool_calls.jsonl` | one line per MCP call: iteration, tool, input (the dry-run mock also records an output preview) |
| `live_transcript.txt` | the assistant's final text (or the mock transcript) |

Findings are recovered from the `REPORT:` JSON block the system prompt asks
Claude to end with (fenced or bare). The `usage` block is what lets an operator
verify that prompt caching is actually firing: from the second iteration
onward `cache_read_tokens` should dominate `input_tokens`, and the agent prints
the cache-hit ratio on stderr when the run finishes.

When you run through `analyze.py`, each run lands in
`out/<tier>/<case>/<timestamp>/` and the native live outputs are mapped onto
the canonical evaluation filenames: `findings.json` (the findings array),
`report.json` (the full live summary), and `summary.json` (case, model, host,
Python version, evidence root, findings count, iterations, usage).
`analyze.py` also applies a non-determinism guard at that single entry point:
a run that ends with zero findings is re-run once, and whatever the retry
yields is final.

The SHA-256 audit chain (`audit.jsonl`), the hypothesis log
(`progress.jsonl`) and `report.json` of deterministic mode are produced by the
deterministic agent path; the two modes share the same evidence tree and the
same read-only MCP surface. See [dfir-audit](../dfir_audit/README.md) for the
chain format and `python3 -m dfir_audit trace`.

## What Claude can and cannot do in live mode

**Can:**

- Choose any of the typed MCP functions on the surface (73 total — 48 native
  + 25 SIFT adapters)
- Pass any schema-valid arguments — `call_tool()` validates arguments against
  the advertised JSON Schema before dispatch
- Reason about the output and pick the next call

**Cannot:**

- Call functions not on the surface — this raises `ToolNotFound` at the wire
  boundary, not at the agent
- Modify evidence — no function on the surface can write
- Escape `DFIR_EVIDENCE_ROOT` — `_safe_resolve` rejects relative traversal,
  absolute paths outside the root, and NUL-byte truncation
- Hide a call — every MCP call the model makes is recorded in
  `live_tool_calls.jsonl` before its result is consumed

This is the architectural guarantee made concrete: **a fully jailbroken model
is still bounded by the surface.**

## Why this is the architecturally correct design

Compare two hypothetical designs for a DFIR agent:

### Design A: "give the LLM shell access and tell it to behave"

```python
# Anti-pattern — do NOT do this
def execute_shell(cmd: str) -> str:
    """The LLM has read our system prompt saying 'only read evidence'."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
```

One prompt injection in a document, one hallucinated command, one model
update that changes the alignment, and the LLM can do anything.

### Design B: "give the LLM a typed, read-only function set"

```python
# dfir-mcp registers ONLY this interface
@tool(name="extract_mft_timeline", schema=...)
def extract_mft_timeline(mft_path, start, end): ...
```

The LLM can no more call `execute_shell` than it can call `delete_evidence`
— those names do not resolve to anything on the server. It is not a
policy. It is an absence.

The MCP protocol is the enforcement point. `tests/test_live_mcp.py` asserts
this with a real `call_tool("execute_shell", ...)` over the wire — the call is
blocked by `KeyError: ToolNotFound` at the protocol layer, not by any prompt.
The reasoning behind this choice is in
[Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md).

## Wire-level tests

`tests/test_live_mcp.py` runs end-to-end against the real MCP stdio server,
with the scripted mock Claude picking tools deterministically. No API key is
required and the whole file runs in seconds:

```bash
python3 tests/test_live_mcp.py      # or: python3 -m pytest tests/test_live_mcp.py
```

What it asserts:

1. `dfir-agent --mode live --dry-run` runs end-to-end as a subprocess: the
   `MCP handshake OK` banner appears, the tool surface is enumerated over the
   wire, and `live_transcript.txt`, `live_tool_calls.jsonl` and
   `live_summary.json` are written with the expected structure.
2. The dry-run mock does not emit a finding the tools did not corroborate.
3. `tools/list` advertises exactly the registered surface — 73 functions, 48
   native + 25 SIFT adapters; any drift between the wire and the in-process
   registry fails the test.
4. A real tool call (`analyze_usb_history`) returns real data over stdio — the
   ATEN IP-KVM signature (VID `0557`) survives the JSON-RPC round trip.
5. Calling a non-registered function returns `ToolNotFound` over the wire.

## Performance and usage notes

A single iteration of the live loop consumes tokens depending on artifact size
and the amount of tool output sent back to Claude. The bundled IP-KVM case
typically completes in about five iterations. Token counts (including cache
reads and cache writes) are recorded in `live_summary.json` so operators can
review usage after the run. Check current Anthropic pricing and account
limits before running live investigations.

For reproducibility the agent pins `temperature=0` on every model call that
accepts it. Models that have deprecated the parameter (Claude Opus 4.8 returns
HTTP 400 "temperature is deprecated for this model") are detected on the first
rejection and the parameter is dropped for the rest of the run — there is
nothing to configure. What this means for run-to-run variance is covered in
the [accuracy report](./accuracy-report.md#model-selection--determinism--what-we-learned).

For air-gapped or credential-free reproduction, deterministic mode handles the
same case classes the playbook covers with no external dependency. `--dry-run`
also exercises the live MCP plumbing without contacting the API.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ANTHROPIC_API_KEY not set` | env var missing | `export ANTHROPIC_API_KEY=...` |
| `MCP handshake timeout` | `dfir-mcp` subprocess crashed at startup | Run `python3 -m dfir_mcp.server_stdio` directly to see the error |
| `tools/list returns 0 tools` | Wrong PYTHONPATH | `export PYTHONPATH="$PWD/dfir_mcp/src:..."` |
| `Loop hangs` | Claude waiting on a `tool_result` that never arrived | Check `live_tool_calls.jsonl` for the last call — likely a parser raised silently |

More symptoms (credential resolution, the `--max-iterations` cap,
context-window exhaustion, the MCP server not showing up in Claude Code) are in
[troubleshooting](./troubleshooting.md).

## See also

- [dfir-agent](../dfir_agent/README.md) — the wrapper loop
- [dfir-mcp](../dfir_mcp/README.md) — the typed surface that gets exposed
- [Architecture](./architecture.md) — how the packages fit together
- [Operator guide](./operator-guide.md) — install, requirements, running your own evidence
- [Accuracy report](./accuracy-report.md) — what the live runs score and how that is measured
- [Troubleshooting](./troubleshooting.md)
