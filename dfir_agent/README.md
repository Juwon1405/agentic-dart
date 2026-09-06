# dfir-agent

`dfir-agent` is the wrapper loop that orchestrates the agent's reasoning: it loads the senior-analyst playbook, maintains the hypothesis tracker, runs the iteration controller under a hard cap, and emits the analyst-readable report. It is the only Python package in the project that contains *control flow* for the agent — the other four (`dfir_mcp`, `dfir_corr`, `dfir_audit`, `dfir_playbook`) are typed surfaces, helpers, or data. This page explains what the package owns, the CLI as it exists in the current tree, the loop, the two execution modes, how credentials are resolved, and how the playbook reaches the model.

## What it owns

- The senior-analyst loop (`DeterministicAnalyst.run()` in `dfir_agent/src/dfir_agent/__init__.py`)
- Two execution modes: `deterministic` and `live`, selected with `--mode`
- Hypothesis state (`Hypothesis` with a confidence score and supporting / contradicting finding IDs; `ProgressSnapshot` per iteration; `ProgressTracker` appending to `progress.jsonl`)
- The iteration controller with the `--max-iterations` hard cap and a closeout snapshot when the cap forces an exit
- The finding serializer, which attaches to each finding the `audit_id`s of the MCP calls that produced it
- Building the live-mode system prompt from the playbook YAML (`live.py`) and the live tool-use loop over MCP stdio
- Credential resolution for live mode (`auth.py`)
- The final structured report (`report.json`)

## What it does *not* own

- The forensic functions themselves — those live in [dfir-mcp](../dfir_mcp/README.md)
- Cross-artifact joins — those live in [dfir-corr](../dfir_corr/README.md)
- The audit chain — that lives in [dfir-audit](../dfir_audit/README.md)
- Any sequencing rule — those live in [dfir-playbook](../dfir_playbook/README.md) YAML
- Security boundaries — those live in `dfir-mcp` and the OS read-only mount

The agent is deliberately small. The deterministic control flow — loop, hypothesis state, finding serializer — fits in `__init__.py`; the live-mode controller and the credential layer are separate modules so their optional dependencies stay optional.

## CLI

```bash
export DFIR_EVIDENCE_ROOT=/path/to/evidence_root      # evidence root is an env var, not a flag
python3 -m dfir_agent \
    --case <case-id> \
    --out ./out/<case-id>/ \
    --mode deterministic \
    --max-iterations 10

# live mode (Claude API over MCP stdio); --dry-run swaps in a scripted mock, no key needed
python3 -m dfir_agent --case <case-id> --out ./out/<case-id>/ --mode live [--model <id>] [--prompt "..."] [--dry-run]
```

Flags, as reported by `python3 -m dfir_agent --help`:

| Flag | Default | Meaning |
|---|---|---|
| `--case CASE` | required | Case identifier; also used as the audit `run_id` |
| `--out OUT` | required | Output directory (created if missing) |
| `--max-iterations N` | `10` | Hard cap on the loop. The controller refuses to exceed it even if the playbook schedules more phases |
| `--mode {deterministic,live}` | `deterministic` | `deterministic`: scripted analyst, offline, no API calls. `live`: Claude API talking to `dfir-mcp` via stdio |
| `--prompt PROMPT` | "Investigate the bundled evidence and report any high-severity findings." | (live) initial user prompt to Claude |
| `--model MODEL` | `claude-haiku-4-5-20251001`, or `DFIR_MODEL` if set | (live) Anthropic model id, e.g. `claude-sonnet-4-6` for higher fidelity |
| `--dry-run` | off | (live) use a scripted mock Claude — no API key needed |

Environment variables: `DFIR_EVIDENCE_ROOT` (the read-only evidence root every path argument is resolved against), `DFIR_MODEL` (live-mode default model), `ANTHROPIC_API_KEY` (live-mode credential; see Authentication below).

Outputs, by mode:

| Mode | Files written to `--out` |
|---|---|
| `deterministic` | `audit.jsonl` (SHA-256 chain, verified at exit — the process exits 1 if the chain fails), `progress.jsonl` (one snapshot per iteration), `report.json` (`primary_hypothesis`, `alternative_hypothesis`, `findings` — each with `finding_id`, `description`, `audit_ids` and `status` (`confirmed`, `unresolved` or `false_positive`) — `unresolved`, `iterations`) |
| `live` | `live_transcript.txt` (the model's final text), `live_tool_calls.jsonl` (one line per MCP call), `live_summary.json` (case, mode `real-claude` or `dry-run`, iterations, `tool_call_count`, findings, token `usage`) |

The committed reference run at [`examples/out/ref-01/`](../examples/out/ref-01/) is a deterministic run of the bundled IP-KVM case. `python3 analyze.py` is the evaluation runner built on top of this CLI (live mode only, default ceiling 25 iterations); see [Quick start](../docs/QUICKSTART.md) and [Operator guide](../docs/operator-guide.md).

## The loop, in pseudocode

```
audit    = AuditLogger(out/audit.jsonl, run_id=case)
progress = ProgressTracker(out/progress.jsonl)

for phase in [timeline, hypothesis, cross_source_validation, finalize]:
    if iteration >= max_iterations:
        progress.write(forced_exit snapshot)          # partial report, still analyst-readable
        break
    output = call_tool(name, inputs)                  # via dfir-mcp — the only way to touch evidence
    audit_id = audit.log(name, inputs, output, iteration, finding_ids=...)
    if output contradicts the current hypothesis:
        unresolved.append(description)
        output2, audit_id2 = call_tool(...)           # re-run with adjusted parameters
        hypothesis = replaced, not smoothed           # both audit_ids attached to the finding
    progress.write(snapshot)                          # hypothesis, confidence, unresolved gaps

report.json = {primary_hypothesis, alternative_hypothesis, findings, unresolved, iterations}
AuditLogger.verify(out/audit.jsonl)
```

Five things to notice:

1. The agent never bypasses `dfir-mcp`. It cannot call anything that isn't on the [MCP function catalog](../docs/mcp-function-catalog.md); an unregistered name raises `ToolNotFound`.
2. Every tool call is logged before the result is consumed. `_call` is the single primitive that both invokes `call_tool` and writes the audit entry, so there is no logged-later path. The audit chain is not best-effort — it is load-bearing.
3. Cross-source validation is mandatory. The primary hypothesis is checked against a source that was *not* used to form it (in the bundled case: Amcache forms the hypothesis, USB history tests it).
4. A contradiction cannot be ignored. It is appended to `unresolved` and either resolved by a further call — after which the hypothesis is *replaced* — or carried into `report.json` under `unresolved`.
5. Every finding carries the `audit_id`s of the MCP calls that produced it. `python3 -m dfir_audit trace <audit.jsonl> <finding-id>` walks them back to the artifact reads.

## Modes

### Deterministic

```bash
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence
python3 -m dfir_agent --case CASE-ID --out ./out/CASE-ID --mode deterministic
```

Uses a scripted decision policy (`DeterministicAnalyst` in `dfir_agent/src/dfir_agent/__init__.py`) that mimics what a senior analyst would call next given the current state. No external service. Suitable for CI, reproducibility checks, and air-gapped runs. What is "deterministic" is only the LLM reasoning — the order of calls, the cross-source check and the contradiction flagging are the actual logic the agent runs; pre-scripted hypotheses replace the model so the run is reproducible.

`run()` walks four phases and emits a `report()` dict at the end:

| Phase (`progress.jsonl` name) | What happens |
|---|---|
| `_phase_timeline` (`timeline_reconstruction`) | `get_amcache` on `disk/Windows/AppCompat/Programs/Amcache.hve`; finding `F-001` (unusual binary first-executed shortly after the reported login) is pre-declared on the audit entry so `trace F-001` resolves to this exact call |
| `_phase_hypothesis` (`hypothesis_formation`) | Two competing hypotheses from Amcache-only evidence: primary "unauthorized interactive login followed by unusual binary execution" (0.55) and alternative "legitimate admin maintenance" (0.25) |
| `_phase_validate_usb` (`cross_source_validation`) | `analyze_usb_history` on the SYSTEM hive and `setupapi.dev.log`. If IP-KVM indicators precede the logon window, the contradiction is recorded, the call is re-run with a widened time window, finding `F-013` is emitted with both `audit_id`s, and the primary hypothesis is replaced by "remote-hands insider access via IP-KVM" (0.82) |
| `_phase_finalize` (`structured_report`) | Closeout snapshot; every finding carries `audit_id`s |

The committed reference run shows this shape: three audit entries (`get_amcache`, `analyze_usb_history` twice) and two findings, `F-001` and `F-013`. Its audit `verify` and `summary` output is shown in [dfir-audit](../dfir_audit/README.md).

### Live

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence
python3 -m dfir_agent --case CASE-ID --out ./out/CASE-ID --mode live
```

Connects an actual Claude model (default `claude-haiku-4-5-20251001`) to `dfir-mcp` over JSON-RPC stdio MCP: the controller launches `python3 -m dfir_mcp.server_stdio` as a subprocess, performs the MCP handshake, converts the advertised tool schemas to Anthropic tool-use format, and runs the tool-use loop up to `--max-iterations`. The model picks the next call based on its judgment, but the surface is the same 73-tool set (48 native + 25 SIFT adapters), and the read-only guarantee holds because there is no `execute_shell` for it to call. Live mode needs the `live` extra (`anthropic`, `mcp<2`, `requests`); with `--dry-run` a scripted stand-in plays Claude so CI can exercise the same MCP plumbing with no credentials.

See [Live mode](../docs/live-mode.md) for the wire-level details, prompt-cache accounting and troubleshooting.

### Authentication

Live-mode credentials are resolved by `dfir_agent.auth` (added in v1.2.0 as model-aware authentication):

1. **Haiku (the default model):** local Claude Code credentials are used first when present on the analyst host (`~/.claude/.credentials.json`, an XDG path, the macOS location or the macOS Keychain; `CLAUDE_CREDENTIALS_FILE` overrides the search), refreshed when close to expiry; `ANTHROPIC_API_KEY` is the fallback.
2. **Sonnet and Opus:** `ANTHROPIC_API_KEY` only — the subscription token does not serve those models, so there is no OAuth fallback.
3. The resulting credential is handed to the Anthropic SDK. The chosen source is logged next to the model on every run.

No token ever lives in code or the repository — every value is read at runtime from the local store. Check what a run would use with the `dfir-auth` alias that `scripts/install.sh` writes, or directly:

```bash
python3 dfir_agent/src/dfir_agent/auth.py
```

## Playbook loading

The playbook is a versioned artifact in `dfir_playbook/`, not a string baked into the agent. In live mode `live.py` picks the highest-sorting `dfir_playbook/senior-analyst-v*.yaml` at import time and renders its `sequence` — each phase's name, the first sentence of its `rationale` and up to six of its `mcp_calls` — plus any `classification_guidance` block into the system prompt, followed by the two cross-cutting rules the methodology always enforces (competing hypotheses and cross-validation; every finding cites a tool call). If the file or PyYAML is unavailable the controller falls back to a minimal built-in five-step sequence so the agent still runs. There is no `--playbook` flag in the current CLI. Deterministic mode does not read the YAML; its four phases are scripted in code, using the phase names of `senior-analyst-v1.yaml`. See [dfir-playbook](../dfir_playbook/README.md) for the YAML grammar and what the runtime consumes.

## Files

```
dfir_agent/
├── README.md
├── pyproject.toml         # dfir-agent; depends on dfir-audit, dfir-mcp; extra [live] = anthropic, mcp<2, requests
└── src/dfir_agent/
    ├── __init__.py        # public entry point + DeterministicAnalyst class
    │                      # (loop, hypothesis state, finding serializer and the argparse CLI
    │                      #  all live here — the deterministic control flow fits in one file)
    ├── __main__.py        # python3 -m dfir_agent -> main()
    ├── live.py            # live-mode controller: playbook rendering, MCP stdio client, tool-use loop, dry-run mock
    └── auth.py            # credential resolution (API key / local Claude credentials), runnable for a status check
```

## Status

Implemented — deterministic, live and dry-run modes. Run `pytest tests/test_agent_self_correction.py tests/test_live_mcp.py tests/test_live_findings_extraction.py tests/test_live_truncation.py tests/test_live_usage_tracking.py` for the agent-specific tests, or the whole suite as described in [`tests/README.md`](../tests/README.md).

## See also

- [Architecture](../docs/architecture.md) — design rationale
- [Operator guide](../docs/operator-guide.md) — running it on real evidence
- [Live mode](../docs/live-mode.md) — wire-level details for live mode
- [dfir-playbook](../dfir_playbook/README.md) — the YAML the live prompt is rendered from
- [dfir-audit](../dfir_audit/README.md) — the chain every finding cites
