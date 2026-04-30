# Live Mode — Claude API + dart-mcp over stdio

Agentic-DART runs in two modes:

| Mode | Claude? | Network? | Purpose |
|---|---|---|---|
| `deterministic` | No (scripted) | No | Reproducible demo, accuracy metric, CI |
| `live` | Yes (Anthropic API) | Yes | Real investigation against real evidence |

`live` mode is what you use when a real case comes in.

## What `live` mode actually does

```
┌────────────────────────┐                  ┌──────────────────────────┐
│   dart_agent         │  MCP over stdio  │ dart_mcp.server_stdio  │
│   (Anthropic API       │ ◄───────────────►│ (subprocess; 15 typed    │
│    tool-use loop)      │  JSON-RPC        │  forensic functions)     │
└──────────┬─────────────┘                  └────────────┬─────────────┘
           │                                             │
           │ HTTPS                                       │ file read
           ▼                                             ▼
    api.anthropic.com                           EVIDENCE_ROOT (read-only)
```

The agent:

1. Spawns `python -m dart_mcp.server_stdio` as a subprocess
2. Completes the MCP initialize handshake
3. Calls `list_tools()` — sees exactly the 15 registered forensic functions
4. Hands that tool list (converted to Anthropic's tool-use schema) to Claude
5. Enters a loop: ask Claude → receive tool_use blocks → route each via MCP
   session → feed results back → repeat until Claude stops or max-iter hits

Claude can NOT see anything beyond the 31 functions. Not because we told
it not to — because the MCP server does not expose anything else.

## Running it

### With a real API key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export DART_EVIDENCE_ROOT=/path/to/evidence
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"

python3 -m dart_agent --mode live \
    --case my-case \
    --out /tmp/my-case-out \
    --prompt "Investigate evidence root for IP-KVM insider pattern. Report findings with audit IDs." \
    --model claude-opus-4-7 \
    --max-iterations 10
```

### Without an API key (CI, offline reproduction)

Pass `--dry-run`. Everything runs the same — MCP subprocess, stdio
handshake, real tool calls — except Claude is replaced with a scripted
mock that walks a plausible tool-call sequence. Useful for:

- CI pipelines where an API key shouldn't live
- Verifying the MCP plumbing without spending tokens
- Running the same plumbing Claude will use in a deterministic test

```bash
python3 -m dart_agent --mode live --case test --out /tmp/out --dry-run
```

## Outputs

Live mode writes three files to `--out`:

| File | Contents |
|---|---|
| `live_summary.json` | case id, mode, iterations, tool_call_count, final findings |
| `live_tool_calls.jsonl` | one line per MCP call: iteration, tool, input, output preview |
| `live_transcript.txt` | the assistant's final text (or the mock transcript) |

These sit alongside the existing `audit.jsonl` / `progress.jsonl` /
`report.json` from deterministic mode — same evidence tree, same run
directory, same audit-chain discipline.

## Why this is the architecturally correct design

Compare two hypothetical designs for a DFIR agent:

### ❌ Design A: "give the LLM shell access and tell it to behave"

```python
# Anti-pattern — do NOT do this
def execute_shell(cmd: str) -> str:
    """The LLM has read our system prompt saying 'only read evidence'."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
```

One prompt injection in a document, one hallucinated command, one model
update that changes the alignment, and the LLM can do anything.

### ✅ Design B: "give the LLM a typed, read-only function set"

```python
# dart-mcp registers ONLY this interface
@tool(name="extract_mft_timeline", schema=...)
def extract_mft_timeline(mft_path, start, end): ...
```

The LLM can no more call `execute_shell` than it can call `delete_evidence`
— those names do not resolve to anything on the server. It is not a
policy. It is an absence.

The MCP protocol is the enforcement point. `test_live_mcp.py` asserts this
with a real `call_tool("execute_shell", ...)` over the wire — the
call is blocked by `KeyError: ToolNotFound` at the protocol layer, not
by any prompt.

## Tests you can run right now

```bash
# End-to-end: agent subprocess spawns MCP subprocess, 15-tool handshake,
# real tool calls over stdio, guardrail-over-wire verification.
python3 tests/test_live_mcp.py
```

Four tests, all run in under 10 seconds, no API key required.
