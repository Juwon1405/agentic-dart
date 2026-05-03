# Agentic-DART Architecture

## Thesis

Protocol SIFT works. It also hallucinates more than a DFIR practitioner can stand behind in a courtroom-grade report. The fix is not a better prompt. The fix is to make analyst reasoning — and evidence integrity — **properties of the system's shape**, not rules the agent is asked to follow.

## System overview

See [`../dart-architecture.png`](../dart-architecture.png).

The stack is a deliberate hybrid of three of the four supported FIND EVIL! architectural patterns:

1. **Custom MCP Server (primary enforcement layer)** — `dart-mcp`
2. **Direct Agent Extension on Claude Code** — `dart-agent`
3. **Persistent Learning Loop** — iteration controller + `progress.jsonl`

The fourth pattern (Multi-Agent Framework) is reserved for the post-submission roadmap.

## Components

### `dart-agent` — Claude Code wrapper

Responsible for:

- Loading the senior-analyst system prompt from `dart_playbook/`
- Maintaining the hypothesis tracker (writes to `progress.jsonl`)
- Running the iteration controller with `--max-iterations` hard cap
- Routing all forensic work through the MCP server — never through shell

Not responsible for:

- Security boundaries (those live in the MCP server + OS mount)

### `dart-mcp` — Custom MCP Server

The enforcement layer. Exposes **typed, schema-validated functions only**. Examples:

| Function | Returns | Guardrail |
|---|---|---|
| `get_amcache()` | Structured JSON (paginated) | No arbitrary paths |
| `extract_mft_timeline(start, end)` | Structured JSON (cursor) | Bounded by time window |
| `parse_prefetch(target)` | Structured JSON | `target` validated against allowlist |
| `analyze_usb_history()` | Structured JSON | Read-only registry access |
| `list_scheduled_tasks()` | Structured JSON | System-wide read only |
| `correlate_events(hypothesis_id)` | Structured JSON | Operates on already-extracted data |

Functions that **are not exposed** (and therefore cannot be called):

- `execute_shell()`
- `write_file()`
- `mount()` / `umount()`
- `network_egress()` of any kind

The server pre-parses tool output (which can be gigabytes) and returns cursor-paginated JSON so the LLM context is never flooded.

### `dart-corr` — Cross-artifact correlation engine

Python + DuckDB. Performs timeline joins across:

- Disk artifacts (MFT, Amcache, Prefetch, USB setupapi)
- Memory artifacts (process tree, network sockets, registry hives in RAM)
- Network artifacts (PCAP flows, DNS, auth)

When two sources contradict, the contradiction is flagged as **UNRESOLVED** and written to `progress.jsonl`. The agent is architecturally forbidden from smoothing over contradictions in its report.

### `dart-audit` — JSONL logger

Side-tapped from every MCP call. Each entry:

```json
{
  "ts": "2026-06-01T14:23:17.412Z",
  "iteration": 2,
  "tool_name": "extract_mft_timeline",
  "inputs": {"start": "2025-12-01T00:00:00Z", "end": "2025-12-08T00:00:00Z"},
  "output_digest": "sha256:...",
  "audit_id": "a7f3e9",
  "token_count_in": 412,
  "token_count_out": 1847,
  "finding_ids": ["F-013", "F-014"]
}
```

Every finding in the final report carries an `audit_id`. Judges can trace any claim back to the exact tool call in ≤3 clicks.

### `dart-playbook` — YAML sequencing rules

The senior-analyst playbook, expressed as YAML so other responders can contribute without touching Python. See [`../dart_playbook/senior-analyst-v3.yaml`](../dart_playbook/senior-analyst-v3.yaml) (default — industrialization release) or [`v2`](../dart_playbook/senior-analyst-v2.yaml) (methodology baseline) or [`v1`](../dart_playbook/senior-analyst-v1.yaml) (quick demo).

## Evidence integrity — by architecture

Integrity is enforced at **three layers**, any one of which is sufficient on its own:

1. **OS layer:** Evidence is mounted read-only (`mount -o ro,noload`) before the agent starts. The kernel refuses writes.
2. **MCP server layer:** The server exposes no function that writes to the evidence path. Calls that would modify evidence **do not exist**.
3. **Integrity verification:** SHA-256 of every evidence file is recorded at startup in `audit.jsonl`. Any deviation at finalization fails the run.

This is the architectural property that lets a practitioner stand behind the agent's output in a courtroom-grade report.

## Prompt-based guardrails vs. architectural guardrails

| Guardrail | Implementation | Bypass risk |
|---|---|---|
| "Please do not modify evidence" | Prompt | High — model ignores under adversarial input |
| "Only use these tools" | Prompt | Moderate — model may invent tool output |
| No `execute_shell` function registered | Architecture | None — function does not exist |
| Evidence mounted `ro,noload` | OS kernel | None — kernel enforces |
| SHA-256 pre/post verification | Separate verifier | Detects any deviation |

Agentic-DART uses the bottom three, not the top two.

## Trust boundaries (for judges)

- **Inside the agent's trust:** Playbook YAML, progress.jsonl (agent-writable state)
- **Outside the agent's trust:** Evidence files, audit.jsonl (append-only), final report path
- **The MCP surface is the trust boundary itself** — everything the agent does passes through typed functions. There is no other path.
