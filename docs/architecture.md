# Architecture

This page explains how Agentic-DFIR is put together and why it is shaped the way it is: the five packages and the single read-only boundary between them, the repository layout, the reasons for DuckDB and for a SHA-256-chained audit log, the three layers that protect evidence, and what was deliberately not built. For the safety argument in adversarial terms see [Threat model](./threat-model.md); for the design philosophy on its own see [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md).

## Thesis

A prompt-first DFIR agent works. It also hallucinates more than a DFIR practitioner can stand behind in a courtroom-grade report. The fix is not a better prompt. The fix is to make analyst reasoning — and evidence integrity — **properties of the system's shape**, not rules the agent is asked to follow.

## The core claim

> A senior analyst's reasoning is not "what to say" — it's *what they
> refuse to do*. Encode the refusal as architecture, not as prompt.

Here is what that means concretely.

A traditional LLM-driven assistant is a function:

```
(prompt + context) → text
```

The safety surface is the *prompt*. Every guardrail you want — "don't
modify evidence", "don't fabricate findings", "always cite an
artifact" — has to be re-asserted in language. Language is leaky.
A jailbreak, an unusual context, or a long enough conversation can
erode every prompt-based guardrail.

Agentic-DFIR inverts this:

```
(prompt + context) → typed_tool_call(args) → typed_result
                          ↑                       ↑
                    schema-validated       no destructive op exists
```

The agent literally cannot call `execute_shell` or `write_file` on
the evidence tree, because those functions do not exist on the MCP
surface. The "guardrail" is not a sentence in the prompt. It is the
absence of a function.

This is why the project's bypass test ([`tests/test_mcp_bypass.py`](../tests/test_mcp_bypass.py))
is the most important test in the repository:

```python
def test_unregistered_destructive_function_raises_ToolNotFound():
    """Calling anything not in the registry must fail hard."""
    for forbidden in ["execute_shell", "write_file", "mount", "umount",
                      "network_egress", "eval", "exec_python",
                      "delete_file", "system"]:
        try:
            call_tool(forbidden, {})
        except KeyError as e:
            assert "ToolNotFound" in str(e), f"wrong error for {forbidden}"
            continue
        raise AssertionError(
            f"SECURITY: call_tool({forbidden!r}) did not raise — "
            f"forbidden function is somehow exposed")
```

If that test ever fails — meaning *something* on the MCP surface lets
a destructive verb through — the architecture has been compromised.
The agent's reasoning quality is downstream of this; it does not
matter how smart the loop is if the surface leaks.

## System overview

![Agentic-DFIR Architecture](./dfir-architecture.png)

Editable source: [`dfir-architecture.drawio`](./dfir-architecture.drawio).

The stack has four parts:

1. **Custom MCP server (primary enforcement layer)** — `dfir_mcp`, exposing typed native Python functions plus adapters for the SIFT Workstation toolchain. The agent has no `execute_shell()`. Destructive commands are not refused — they are *not present*.
2. **Agent loop** — `dfir_agent`, a wrapper that drives Claude through the Anthropic API exclusively via that MCP surface (Claude Code can also call the same server interactively) and handles session ergonomics. Security boundaries live in the server, not the prompt.
3. **Persistent learning loop** — the iteration controller plus `progress.jsonl`. Every iteration writes hypothesis, confidence, and unresolved gaps; the next iteration must address those gaps or declare them unreachable.
4. **Tamper-evident audit chain** — `dfir_audit`. Every MCP call is recorded in a SHA-256-chained JSONL file. Any rewrite fails verification.

Evidence is mounted **read-only at the OS level** before the agent is ever started. A multi-agent layer is not part of the current design; later phases build on the same read-only, audit-chained core (see [Roadmap](./roadmap.md)).

## Five small packages, one boundary

```
┌─────────────────────────────────────────────────────────────────┐
│                       IR analyst (human)                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│           dfir-agent     (senior-analyst loop wrapper)          │
│           dfir-playbook  (YAML sequencing rules)                │
└────────────────────────────┬────────────────────────────────────┘
                             │  (typed MCP calls only)
┌────────────────────────────▼────────────────────────────────────┐
│           ▼  READ-ONLY BOUNDARY (architectural)  ▼              │
│                                                                 │
│           dfir-mcp      typed forensic function surface         │
│                         (native + SIFT adapters)                │
│                         · schema-validated input                │
│                         · cursor-paginated output               │
│                         · no destructive verb exists            │
│                                                                 │
│           dfir-corr     DuckDB cross-artifact correlation       │
│                         · flags contradictions as UNRESOLVED    │
│                                                                 │
│           dfir-audit    SHA-256 chained JSONL                   │
│                         · side-tapped from every MCP call       │
│                         · replayable, tamper-evident            │
│                                                                 │
│           Evidence (read-only mount)                            │
└─────────────────────────────────────────────────────────────────┘
```

Each package owns exactly one responsibility:

| Package | Owns | Forbidden |
|---|---|---|
| `dfir_audit` | Append-only, chained log of every tool call | Reading evidence directly |
| `dfir_mcp` | The set of tools the agent can call | Side-effects outside the evidence tree |
| `dfir_agent` | The reasoning loop | Calling tools that aren't on the MCP surface |
| `dfir_corr` | Cross-artifact correlation, contradiction detection | Making claims (only surfaces them) |
| `dfir_playbook` | Sequencing rules, analyst heuristics | Imperative code |

A sixth directory, `dfir_sigma`, is data rather than code: the Sigma detection-rule pack that `match_sigma_rules` reads (see [`dfir_sigma/README.md`](../dfir_sigma/README.md)).

## Repository layout

```text
agentic-dfir/
├── dfir_audit/           SHA-256-chained JSONL logger — every MCP call recorded, tamper-evident
├── dfir_mcp/             Custom MCP server — typed, read-only forensic functions (native + sift_adapters/)
├── dfir_agent/           Iteration controller, hypothesis tracker, self-correction loop, live-mode client
├── dfir_corr/            Cross-artifact correlation engine — DuckDB joins, contradiction flagging
│   ├── correlation-rules.yaml      operator-tunable rule pack
│   └── tests/                      engine tests (run with the root suite)
├── dfir_playbook/        Senior-analyst YAML playbooks (v1 / v2 / v3 industrialization)
├── dfir_sigma/           Sigma detection-rule pack — 11 rules under rules/, pack.yml index; feeds match_sigma_rules
│
├── examples/
│   ├── case-studies/               two tiers, self-contained cases (README + truth.json + evidence_root)
│   │   ├── self-evaluation/        case-01..08 — synthetic; each ships its own evidence_root + truth.json
│   │   └── external-evaluation/    case-01..03 — public datasets (NIST CFReDS / Ali Hadi / Digital Corpora M57)
│   ├── out/ref-01/                 committed reference run (audit.jsonl, progress.jsonl, report.json)
│   ├── demo-run.sh                 low-level reproducible demo (native tools, no API key)
│   └── sift-adapter-demo.sh        SIFT-adapter demo (needs SIFT binaries on PATH)
│
├── analyze.py            primary user-facing command (live mode; fail-fast without a key)
├── requirements.txt      third-party deps (mirrors the package pyproject lower bounds)
├── pytest.ini            pytest configuration
├── tests/                pytest suite (fixtures/, _pending/; run it for the authoritative count)
├── scripts/              install.sh, healthcheck.py, check_sift_tools.py, regenerate_*.py,
│                         eval/ (demo · self · external · download · score · validate_ground_truth)
├── docs/                 this documentation set (index: docs/README.md), diagram source, screenshots, benchmarks
├── .github/              workflows/ (ci.yml: CI matrix Python 3.10–3.13 + URL reachability;
│                         benchmark-integrity.yml), issue and PR templates, dependabot.yml
│
├── README.md             landing page
├── CHANGELOG.md          release history
├── CONTRIBUTING.md       contribution rules and PR checklist
├── SECURITY.md           how to report a boundary bypass
├── CODE_OF_CONDUCT.md
├── AGENTS.md / CLAUDE.md guides for AI coding assistants working in this repository
└── LICENSE               MIT
```

Each package has its own `README.md` with deeper detail (wire surface for [`dfir_mcp`](../dfir_mcp/README.md), engine internals for [`dfir_corr`](../dfir_corr/README.md), YAML grammar for [`dfir_playbook`](../dfir_playbook/README.md), audit format for [`dfir_audit`](../dfir_audit/README.md), the loop for [`dfir_agent`](../dfir_agent/README.md)).

## Components

### `dfir-agent` — the senior-analyst loop wrapper

Responsible for:

- Loading the senior-analyst system prompt from `dfir_playbook/`
- Maintaining the hypothesis tracker (writes to `progress.jsonl`)
- Running the iteration controller with `--max-iterations` hard cap
- Routing all forensic work through the MCP server — never through shell

Not responsible for:

- Security boundaries (those live in the MCP server + OS mount)

The agent has two modes, selected with `--mode deterministic|live`. Deterministic mode is a scripted analyst that calls `dfir_mcp` functions directly, writes `audit.jsonl` through `dfir_audit.AuditLogger`, and verifies the chain at exit. Live mode spawns `python -m dfir_mcp.server_stdio` as a subprocess, talks MCP over stdio, and lets Claude choose tools; it records every call in `live_tool_calls.jsonl` and the final findings in `live_summary.json`. See [Live mode](./live-mode.md).

### `dfir-mcp` — Custom MCP Server

The enforcement layer. Exposes **typed, schema-validated functions only** — 73 in total: 48 native pure-Python functions plus 25 SIFT Workstation adapters (12 Volatility 3 plugins, 9 Eric Zimmerman tool wrappers, 2 YARA, 2 Plaso). Examples:

| Function | Returns | Guardrail |
|---|---|---|
| `get_amcache()` | Structured JSON (paginated) | No arbitrary paths |
| `extract_mft_timeline(start, end)` | Structured JSON (cursor) | Bounded by time window |
| `parse_prefetch(prefetch_path)` | Structured JSON | path resolved under the read-only evidence root |
| `analyze_usb_history()` | Structured JSON | Read-only registry access |
| `list_scheduled_tasks()` | Structured JSON | System-wide read only |
| `correlate_events(hypothesis_id)` | Structured JSON | Operates on already-extracted data |

Functions that **are not exposed** (and therefore cannot be called):

- `execute_shell()`
- `write_file()`
- `mount()` / `umount()`
- `network_egress()` of any kind

Every function that takes a path routes it through `_safe_resolve`, which canonicalizes the path and rejects anything outside `DFIR_EVIDENCE_ROOT`. The server pre-parses tool output (which can be gigabytes) and returns cursor-paginated JSON so the LLM context is never flooded. The full list is enumerated at runtime by `list_tools()`; see [MCP function catalog](./mcp-function-catalog.md) and [SIFT adapter layer](./sift-adapter-layer.md).

### `dfir-corr` — Cross-artifact correlation engine

Python + DuckDB. Performs timeline joins across:

- Disk artifacts (MFT, Amcache, Prefetch, USB setupapi)
- Memory artifacts (process tree, network sockets, registry hives in RAM)
- Network artifacts (PCAP flows, DNS, auth)

When two sources contradict, the contradiction is flagged as **UNRESOLVED** and written to `progress.jsonl`. The agent is architecturally forbidden from smoothing over contradictions in its report.

### `dfir-audit` — JSONL logger

Side-tapped from every MCP call. Each entry is one line; this is the first entry of the committed reference run, [`examples/out/ref-01/audit.jsonl`](../examples/out/ref-01/audit.jsonl):

```json
{
  "audit_id": "7f311676",
  "entry_hash": "ea08eeb3545d901a8b7e5a0154f42ef93d492975f8e5f9cabc25d5cab31b5db0",
  "finding_ids": ["F-001"],
  "inputs": {"hive_path": "disk/Windows/AppCompat/Programs/Amcache.hve"},
  "iteration": 1,
  "output_digest": "sha256:46a1479e21342706e2df979e3b5e0fe31544dad6ffb29684cfa0cf1cd81c1cd4",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "token_count_in": 15,
  "token_count_out": 500,
  "tool_name": "get_amcache",
  "ts": "2026-06-14T21:02:19.713Z"
}
```

`prev_hash` is the previous entry's `entry_hash` (all zeros for the first entry); `entry_hash` is the SHA-256 of `prev_hash` plus the canonical JSON body. The tool output itself is not stored — only its digest — so the log stays small.

Every finding in the final report carries the `audit_id`s of the MCP calls that produced it. Reviewers can trace any claim back to the exact tool call with `python3 -m dfir_audit trace <audit.jsonl> <finding-id>`; the CLI also offers `verify`, `lookup <audit_id>`, and `summary`.

### `dfir-playbook` — YAML sequencing rules

The senior-analyst playbook, expressed as YAML so other responders can contribute without touching Python. See [`../dfir_playbook/senior-analyst-v3.yaml`](../dfir_playbook/senior-analyst-v3.yaml) (default — industrialization release) or [`v2`](../dfir_playbook/senior-analyst-v2.yaml) (methodology baseline) or [`v1`](../dfir_playbook/senior-analyst-v1.yaml) (quick demo).

## Why DuckDB

`dfir-corr` is the boring part of the project, and it is the part that
makes the rest work.

LLMs are excellent at narrative reasoning and bad at *set algebra at
scale*. Joining a 5-million-row MFT timeline against a 200-thousand-row
process list under time pressure is set algebra. We push that work
to DuckDB and let the agent do what it's good at: interpreting the
join result.

Specifically:

- DuckDB runs in-process (no daemon, no port to harden)
- Reads Parquet, CSV, and JSONL natively — most evidence parsers
  produce one of those
- Joins of millions of rows finish in seconds on a SIFT VM
- Window functions for time-proximity joins are first-class

The agent never writes SQL. `dfir-corr` exposes a small typed surface
(`correlate_events`, `correlate_timeline`, `correlate_download_to_execution`) and the agent calls those through `dfir_mcp`. The optional `rules` strings an operator can pass to `correlate_timeline` are checked against a strict character allow-list and a forbidden-keyword block before they reach DuckDB; rejected rules come back as structured errors, never as executed SQL.

## Why SHA-256 chained audit

Forensic findings have a chain-of-custody requirement that ordinary
software doesn't. If the agent claims "USB Kingston DataTraveler was
inserted at 14:22:18 UTC", a reviewer must be able to verify, after
the fact, that:

1. The agent actually *saw* that artifact
2. The artifact has not been edited between the agent's read and the
   reviewer's verification
3. No log entry has been silently inserted, deleted, or reordered

A simple append-only log gives you (1). A SHA-256 chain — where each
entry's hash includes the previous entry's hash — gives you (2) and
(3) for free. Tampering with any entry breaks the chain at that point
and every subsequent point.

Implementation: [`dfir_audit/src/dfir_audit/__init__.py`](../dfir_audit/src/dfir_audit/__init__.py), under two hundred lines.
The simplicity is the feature; this is not the place to be clever.

## Evidence integrity — by architecture

Integrity is enforced at **three layers**, any one of which is sufficient on its own:

1. **OS layer:** Evidence is mounted read-only (`mount -o ro,noload`) before the agent starts. The kernel refuses writes.
2. **MCP server layer:** The server exposes no function that writes to the evidence path. Calls that would modify evidence **do not exist**. Adapters that must produce output (Plaso storage files) write only under `DFIR_DERIVED_ROOT`, never under the evidence root.
3. **Integrity verification:** Tools record the SHA-256 of the input files they read (the `_sha256` helper is used throughout `dfir_mcp` and by every SIFT adapter), and that output is digested into the audit chain. The evaluation runner (`scripts/eval/demo.py`) additionally hashes every file under the evidence root before and after the run and reports `evidence_integrity: false` if a single digest differs; the accuracy report publishes that result.

This is the architectural property that lets a practitioner stand behind the agent's output in a courtroom-grade report.

## Prompt-based guardrails vs. architectural guardrails

| Guardrail | Implementation | Bypass risk |
|---|---|---|
| "Please do not modify evidence" | Prompt | High — model ignores under adversarial input |
| "Only use these tools" | Prompt | Moderate — model may invent tool output |
| No `execute_shell` function registered | Architecture | None — function does not exist |
| Evidence mounted `ro,noload` | OS kernel | None — kernel enforces |
| SHA-256 pre/post verification | Separate verifier | Detects any deviation |

Agentic-DFIR uses the bottom three, not the top two.

## Trust boundaries

- **Inside the agent's trust:** Playbook YAML, progress.jsonl (agent-writable state)
- **Outside the agent's trust:** Evidence files, audit.jsonl (append-only), final report path
- **The MCP surface is the trust boundary itself** — everything the agent does passes through typed functions. There is no other path.

## What was deliberately not built

These are conscious omissions, not oversights.

### No "general purpose escape hatch"

There is no `execute_shell`, no `eval`, no `subprocess.run` exposed
through the MCP surface. The temptation in agent design is to add a
general fallback so the agent can "just figure it out" when the typed
surface is insufficient. We refuse this. If a typed function is
missing, the right move is to add a *new typed function*, not to
expose a general escape.

### No write path to evidence

Every parser opens files in `'r'` or `'rb'` mode. The OS-level mount
is read-only. There is no code path that can write to the evidence
tree even if asked. Evidence is fixture, not workspace.

### No automatic remediation

The agent does not quarantine, terminate, or block anything. It
*reports*. Phase 3 of the [roadmap](./roadmap.md) (agentic SOC) is planned to introduce
*supervised* response, but as a separate package
(`dfir_responder`) with its own boundary, not a flag on `dfir-agent`.

### No memory across cases

A run is a run. State lives in `progress.jsonl` and `audit.jsonl` for
the duration of one case. There is no global "knowledge base" that
accumulates across runs. The reasoning has to be reproducible from a
single audit log alone.

### No prompt-based guardrails

The system prompt does say things like "every finding you report must reference at least one tool call". But none of those instructions are *load-bearing*. In deterministic mode every `Finding` the agent emits carries the `audit_id`s of the MCP calls that produced it as a structured field, `python3 -m dfir_audit trace` walks each one back to the underlying artifact read, and the demo scorer (`scripts/eval/demo.py`) counts a finding whose `audit_id`s resolve to no chain entry as a hallucination. In live mode every call the model made is on record in `live_tool_calls.jsonl` whether or not the model cites it. Every prompt-level "rule" has a mechanical counterpart downstream.

## What this means for contributions

If you want to add something:

- **A new typed forensic function**: yes, this is the easy path.
  Read [`CONTRIBUTING.md`](../CONTRIBUTING.md)
  and add a JSON schema, a `_safe_resolve` call, and a bypass test.
- **A new playbook YAML**: yes, no Python change required.
- **A new correlation pattern in `dfir-corr`**: yes, but the new
  pattern must surface contradictions as `UNRESOLVED`, not "decide".
- **A way for the agent to write back to evidence**: no, ever.
- **A general-purpose tool ("query_anything")**: no. If you find
  yourself wanting one, the typed surface is too narrow somewhere
  specific — add a typed function for that specific case.

## See also

- [Threat model](./threat-model.md) — what the architecture defends against, and what it does not
- [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md) — the design claim on its own
- [MCP function catalog](./mcp-function-catalog.md) and [SIFT adapter layer](./sift-adapter-layer.md) — the full tool surface
- [Case study: PtH + timestomp](./case-pth-timestomp.md) — a worked example showing the loop and the contradiction handling
- [Glossary](./glossary.md)
- [Documentation index](./README.md)
