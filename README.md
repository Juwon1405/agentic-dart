# YuShin (優心) — Autonomous DFIR Agent on SANS SIFT Workstation

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)


> *An autonomous DFIR agent that thinks like a senior analyst.*
> *Architecture-first, not prompt-first.*

**Submission to:** [SANS FIND EVIL! Hackathon 2026](https://findevil.devpost.com/)
**License:** MIT
**Status:** 🟢 MVP runs end-to-end; self-correction path validated. Active development through June 15, 2026.

---


## What YuShin is (and what it is not)

**YuShin is:** an autonomous AI agent that sits on top of the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation) and the [Protocol SIFT](https://findevil.devpost.com/) framework, runs a senior-analyst-style reasoning loop with architectural evidence-integrity guarantees, and produces a courtroom-traceable report of its findings.

**YuShin is not:** a replacement for Velociraptor, KAPE, Timesketch, Plaso, or any SIEM/EDR. Those are the layers underneath. See [`docs/comparison.md`](./docs/comparison.md) for the layer map and a side-by-side table.

**The single design principle:** evidence integrity is a property of the system's shape — what functions exist on the MCP server — not a rule the agent is asked to follow. The baseline [Protocol SIFT](https://findevil.devpost.com/) agent prompts the model to behave; YuShin removes the ability to misbehave.

## Why YuShin exists

Protocol SIFT proved that AI agents can operate the SIFT Workstation. It also hallucinates more than a DFIR practitioner can stand behind in a courtroom-grade report. YuShin is an attempt to close that gap by encoding the *reasoning pattern of a senior analyst* as architecture — not as a prompt.

The name is a Japanese reading of **優心**, meaning "discerning mind."

## Architecture

![YuShin Architecture](./yushin-architecture.png)

1. **Custom MCP Server** (`yushin_mcp`) is the primary enforcement layer. The agent has no `execute_shell()`. Destructive commands are not refused — they are *not present*.
2. **Direct Agent Extension on Claude Code** (`yushin_agent`) handles session ergonomics. Security boundaries live in the server, not the prompt.
3. **Persistent Learning Loop** — every iteration writes hypothesis, confidence, and unresolved gaps to `progress.jsonl`. The next iteration must address those gaps or declare them unreachable.
4. **Tamper-evident audit chain** (`yushin_audit`) — every MCP call is recorded in a SHA-256-chained JSONL file. Any rewrite fails verification.

Evidence is mounted **read-only at the OS level** before the agent is ever started. For the full design rationale, see [`docs/architecture.md`](./docs/architecture.md).

## Repository layout

```text
yushin-dfir/
├── yushin_audit/      # Tamper-evident JSONL logger with SHA-256 chain
├── yushin_mcp/        # Custom MCP server: typed, read-only forensic functions
├── yushin_agent/      # Iteration controller + self-correction loop
├── examples/
│   ├── sample-evidence/  # Reproducible test fixtures (triggers IP-KVM finding)
│   ├── demo-run.sh       # One-command demo — exactly what the video records
│   └── out/              # Generated on each run: audit.jsonl, progress.jsonl, report.json
├── tests/             # pytest-compatible; runs without network
├── docs/              # architecture.md, dataset.md, accuracy-report.md, troubleshooting.md
└── yushin-architecture.png
```

## Quick start — prove it works in 30 seconds

```bash
git clone https://github.com/Juwon1405/yushin-dfir.git
cd yushin-dfir
bash examples/demo-run.sh
```

Expected output:

```
[yushin-agent] iterations: 5
[yushin-agent] findings: 2
[yushin-agent] audit chain: chain verified: 3 entries, tail=1e995b6afc6a6660...
[demo] bypass test — attempting to call an unregistered destructive function:
[demo] PASS — "ToolNotFound: 'execute_shell' is not exposed by yushin-mcp"
```

The demo walks the full senior-analyst loop against sample evidence, triggers a USB contradiction, **auto-self-corrects** by widening the time window, and writes a chain-verified audit log. The bypass test proves the `execute_shell` guardrail is architectural, not prompt-based.

## Running the tests

```bash
export PYTHONPATH="$PWD/yushin_audit/src:$PWD/yushin_mcp/src:$PWD/yushin_agent/src"
python3 tests/test_audit_chain.py            # chain integrity + tamper detection
python3 tests/test_mcp_surface.py            # surface is a hard-coded set
python3 tests/test_agent_self_correction.py  # end-to-end self-correction
```

All three pass on a clean checkout. See `tests/` for exactly what is asserted.

## Target case class

Insider-threat and DPRK IT-worker-style patterns:

- IP-KVM indicators and anomalous remote-access stacks
- USB timelines contradicting authentication telemetry
- Process-tree anomalies associated with remote-hands operations
- Living-off-the-land sequencing across MFT / Amcache / Prefetch / memory

The MVP demo case exercises the IP-KVM remote-hands pattern end-to-end.

## Judging-criteria alignment (SANS FIND EVIL!)

| Criterion | How YuShin addresses it | Evidence |
|---|---|---|
| Autonomous Execution Quality | Hypothesis tracker + persistent learning loop + self-correction | `progress.jsonl` shows iteration 4 contradiction + auto-widened retry |
| IR Accuracy | Cross-artifact correlation; contradictions flagged, not smoothed | F-013 replaces F-001 hypothesis when USB contradicts logon |
| Breadth / Depth | Disk + USB + (memory, MFT, prefetch scaffolded) on a single trace | `yushin_mcp/__init__.py` exposes 6 typed functions |
| Constraint Implementation | **Architectural** — no `execute_shell` function exists in the registry | `test_mcp_surface.py::test_calling_unregistered_function_raises` |
| Audit Trail Quality | Every finding → `audit_id` → MCP call → command → raw output | `audit.jsonl` chain verifiable end-to-end |
| Usability / Documentation | One-command demo; typed schemas; YAML playbook | `examples/demo-run.sh` runs on any Python 3.10+ host |


## Platform support

Runs on SIFT Workstation (primary), Ubuntu, and **macOS 12+** (Intel and Apple Silicon). See [`docs/running-on-macos.md`](./docs/running-on-macos.md) for the 5-minute macOS quickstart.

YuShin covers **both** Windows and macOS artifacts:

- **Windows (10 functions):** Amcache, Prefetch, ShimCache, MFT, USB history, ShellBags, Scheduled Tasks, Persistence (Run keys/Services/Tasks), Event Logs, Process tree with LOTL detection
- **macOS (3 functions):** UnifiedLog (with rule pack), KnowledgeC, FSEvents
- **Cross-platform (2 functions):** `correlate_events` (proximity join), `correlate_timeline` (DuckDB scale engine)


## Live mode (real Claude API + MCP stdio)

YuShin can run in `live` mode where Claude is the agent, connected to `yushin-mcp` over real MCP stdio JSON-RPC:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m yushin_agent --mode live --case my-case --out /tmp/out \
    --prompt "Investigate for IP-KVM insider pattern"
```

Or without an API key (scripted mock-Claude over real MCP plumbing):

```bash
python3 -m yushin_agent --mode live --case test --out /tmp/out --dry-run
```

See [`docs/live-mode.md`](./docs/live-mode.md) for the architecture, the tool-use loop, and `tests/test_live_mcp.py` for end-to-end wire-level tests (no API key needed).

## Case study for judges

See [`examples/case-studies/case-01-ipkvm-insider/`](./examples/case-studies/case-01-ipkvm-insider/README.md) for a step-by-step walkthrough of the bundled IP-KVM remote-hands case — what the agent does at each iteration, what `audit.jsonl` records, and how `yushin-audit trace F-013` resolves a finding back to raw evidence in three clicks.

## Measured accuracy (reproducible)

```
Recall:                    1.000
False positive rate:       0.000
Hallucination count:       0
Evidence integrity:        preserved (8 files, all SHA-256 hashes match pre/post)
Self-correction observed:  true
```

Produced by `python3 scripts/measure_accuracy.py`. See [`docs/accuracy-report.md`](./docs/accuracy-report.md) for the full methodology, ground truth, honest limitations, and the measured bypass test table (6/6 passing).


## Status — what is implemented vs. what is roadmap

### Implemented end-to-end — 13 MCP functions, all callable from Claude Code live mode

**Windows artifacts**

| Function | What it does |
|---|---|
| `get_amcache` | Amcache.hve reader, paginated output |
| `extract_mft_timeline` | MFTECmd-CSV reader with `[start, end]` window |
| `parse_prefetch` | Native + PECmd-sidecar reader |
| `list_scheduled_tasks` | Evidence tree enumeration with per-file SHA-256 |
| `analyze_usb_history` | setupapi.dev.log parser + IP-KVM VID/PID signature detection |
| `parse_evtx` | EVTX event log reader (EvtxECmd CSV sidecar) with event_id + time window filters |

**Memory forensics**

| Function | What it does |
|---|---|
| `volatility_summary` | Volatility 3 sidecar reader — surfaces injected processes + candidate C2 IPs |

**macOS artifacts**

| Function | What it does |
|---|---|
| `parse_knowledgec` | KnowledgeC.db SQLite reader with Cocoa-epoch → ISO 8601 decoding |
| `parse_fsevents` | FSEvents CSV reader with flag filter (ItemCreated / ItemRenamed / …) |
| `parse_unified_log` | UnifiedLog `log show --style csv` reader with subsystem + process filters |

**Reasoning layer**

| Function | What it does |
|---|---|
| `correlate_events` | Python cross-artifact timeline join, contradiction flagging |
| `duckdb_timeline_correlate` | **Real DuckDB-backed cross-source join at scale** — accepts N named sources, joins on time proximity, returns paired events |
| `match_sigma_rules` | YAML Sigma matcher (`equals`, `contains`, `startswith` modifiers) |

**Infrastructure**

| Component | What it does |
|---|---|
| `yushin_agent` (CLI) | Iteration controller, hypothesis tracker, self-correction loop, `--max-iterations` cap |
| `yushin_audit` (CLI) | SHA-256-chained JSONL logger + `verify / lookup / trace / summary` subcommands |
| `yushin_mcp.server` | **JSON-RPC 2.0 MCP stdio server** — `claude mcp add yushin python3 -m yushin_mcp.server` |
| `yushin_playbook/senior-analyst-v1.yaml` | Sequencing rules for insider-threat / remote-hands class |

### Remaining roadmap (honest)

| Item | Target |
|---|---|
| Native EVTX binary parser (drop EvtxECmd CSV dependency) | W3 |
| Native Volatility 3 subprocess wiring (drop info.json sidecar) | W3 |
| Baseline Protocol SIFT agent head-to-head accuracy runs on 2 external datasets | W4 |
| Ali Hadi Challenge #1 + NIST CFReDS Hacking Case measured accuracy | W4–W5 |
| Multi-agent decomposition (Memory / Disk / Network / Synthesizer specialists) | Post-submission |
| TimeSketch export format | Post-submission |



## License

MIT — see [LICENSE](./LICENSE).

## Author

**YuShin (優心 / Bang Juwon)** — DFIR practitioner.
Contact via GitHub.
