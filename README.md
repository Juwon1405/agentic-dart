# YuShin (優心) — Autonomous DFIR Agent on SANS SIFT Workstation

> *An autonomous DFIR agent that thinks like a senior analyst.*
> *Architecture-first, not prompt-first.*

**Submission to:** [SANS FIND EVIL! Hackathon 2026](https://findevil.devpost.com/)
**License:** MIT
**Status:** 🟢 MVP runs end-to-end; self-correction path validated. Active development through June 15, 2026.

---

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

## Roadmap

- MFTECmd / PECmd wrappers (W2 — completes the scaffolded functions)
- Live Claude Code integration via MCP stdio (W3)
- DuckDB correlation engine (W4)
- macOS evidence depth (UnifiedLogs, KnowledgeC, FSEvents) — post-submission
- Multi-agent decomposition — post-submission

## License

MIT — see [LICENSE](./LICENSE).

## Author

**YuShin (優心 / Bang Juwon)** — DFIR practitioner.
Contact via GitHub.
