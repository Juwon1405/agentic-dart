# Tests

`pytest` test suite for the five packages plus the live-mode agent loop.
The suite is split across two directories — **150 tests total**:

- `tests/` — **136** tests (dart_mcp / dart_agent / dart_audit, parsers,
  live-mode loop, hardening).
- `dart_corr/tests/` — **14** tests (the correlation engine extracted into
  its own package in v0.7.1).

Run both from repo root:

```bash
PYTHONPATH=dart_audit/src:dart_mcp/src:dart_agent/src:dart_corr/src \
  python3 -m pytest tests/ dart_corr/tests/ -q
```

CI runs these on every push (`.github/workflows/ci.yml`): the `tests/` files
individually plus `python3 -m pytest dart_corr/tests/`.

## Categories

| File | Covers |
|---|---|
| `test_mcp_surface.py` | dart_mcp registry shape and tool signatures |
| `test_audit_chain.py` | dart_audit chained writes and replay |
| `test_concurrency_and_edge_cases.py` | parallel / racey paths, malformed input |
| `test_parse_linux_dfir.py` | Linux parsers (auditd, bash_history, journald) on the realistic tree |
| `test_parse_registry_hive.py` | Windows registry hive parsing |
| `test_evtxecmd_oom.py` | EvtxECmd adapter OOM-safe truncation |
| `test_sift_adapters.py` | SIFT workstation tool adapters |
| `test_v05_supply_chain.py` | v0.5 supply-chain detection |
| `test_v06_macos_linux.py` | v0.6 macOS/Linux coverage |
| `test_qa_pass_regressions.py` | regressions caught during the QA rounds |
| `test_mcp_bypass.py` | direct vs MCP function-call equivalence |
| `test_agent_self_correction.py` | dart_agent self-correction loop |
| `test_live_mcp.py`, `test_live_truncation.py`, `test_live_usage_tracking.py` | live-mode agent loop, truncation, token usage |

## Layout notes

- **`fixtures/`** — static inputs (currently `registry-hives/`) used by the
  parser tests. Not exposed via `__init__.py`; tests load directly.
- **`_pending/`** — quarantined tests staged for future inclusion (extended
  MCP coverage, Sigma matcher). Has its own README.

## What about the evidence trees?

Per-case scoring of the cases under
`examples/case-studies/{self-evaluation,external-evaluation}/` is **not**
part of `pytest`. That
lives under `scripts/eval/` (`scripts/eval/score.py`, `scripts/eval/demo.py`) and runs
separately as the `benchmark-integrity` workflow.
