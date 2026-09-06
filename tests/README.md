# Tests

`pytest` test suite for the five packages plus the live-mode agent loop.
The suite is split across two directories:

- `tests/` — dfir_mcp / dfir_agent / dfir_audit, parsers, live-mode loop,
  hardening, and the evaluation-suite contracts.
- `dfir_corr/tests/` — the correlation engine, extracted into its own package
  in v0.7.1.

Run both from repo root; run pytest for the authoritative count:

```bash
PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src \
  python3 -m pytest tests/ dfir_corr/tests/ -q
```

CI (`.github/workflows/ci.yml`, Python 3.10–3.13) runs the same files on every
push: the standalone-style files (`test_audit_chain.py`, `test_mcp_surface.py`,
`test_mcp_bypass.py`, `test_sift_adapters.py`,
`test_concurrency_and_edge_cases.py`, `test_agent_self_correction.py`) as
`python3 tests/<file>`, the pytest-collected files as one `python3 -m pytest`
batch, `test_live_mcp.py` in its own step (it launches a real `dfir-mcp` stdio
subprocess), `python3 -m pytest dfir_corr/tests/`, and finally
`bash examples/demo-run.sh`.

## Categories

| File | Covers |
|---|---|
| `test_mcp_surface.py` | dfir_mcp registry shape and tool signatures |
| `test_audit_chain.py` | dfir_audit chained writes and replay |
| `test_concurrency_and_edge_cases.py` | parallel / racey paths, malformed input |
| `test_parse_linux_dfir.py` | Linux parsers (auditd, bash_history, journald) on the realistic tree |
| `test_parse_registry_hive.py` | Windows registry hive parsing |
| `test_evtxecmd_oom.py` | EvtxECmd adapter OOM-safe truncation |
| `test_sift_adapters.py` | SIFT workstation tool adapters |
| `test_sigma_matcher.py` | `match_sigma_rules` against the real `dfir_sigma/` pack and a synthetic event log |
| `test_v05_supply_chain.py` | v0.5 supply-chain detection |
| `test_v06_macos_linux.py` | v0.6 macOS/Linux coverage |
| `test_qa_pass_regressions.py` | regressions caught during the QA rounds |
| `test_mcp_bypass.py` | direct vs MCP function-call equivalence; path-traversal, absolute-path and null-byte escapes; exact positive/negative surface set |
| `test_agent_self_correction.py` | dfir_agent self-correction loop |
| `test_live_mcp.py`, `test_live_truncation.py`, `test_live_usage_tracking.py` | live-mode agent loop, truncation, token usage |
| `test_live_findings_extraction.py` | live-mode parsing of the final `REPORT:` block back into `state.findings` |
| `test_download.py` | `scripts/eval/download.py` offline: split-concat, browser headers, `--dry-run`, `--check-urls` (network boundary monkeypatched) |
| `test_eval_layout.py` | the tiered case-study layout and `analyze.py` contracts, without calling the API |

## Layout notes

- **`fixtures/`** — static inputs (currently `registry-hives/`) used by the
  parser tests. Not exposed via `__init__.py`; tests load directly.
- **`_pending/`** — quarantined tests staged for future inclusion (extended
  MCP coverage for functions not yet on the surface). Has its own README.

## What about the evidence trees?

Per-case scoring of the cases under
`examples/case-studies/{self-evaluation,external-evaluation}/` is **not**
part of `pytest`. That
lives under `scripts/eval/` (`scripts/eval/score.py`, `scripts/eval/demo.py`) and runs
separately as the `benchmark-integrity` workflow. See
[`scripts/eval/README.md`](../scripts/eval/README.md) and
[`docs/writing-case-studies.md`](../docs/writing-case-studies.md).

## See also

- [Operator guide](../docs/operator-guide.md) — running the tests as part of a real install
- [`dfir_corr/README.md`](../dfir_corr/README.md) — the engine tests in `dfir_corr/tests/`
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — which tests a PR must keep green
