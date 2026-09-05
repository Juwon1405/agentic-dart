# Pending tests

Tests in this directory exercise functions that are **not on the
current 73-tool MCP surface** (48 native + 25 SIFT adapters) but
are scaffolded for Phase 2:

- `test_extended_mcp.py` — needs `parse_evtx`, `volatility_summary`,
  `duckdb_timeline_correlate`. The current surface has *successors*
  of these (`analyze_event_logs`, `correlate_timeline`) but not the
  originals. A native `parse_evtx` is tracked at issue #30.
  The SIFT adapter layer has `sift_evtxecmd_filter_eids`
  which is a working alternative for Windows event-log triage at
  scale today.

- `test_sigma_matcher.py` — needs `match_sigma_rules`. Sigma
  matching is part of Phase 2 (detection-engineering work).
  Tracked at issue #10.

These tests are **not** part of the 93-test pass count the README
cites (79 dfir_mcp/agent/audit + 14 dfir_corr). They live here so
the test intent is preserved for when the corresponding surface
lands in Phase 2.

Do not move them back to `tests/` until the corresponding functions
are registered in `dfir_mcp` and the `tests/_pending/test_*.py`
imports succeed cleanly.
