# Pending tests

Tests in this directory exercise functions that are **not on the
current 60-tool MCP surface** (35 native + 25 SIFT adapters) but
are scaffolded for Phase 2:

- `test_extended_mcp.py` — needs `parse_evtx`, `volatility_summary`,
  `duckdb_timeline_correlate`. Surface has the *successors* of these
  (`analyze_event_logs`, `correlate_timeline`) but not the originals.
  A native `parse_evtx` is tracked at issue #30 (post-sans). The SIFT
  adapter layer has `sift_evtxecmd_filter_eids` which is a working
  alternative for Windows event-log triage at scale today.

- `test_sigma_matcher.py` — needs `match_sigma_rules`. Sigma matching
  is part of Phase 2 (detection-engineering work, not the hackathon
  submission). Tracked at issue #10 (post-sans).

These tests are **not** in the "31/31 passing on a clean clone" count
that the README cites. They live here so the test intent is preserved
for when the corresponding surface lands in Phase 2.

Do not move them back to `tests/` until the corresponding functions
are registered in `dart_mcp` and the `tests/_pending/test_*.py`
imports succeed cleanly.
