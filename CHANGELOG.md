# Changelog

All notable changes to Agentic-DART are recorded here.

## [Unreleased] — 2026-04-20

## [0.2.0] — 2026-04-20 (Breadth Expansion)

### Added — 6 new MCP functions, all end-to-end
- `parse_evtx`: Windows EVTX event log reader with event_id + time window filters
- `volatility_summary`: memory dump analysis via Volatility 3 sidecar — surfaces injected processes and candidate C2 IPs
- `parse_knowledgec`: macOS KnowledgeC.db SQLite reader with Cocoa-epoch → ISO 8601 decoding (real SQLite connection, not a stub)
- `parse_fsevents`: macOS FSEvents CSV reader with flag substring filter
- `parse_unified_log`: macOS UnifiedLog (`log show --style csv`) reader with subsystem + process filters
- `duckdb_timeline_correlate`: **real DuckDB cross-source timeline join at scale** — accepts N named sources, joins on time proximity

### Added — Live mode infrastructure
- `dart_mcp.server`: **JSON-RPC 2.0 MCP stdio server** — launchable from Claude Code via `claude mcp add agentic-dart python3 -m dart_mcp.server`. The server exposes exactly the 13 registered tools and refuses anything else (verified by two adversarial tests in `test_extended_mcp.py`).

### Added — Evidence fixtures
- `examples/sample-evidence/logs/security_sample.evtx.csv` (6 events: 4624 logon, 4688 process create, 4698 scheduled task, 4663 file access)
- `examples/sample-evidence/macos/KnowledgeC.db` (real SQLite, 5 app-usage + Safari-history rows in ZOBJECT)
- `examples/sample-evidence/macos/fsevents_sample.csv` (4 events including LaunchAgent creation)
- `examples/sample-evidence/macos/unified_log_sample.csv` (4 entries including Gatekeeper disable)
- `examples/sample-evidence/memory/memdump.raw.info.json` (Volatility pslist + netscan aggregated)

### Added — Tests
- `tests/test_extended_mcp.py`: 8 new tests covering all 6 new functions + stdio server initialize + stdio server destructive-call refusal

### Test suite now totals 24 tests, all passing:
- audit_chain (3) + mcp_surface (3) + mcp_bypass (6) + agent_self_correction (1) + sigma_matcher (3) + extended_mcp (8)

### Roadmap updated
- All previous Windows / memory / macOS / DuckDB / live-mode items moved from Roadmap to Implemented
- Remaining roadmap focuses on native binary parsers (drop CSV sidecar dependencies) and 2nd-dataset measured accuracy runs


### Added
- Real implementations for `extract_mft_timeline`, `parse_prefetch`,
  `list_scheduled_tasks`, and `correlate_events`. No more scaffolds.
- `dart-audit` CLI with `verify`, `lookup`, `trace`, `summary`
  subcommands. Enables the "3 clicks from finding to raw evidence"
  claim to be executed, not just asserted.
- `scripts/measure_accuracy.py` — deterministic accuracy measurement
  producing the numbers committed to `docs/accuracy-report.md`.
- `tests/test_mcp_bypass.py` — six adversarial bypass scenarios
  (unregistered function, ../ traversal, absolute-path escape, NUL
  truncation, surface drift, write attempt).
- `_safe_resolve` hardened against absolute-path escape, symlink
  chains, and NUL-byte truncation.
- `--max-iterations` enforcement in the agent controller with
  forced-exit closeout report.
- `examples/case-studies/case-01-ipkvm-insider/` walkthrough for
  judges.
- `.github/workflows/ci.yml` — CI across Python 3.10–3.12.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`.
- Agent audit entries now carry `finding_ids`, which is what
  `dart-audit trace <finding_id>` relies on.

### Changed
- `docs/accuracy-report.md` rewritten to show REAL measured numbers
  (recall=1.0, FP rate=0.0, hallucination count=0 on sample case)
  instead of TBD placeholders.

## [0.1.0] — 2026-04-20

Initial MVP. See `git log` for the bootstrap commit history.
