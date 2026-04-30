# Changelog

All notable changes to Agentic-DART are recorded here.

## [Unreleased] — 2026-04-30

### Added — v0.4 Linux + macOS expansion (4 new functions, 31 → 35)

The original 31-function surface was Windows-heavy. v0.4 adds typed
functions for the most-asked-for Linux and macOS artifacts:

- `parse_auditd_log` — Linux kernel-level syscall audit (`/var/log/audit/audit.log`).
  Filters by syscall, key, executable, time window. Reference:
  Red Hat RHEL Security Guide ch.7, SANS FOR577.

- `parse_systemd_journal` — Unified system log
  (`journalctl -o json --no-pager > journal.ndjson`). Filter by unit,
  priority, message. Reference: systemd.journal-fields(7),
  freedesktop.org Journal Export Format.

- `parse_bash_history` — bash/zsh history with attacker-pattern
  detection (15 named patterns, each mapped to a MITRE technique).
  Detects encoded payloads, reverse shells, SSH key insertion,
  history clearing, SUID escalation, kernel-module load.
  Reference: SANS FOR577, MITRE ATT&CK T1059.004 / T1070.003 /
  T1098.004 / T1105.

- `parse_launchd_plist` — macOS LaunchAgent / LaunchDaemon plist
  parser with persistence-indicator scoring. Flags `RunAtLoad=true`
  in user-writable paths, executables in `/tmp/`, aggressive
  KeepAlive. Reference: Apple Developer Daemons & Services
  Programming Guide, Patrick Wardle "The Art of Mac Malware",
  MITRE ATT&CK T1543.001 / T1543.004.

### Added — wiki MCP function catalog

New wiki page [MCP-function-catalog](https://github.com/Juwon1405/agentic-dart/wiki/MCP-function-catalog)
enumerates all 35 functions with: primary OS / artifact, MITRE
mapping, and published reference (SANS course / paper / vendor doc /
open-source tool) so reviewers can audit where the detection logic
comes from.

### Added — Platform support matrix in README

The README's Platform support section now has explicit matrices for:
- Supported analysis targets (Windows / macOS / Linux versions)
- 35 functions grouped by primary platform
- MITRE ATT&CK 11 / 12 tactic coverage with per-tactic function list

### Verification

- 17 / 17 tests pass on a clean clone (test set unchanged; the count
  refers to assertion *count*, not function count)
- Each new function call validated against synthetic samples in
  `examples/sample-evidence/linux/` and `examples/sample-evidence/macos/`
- `parse_bash_history` matches 3 attacker patterns in a 5-line
  sample (T1098.004, T1105, T1070.003)
- `parse_launchd_plist` flags 2 indicators (T1574, T1543) in a
  RunAtLoad=true / `/tmp/` path / KeepAlive=true sample
- 1000-attempt fuzz test against the 35-function surface still
  blocks 100% of unregistered destructive calls

## [0.2.0] — 2026-04-20 (Breadth Expansion)

### Added — new MCP functions in the 0.2 expansion

Live on the 31-tool surface as of v0.3 (post-rebrand):

- `analyze_event_logs`: Windows event log analysis with event_id + time window filters (successor to the original `parse_evtx` scaffolding)
- `parse_knowledgec`: macOS KnowledgeC.db SQLite reader with Cocoa-epoch → ISO 8601 decoding (real SQLite connection, not a stub)
- `parse_fsevents`: macOS FSEvents CSV reader with flag substring filter
- `parse_unified_log`: macOS UnifiedLog (`log show --style csv`) reader with subsystem + process filters
- `correlate_timeline`: cross-source timeline join with time-proximity windowing

Scaffolded but not on the live surface (Phase 2):
- `volatility_summary`, `duckdb_timeline_correlate`, `match_sigma_rules`, `parse_evtx` (raw EVTX) —
  tests under `tests/_pending/`, will land when the corresponding
  parsers ship in Phase 2

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
