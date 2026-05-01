# Changelog

## [Playbook v2] — 2026-04-30 — Senior-analyst methodology

### Added

- **`dart_playbook/senior-analyst-v2.yaml`** (845 lines, 10 phases) —
  comprehensive senior-analyst playbook synthesizing Mandiant M-Trends
  2026 + Targeted Attack Lifecycle, SANS PICERL, Lockheed Cyber Kill
  Chain, David Bianco's Pyramid of Pain + Hunting Maturity Model,
  Diamond Model, MITRE ATT&CK v16, F3EAD framework, NIST SP 800-61/86/150,
  The DFIR Report 2024-2026 case studies (BlackSuit, Akira, Fog, Lynx,
  BlueSky), CISA #StopRansomware advisories, and field practice from
  Sean Metcalf, Sarah Edwards, Patrick Wardle, Hal Pomeranz, Eric
  Zimmerman, Andrew Case, Florian Roth, JPCERT/CC.

  v2 covers 10 case classes (was 3 in v1):
    - insider_threat_unauthorized_access
    - remote_hands_ip_kvm
    - living_off_the_land_execution
    - ransomware_response_recovery_denial      (M-Trends 2026 #1 trend)
    - identity_centric_intrusion
    - vishing_initial_access                   (M-Trends 2026 #2 vector)
    - exploit_initial_access                   (M-Trends 2026 #1 vector)
    - third_party_compromise                   (DBIR 2025 - 30%)
    - cloud_hybrid_lateral_movement
    - division_of_labour_handoff               (M-Trends 2026 - 22sec)

  Includes a `posture` block encoding M-Trends 2026 priors (14-day
  median dwell time, 22-second hand-off, 32%/11%/10% initial access
  vector probabilities), 25 `next_call_decisions` rules, 7
  `contradiction_triggers` (timestomp-predates-alert,
  vpn-kvm-overlap-violation, process-in-memory-no-evtx-creation,
  admin-privilege-no-escalation-path, ssh-auth-no-keys-no-password,
  launchd-user-writable-runatload, ransomware-without-recovery-denial),
  and 5 `stop_conditions` including the architecturally important
  `declare_complex_case_request_human` for hypothesis-revision-count >=5.

  v2 is the recommended default. v1 is kept for backward compatibility
  and short-form demos.

### Changed

- **`dart_playbook/README.md`** — comprehensive rewrite documenting
  v2 methodology lineage, the 10 phases, schema, and the six
  senior-analyst principles encoded in `operator_notes`.

### Wiki

- `dart-playbook.md` page rewritten to reflect v2 as default, with
  full methodology citations and the case-class table.

## [v0.4.2] — 2026-04-30 — Senior-analyst playbook v2

### Added

- **`dart_playbook/senior-analyst-v2.yaml`** — comprehensive playbook
  synthesizing frontline DFIR methodology (845 lines, 10 phases, 7
  contradiction triggers, 25 grounded references). Sources:
  Mandiant M-Trends 2026, Targeted Attack Lifecycle, SANS PICERL,
  Cyber Kill Chain, MITRE ATT&CK v16, David Bianco's Pyramid of
  Pain & Hunting Maturity Model, Diamond Model, F3EAD; The DFIR
  Report 2024-2026 case studies (BlackSuit, Akira AA24-109A,
  Fog, Lynx, BlueSky); field practice from Sean Metcalf, Sarah
  Edwards, Patrick Wardle, Hal Pomeranz, Eric Zimmerman, Andrew
  Case, Florian Roth, JPCERT/CC.

  v2 covers 10 case classes vs v1's 3: adds ransomware-recovery-
  denial (M-Trends 2026 #1 trend), vishing (11% initial vector),
  exploit (32% initial vector), third-party compromise (DBIR 2025
  30%), cloud hybrid pivot, identity-centric intrusion, division-
  of-labour 22-second handoff.

  v2 is the recommended playbook for any new case in 2026; v1 is
  retained as a compact reference.

### Changed

- `dart_playbook/README.md` — documents both v1 and v2, links to
  full methodology lineage.

### Notes

- `dart-agent` deterministic mode still routes through hardcoded
  Python phases (Phase 1 design). Phase 2 will auto-map v2 YAML
  sequence into the agent loop. v2 today serves as the canonical
  *specification* of senior-analyst behavior.

## [v0.4.1] — 2026-04-30 — Audit chain race fix + path safety hardening

### Fixed (HIGH severity — discovered by post-v0.4 1000+-call QA pass)

- **`AuditLogger.log()` race condition**: concurrent callers could read
  the same `_prev_hash`, compute different `entry_hash`es, and append
  both — chain validation then failed because the second entry's
  `prev_hash` no longer matched its file-position predecessor's
  `entry_hash`. This breaks the architectural guarantee that the audit
  chain is tamper-evident under any access pattern.

  Fix: per-instance `threading.Lock()` around the prev_hash read /
  entry_hash compute / file append / prev_hash update critical section.
  Verified by `test_concurrent_writes_preserve_chain` (50 threads ×
  20 calls = 1000-entry chain still validates).

- **`_safe_resolve()` graceful errors**: passing `None`, an int, a list,
  or a 2000-char path raised unwrapped exceptions (`AttributeError`,
  `OSError [Errno 36] File name too long`) instead of the architectural
  `PathTraversalAttempt`. Fix: wrap `Path.resolve()` in try/except,
  re-raise as `PathTraversalAttempt`. New 1024-char path-length cap.

### Added

- `tests/test_concurrency_and_edge_cases.py` (3 tests):
  - `test_concurrent_writes_preserve_chain`
  - `test_safe_resolve_rejects_too_long_paths`
  - `test_safe_resolve_rejects_non_string_inputs`

  Test count: 17 → **20**.

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
