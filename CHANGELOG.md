# Changelog

## [v0.5.2] — 2026-05-03 — Defensive runtime guards + regression coverage

Defensive fixes and regression coverage discovered during a full repo QA
sweep. Behavior unchanged for happy-path callers; failure modes now produce
structured errors instead of crashes or silent SQL execution.

### Fixed

- **`dart_audit`** — `AuditLogger.log()` and `AuditLogger.verify()` were
  inconsistent about `default=str` in `json.dumps()`. The output digest
  used it; the entry serialization and the verify-time canonical recompute
  did not. A single non-JSON-native value in `inputs` (e.g. `pathlib.Path`,
  `datetime`) would either crash log() with `TypeError` or, if it survived,
  desync the chain hash so verify() reported a false tamper. All three
  serialization sites now share `default=str`. Regression test:
  `tests/test_audit_chain.py::test_chain_handles_non_json_native_inputs`.

- **`dart_agent`** — `DeterministicAnalyst._report()` accessed
  `self._primary` / `self._alt` directly. With `--max-iterations` set
  small enough that `_phase_hypothesis()` never ran, those attributes
  were unset and the report path crashed with `AttributeError` — even
  though `_forced_exit_closeout()` already used `getattr(..., None)`
  defensively. Mirrored that pattern in `_report()` so the early-exit
  path is also crash-safe and emits a partial report.

- **`dart_mcp.correlate_timeline`** — the `rules` parameter is
  interpolated into a DuckDB JOIN ON clause. The previous filter only
  blocked `;` and `--`. That left `/* */` comments, `UNION SELECT`,
  `ATTACH`, `PRAGMA`, and DuckDB metafunctions like `read_csv_auto()`,
  `read_parquet()`, `INSTALL httpfs` — any of which is a structurally
  valid path from a prompt-injected agent rule to filesystem read or
  extension load. Replaced with a strict allow-list regex (column
  references + comparison operators + AND/OR/NOT + parens + arithmetic)
  AND a forbidden-keyword regex covering `union/insert/update/delete/
  drop/create/alter/attach/detach/copy/pragma/read_csv*/read_parquet/
  read_json/install/load/exec/execute/describe/explain`. Regression
  test: `tests/test_mcp_bypass.py::test_correlate_timeline_rejects_sql_injection_attempts`
  validates 8 representative payloads.

- **`dart_mcp.analyze_web_access_log`** and **`dart_mcp._v04_expansion.parse_bash_history`**
  — both functions had a parameter named `format` which shadowed Python's
  builtin `format()`. The schemas exposed it as `"format"` too. Renamed
  to `log_format` everywhere (function signature, JSON schema, body refs,
  output field). Behavior unchanged.

- **`tests/test_live_mcp.py`** — `test_live_mode_subprocess_dryrun` had
  `assert "35 tools visible" in result.stderr`, which started failing
  in v0.5 when 25 SIFT adapters joined the surface. Updated to 60.

### Added

- **`pytest.ini`** — pins `testpaths = tests` and excludes the
  `tests/_pending/` directory from auto-collection. Without this, a
  fresh clone hit `tests/_pending/test_extended_mcp.py` (which
  references Phase-2-only `parse_evtx`) and pytest reported a failure
  on the very first run despite the directory's README explicitly
  marking those tests as out-of-scope.

- **2 regression tests** wired into the standard pytest run:
  - `test_chain_handles_non_json_native_inputs` (audit-chain default=str)
  - `test_correlate_timeline_rejects_sql_injection_attempts` (rule guard)

### Verification

```text
$ python -m pytest tests/
============================== 31 passed in 7.08s ==============================
```

All previously-passing tests remain green; the 2 new regressions
verify the fixes do what the diff says they do.

---
## [v0.5.1] — 2026-05-03 — Evergreen visuals + full-surface QA pass

### Changed (visual identity now metric-free)

- **`agentic-dart-hero.png` regenerated.** Removed embedded numeric stats
  (35 / 11-12 / 20-20 / 0) which had silently gone stale after the v0.5
  SIFT adapter expansion. Replaced with permanent design-principle
  words at the same visual rhythm:

      Before                          After
      ─────────────────────────────  ──────────────────────────────────
      35    MCP forensic functions   READ-ONLY      MCP boundary
      11/12 MITRE ATT&CK tactics     ARCHITECTURAL  guardrails, not prompts
      20/20 tests passing            VERIFIABLE     SHA-256 audit chain
      0     destructive ops          ZERO           destructive ops on the wire

  Original archived to `docs/agentic-dart-hero-v0.4.png` for history.

- **README badges** rewritten to evergreen semantics:

      Before (drifted with each release)         After (permanent)
      ─────────────────────────────────────────  ───────────────────────
      MITRE ATT&CK-11/12 tactics                 MITRE ATT&CK aligned
      MCP tools-35 native + 25 SIFT              MCP read-only
      tests-20/20 passing                        audit SHA-256 chained

### Added

- **`scripts/regenerate_hero.py`** — reproducible PIL-based hero image
  generator. Reads the archived original as design-source, paints a
  vertical gradient over the stat-block region (sampled to match the
  original color palette exactly), then writes the four evergreen
  entries on top. Run again only if the design intent changes.

### Fixed (full-surface QA pass)

After the v0.5 SIFT adapter layer landed, several surfaces still cited
older counts. This pass synchronizes every surface to v0.5 reality:

- **README.md** — 4 stale references to `20-test suite` / `20 tests` /
  `All 20 pass` / `20/20 count` updated to `22-test suite` /
  `22 tests` / `All 22 pass` / `22/22 count`.

- **docs/live-mode.md** — `the 35 functions` → `the 60 functions on
  the typed MCP surface (35 native + 25 SIFT adapters)`.

- **docs/accuracy-report.md** — section heading `MCP surface — 35
  functions` → `MCP surface — 60 functions (35 native + 25 SIFT
  Workstation adapters)`.

- **docs/case-pth-timestomp.md** — both references to `dart-mcp, 35
  typed functions` and `enumerated to **35 typed forensic
  functions**` updated to include the SIFT adapter layer.

- **Wiki — 13 pages updated** (separate commit on .wiki repo):
  About-the-name, Architecture-deep-dive, Architecture-first-vs-prompt-first,
  Case-PtH-Timestomp, FAQ, Glossary, Home, Live-mode,
  MCP-function-catalog (page title), Operator-guide, Phase-1
  (added v0.5 timeline entry), Roadmap, Running-on-macOS,
  The-Memex-Bet, _Sidebar, dart-mcp.

### Operating principle going forward

  - Counts belong in README text, CHANGELOG, test output, and
    GitHub Actions badges — surfaces that update automatically or
    are expected to be edited per release.
  - Counts do NOT belong in PNG images, icon assets, or hard-coded
    visual identity — surfaces that are touched manually and drift
    silently.
  - Hero images encode IDENTITY (architecture-first, read-only,
    audit-chained, zero destructive ops), not METRICS.

### Verified

- All 22 test files pass on fresh clone
- `python3 -c 'from dart_mcp import list_tools; print(len(list_tools()))'`
  returns 60
- `bash examples/sift-adapter-demo.sh` exits 0
- `bash scripts/install.sh` (dry-run mode) reports 60 / 35 / 25
- `grep -nE "20/20|exposes 35|exactly 35"` returns no stale hits
  outside historic CHANGELOG entries
(docs(qa): document v0.5.1 QA hardening pass in CHANGELOG, refresh README test/package counts)

## [v0.5.0] — 2026-05-02 — SIFT Workstation tool adapter layer

### Added (Custom MCP Server pattern alignment for SANS FIND EVIL! 2026)

This release brings agentic-dart into explicit alignment with the
hackathon's **Pattern 2 — Custom MCP Server** architectural pattern by
adding 25 typed read-only adapters around the canonical SIFT Workstation
DFIR toolchain.

- **`dart_mcp/sift_adapters/`** — new subpackage containing wrappers around:
  - **Volatility 3 v2.27** (12 plugins) — windows.{pslist, pstree, psscan,
    cmdline, netscan, malfind, dlllist, svcscan, registry.printkey} +
    linux.{pslist, bash} + mac.bash
  - **Eric Zimmerman tools (8 wrappers)** — MFTECmd (parse + timestomp
    detection), EvtxECmd (parse + EID filter), PECmd (parse + run
    history), RECmd (ASEP batch + query-key), AmcacheParser
  - **YARA (2 wrappers)** — single-file + recursive directory scan
  - **Plaso (2 wrappers)** — log2timeline + psort

- **`dart_mcp/sift_adapters/_common.py`** — shared safety primitives:
  - `safe_evidence_input()` re-uses parent package's `_safe_resolve` for
    path-traversal blocking
  - `run_tool()` enforces subprocess timeout + captures stderr tail +
    SHA-256 hashes every output file
  - `_which()` resolves binaries via env-var override (`DART_VOLATILITY3_BIN`
    etc.) → PATH lookup → `SiftToolNotFoundError`
  - All errors are typed (`SiftToolFailedError`, `SiftToolNotFoundError`)
    so the agent loop can fall back to native pure-Python implementations

- **`tests/test_sift_adapters.py`** — new test file verifying:
  - All 25 adapters register via `@tool` decorator
  - No collision with native tool names
  - Every adapter has a well-formed JSON Schema
  - Path traversal is blocked at the SIFT-adapter layer (not just native)
  - Null bytes are blocked
  - Missing-binary error path is clean and actionable
  - Total tool count is exactly 60 (35 native + 25 SIFT)

### Architectural invariants preserved

- **Read-only boundary intact.** Adapters subprocess into binaries but
  do NOT expose `execute_shell`, `write_file`, or any path that would
  let an LLM jailbreak escape the read-only contract.
- **EVIDENCE_ROOT sandbox shared.** SIFT adapters use the same
  `_safe_resolve()` as native tools. The agent cannot reach `/etc`,
  `~/`, or anywhere outside `DART_EVIDENCE_ROOT` regardless of layer.
- **Audit chain compatible.** Every adapter returns SHA-256 of its
  input file in `metadata.{tool}_sha256` and SHA-256 of every output
  artifact in `metadata.csv_sha256` / `output_files`. dart_audit can
  chain these into the case ledger without modification.
- **Graceful degradation.** Adapters fail loudly with
  `SiftToolNotFoundError` listing the env-var override when binaries
  aren't on PATH. The agent loop is expected to catch this and fall
  back to the native pure-Python implementation (e.g.
  `extract_mft_timeline` if `sift_mftecmd_parse` is unavailable).

### Updated

- **README.md** — hero badge now shows `35 native + 25 SIFT` MCP tools.
  New `## SIFT Workstation alignment (Custom MCP Server pattern)`
  section explains positioning relative to the hackathon's four
  supported architectural patterns. Hero numbers updated from
  `35/20/20/0` to `60/22/22/0`.
- **`tests/test_mcp_surface.py`** — exact-set assertion expanded to
  include 25 new SIFT tool names.
- **`tests/test_mcp_bypass.py`** — POSITIVE surface set expanded; the
  NEGATIVE surface (forbidden function names) is unchanged because
  no destructive primitive was added.
- **`tests/test_live_mcp.py`** — wire-surface expectation updated.

### Verified

- All 22 test files pass (20 native + 2 new SIFT-adapter tests).
- `python3 -c "from dart_mcp import list_tools; print(len(list_tools()))"`
  returns 60.
- No new destructive primitives. NEGATIVE surface (`execute_shell`,
  `write_file`, `mount`, etc.) remains unbreached.
- Demo run still completes in <700ms on fresh clone (when SIFT
  binaries are absent — the adapters never get called and demo uses
  native tools).

## [Playbook v3.1] — 2026-05-01 — Yamato Security external references

> **Note on naming.** "v3.1" is a CHANGELOG-only patch label for tracking purposes. There is **no separate `senior-analyst-v3.1.yaml` file** — the changes below were applied directly to `senior-analyst-v3.yaml`, raising its line count from the v3.0 baseline to its current 1182 lines. The shipping artifact is and remains `senior-analyst-v3.yaml`.

### Added (external citations only — NO code or rules imported)

- `related_tools_for_inspiration` (NEW reference category):
  - **Hayabusa** (Yamato Security, Tokyo) — Sigma-based fast EVTX
    timeline generator. Cited as third-party tool we credit as
    inspiration; we did NOT import, bundle, fork, or wrap any of its
    code or rules. Reinforces our case for treating detection corpus
    as a first-class artifact.
  - **EnableWindowsLogSettings** (Yamato Security, Tokyo) — audit
    policy baseline yielding ~75% Sigma rule coverage on Windows
    hosts. Cited as external field calibration reference for ADS
    `technical_context` sections targeting EVTX channels.

- `vendor_research`:
  - **Zach Mathis** (Yamato Security founder, Tokyo) added with
    explicit external-community attribution: "external community
    reference (not a contributor to this project)" and "Agentic-DART
    is independently developed and has no affiliation with Yamato
    Security." Recognized as a voice in Tokyo / Japanese DFIR
    community on Windows event log analysis at scale.

### Why these citations matter

Tokyo-based DFIR community awareness is a credibility signal for
SANS judges familiar with the Japanese security ecosystem. Yamato
Security ships some of the most production-grade open-source EVTX
tooling available. Crediting them as inspiration (without conflating
ownership) is the correct way to acknowledge prior art.

### What we explicitly do NOT do

- We do NOT import any Hayabusa Rust code
- We do NOT bundle the hayabusa-rules Sigma corpus
- We do NOT claim Yamato Security membership or partnership
- We do NOT use the Yamato logo, branding, or naming patterns

The architectural-first guarantees of Agentic-DART are independent of
any third-party detection tool we cite as inspiration.

### Verified

- 20/20 tests still passing
- Demo run still completes in ~685ms
- Total references: 42 (was 39 in v3.0)
- 2 entries in new `related_tools_for_inspiration` category
- 10 entries in `vendor_research` (was 9, +1: Zach Mathis)

## [Playbook v3] — 2026-05-01 — Industrialization release (data scaffold)

### Scope of this release

> **Honest framing.** v3 adds **data scaffolds** for four mature-SOC frameworks
> on top of v2's runtime methodology. The frameworks are **encoded as
> structured YAML** (so they're inspectable, forkable, and citable), but
> their **runtime activation** in `dart_agent` / `dart_corr` is a
> post-SANS work item tracked in issue #44. v2's 10-phase sequence,
> next_call_decisions, contradiction_triggers, and stop_conditions
> remain the runtime path in v3. Anyone reading the v3 yaml will find
> `ads_template`, `magma_ucf`, `hunt_cycle`, and `hunting_maturity_model`
> as data; anyone reading `dart_agent/__init__.py` will find that those
> keys are not yet referenced from the iteration controller. This was
> deliberate — see "Why deferred" below.

### Added

- **`dart_playbook/senior-analyst-v3.yaml`** (1182 lines) —
  industrialization release. Builds on v2's 10-phase Mandiant + Bianco
  + Diamond methodology by adding four framework blocks that mature
  SOCs use to ship detection at scale:

  1. **Palantir ADS Framework** — encoded as `ads_template` data
     structure. Every detection is *intended* to carry a 9-section
     documentation contract (goal, categorization, strategy abstract,
     technical context, blind spots, false positives, validation,
     priority, response). Lint mode field present (`permissive` →
     `warn` → `strict`); the lint pass itself is post-SANS work.

  2. **MaGMa Use Case Framework** (FI-ISAC NL, Rob van Os) — encoded
     as `magma_ucf` data structure. Three-tier traceability:
       L1 business drivers (4 entries): protect data integrity,
                                         detect ransomware before recovery
                                         denial, etc.
       L2 attack patterns (8 entries, MITRE-mapped): AP-001 .. AP-008
       L3 detection coverage: MCP function mapping per L2.
     CMMI 5-level maturity scale documented; the v3 yaml self-declares
     L3 Defined as the current state. Runtime CMMI scoring is post-SANS.

  3. **TaHiTI threat hunt cycle** (Rob van Os et al.) — encoded as
     `hunt_cycle` data structure with H1 Initiate → H2 Hunt →
     H3 Finalize phases and a designed trigger condition
     (`confidence < 0.6 AND iter >= 8`). Runtime entry into hunt mode
     from the agent loop is post-SANS work (issue #44).

  4. **Bianco Hunting Maturity Model (HMM 0–4)** — encoded as
     `hunting_maturity_model` data structure. Levels 0–4 documented
     with what each implies. v3 yaml self-declares HMM3 Innovative
     (analyst-formed hypotheses) as the target. Per-run self-classification
     by the agent is post-SANS work.

### Why deferred

Activating these frameworks at runtime would shift the baseline measured
by `scripts/measure_accuracy.py` (more findings → either spurious
"improvement" or new false positives that read as regressions). The
hackathon submission ships with a stable, reproducible baseline.
Post-SANS, all four runtime activations land together with a single
re-baseline. Tracked at issue #44.

### Reference corpus expansion

- 39 published references (was 25 in v2 — +14 new):
  - **industrialization_frameworks_v3** (15 NEW) — Palantir ADS, MaGMa,
    TaHiTI, SOC-CMM, MITRE 11 Strategies, awesome-soc (cyb3rxp),
    awesome-incident-response (meirwah), awesome-threat-detection
    (0x4D31), ThreatHunter-Playbook (OTRF), Florian Roth Detection
    Engineering Cheat Sheet, *Crafting the InfoSec Playbook* (Bollinger
    et al.), Atomic Red Team, Sigma schema
  - primary_methodology (6 carried)
  - case_studies_2025 (4 carried)
  - vendor_research (9, +1 — Roberto Rodriguez OTRF)
  - standards (5 carried)

### Backward compatibility

- v2 and v1 retained. v3 is the new default.
- All architectural guarantees preserved (read-only MCP boundary, audit
  chain, contradiction enforcement, path safety).
- 35 MCP functions unchanged. v3 changes the methodology *around* the
  surface, not the surface itself.

### Wiki

- `dart-playbook` page updated to feature v3 as default.
- Roadmap updated with Playbook v3 entry in Done section.

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
