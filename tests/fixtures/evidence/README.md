# CI fixture evidence

A small (≤30 lines/file), fully IOC-loaded, byte-stable evidence tree used as a
**CI fixture by the unit tests** (`tests/`). It deliberately carries artifacts
for several scenarios at once so a single `DART_EVIDENCE_ROOT` exercises every
tool's parsing and detection paths in one place.

It is **not** a user-selectable evidence set and is **not** what the accuracy
harness scores. Each evaluation case owns its own self-contained tree at
`examples/case-studies/self-evaluation/case-NN/evidence_root/`; this fixture
exists purely so the test suite has a stable, all-tools-in-one-tree target.

Stable hashes here mean any change in test detection numbers flags a code
change rather than a data drift.

## Layout

| Path | Contents |
|---|---|
| `disk/` | Windows artefacts: Security/Sysmon event JSON, Prefetch (`.pf` + parsed JSON), setupapi.dev.log, RDP/supply-chain event excerpts |
| `event-logs/` | `unified_events.jsonl` — EvtxECmd-shaped output |
| `linux/` | `journal.ndjson`, `auditd_sample.txt`, `bash_history` |
| `logs/` | `security_sample.evtx` + its CSV export (Windows Security samples) |
| `mac/` | `auth.log` (IOC-only — enriched in the canonical tree), `fsevents.csv` |
| `macos/` | `unified_log_sample.csv`, `fsevents_sample.csv`, `KnowledgeC.db` |
| `memory/` | `memdump.raw` + `memdump.raw.info.json` (volatility-style triage metadata) |
| `sigma-rules/` | Sample Sigma detections used by the corr engine |
| `web/` | `access.log` (IOC-only — enriched in the canonical tree), web shell drops |

## How it is used

- The unit tests point `DART_EVIDENCE_ROOT` at this tree for byte-stable
  regression assertions.
- `scripts/generate_realistic_evidence.py` reads the two IOC-only logs from
  here (`web/logs/access.log`, `mac/var/log/auth.log`) and writes them, with
  deterministic benign noise added, into the canonical bundled evidence root
  (`../case-studies/self-evaluation/case-01/evidence_root/`).
- `python3 scripts/measure_accuracy.py` scores the canonical bundled
  evidence root (not this fixture) for the case-01 findings (F-001, F-013).
- Per-case scoring (`scripts/benchmark/score_cases.py`) walks each
  `../case-studies/<tier>/case-NN/truth.json`.
