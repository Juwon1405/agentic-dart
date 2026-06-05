# Reference evidence variant

The deterministic baseline evidence tree. Small (≤30 lines/file), fully
IOC-loaded, stable SHA-256 hashes — used as the CI regression baseline:
any change in detection numbers flags a code change rather than a data drift.

Pair this with `../sample-evidence-realistic/` (hand-curated production
volume + benign noise on the two IOC-only logs) to demonstrate that detection
behaviour is the same on both — see `../../docs/accuracy-report.md`.

## Layout

| Path | Contents |
|---|---|
| `disk/` | Windows artefacts: Security/Sysmon event JSON, Prefetch (`.pf` + parsed JSON), setupapi.dev.log, RDP/supply-chain event excerpts |
| `event-logs/` | `unified_events.jsonl` — EvtxECmd-shaped output |
| `linux/` | `journal.ndjson`, `auditd_sample.txt`, `bash_history` |
| `logs/` | `security_sample.evtx` + its CSV export (Windows Security samples) |
| `mac/` | `auth.log` (IOC-only — enriched in realistic), `fsevents.csv` |
| `macos/` | `unified_log_sample.csv`, `fsevents_sample.csv`, `KnowledgeC.db` |
| `memory/` | `memdump.raw` + `memdump.raw.info.json` (volatility-style triage metadata) |
| `sigma-rules/` | Sample Sigma detections used by the corr engine |
| `web/` | `access.log` (IOC-only — enriched in realistic), web shell drops |

## How it is used

- `python3 scripts/measure_accuracy.py` scores the case-01 reference findings
  (F-001, F-013) against this tree directly.
- `scripts/generate_realistic_evidence.py` reads the two IOC-only logs from
  here (`web/logs/access.log`, `mac/var/log/auth.log`) and writes them, with
  deterministic benign noise added, into `../sample-evidence-realistic/`.
- Per-case scoring (`scripts/benchmark/score_cases.py`) walks each
  `../case-studies/case-NN-*/ground-truth.json` and runs detection against
  this tree.
