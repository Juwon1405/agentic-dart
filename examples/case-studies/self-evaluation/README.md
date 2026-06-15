# Self-evaluation cases (synthetic)

Eight authored DFIR scenarios. **Only `case-01` ships an `evidence_root/`** —
and that one tree is deliberately shared by the whole tier. If you `ls` here and
wonder why `case-02`…`case-08` look "empty", this is by design, not a bug.

## Why only case-01 has evidence files

`case-01/evidence_root/` is not just "the IP-KVM case's evidence." It is the
single **production-volume realistic evidence tree** the whole self-evaluation
tier is built around — one large, noisy host image with *every* scenario's
artifacts seeded into it among benign noise (the classic needle-in-haystack).
Each scenario's findings (in its `truth.json`) point at real files inside this
shared tree:

| Scenario | Where its artifacts live under `case-01/evidence_root/` |
|---|---|
| case-01 — IP-KVM insider | `disk/Windows/` (setupapi.dev.log, Tasks/RemoteHandsSync, Prefetch/REMOTE-ADMIN.EXE) |
| case-02 — LOTL PowerShell | `disk/Windows/`, `disk/events.json`, `disk/processes.csv` |
| case-03 — macOS remote-admin | `macos/com.evil.persistence.plist`, `mac/` (fsevents, KnowledgeC, unified log) |
| case-04 — phishing → exfil | `disk/Users/analyst/Downloads/` (MOTW `.exe`, Zone.Identifier) |
| case-05 — auth + lateral | `disk/processes.csv`, `disk/security-events.json`, `linux/auth.log` |
| case-06 — web + RDP brute | `web/logs/`, `web/var/www/html/uploads/*.php`, `disk/rdp-brute-events.json` |
| case-07 — ransomware chain | `disk/creds-processes.csv`, `discovery-processes.csv`, `log-clearing-events.json`, `ransomware-processes.csv` |
| case-08 — supply-chain → AD CS | `disk/supplychain-network.json`, `supplychain-processes.csv`, `supplychain-security-events.json` |

So `case-02`…`case-08` carry only `README.md` (scenario narrative) and
`truth.json` (expected findings + the exact `host_path` of each artifact). They
are **scenario specifications against the shared tree**, not separate evidence
copies — which keeps the layout realistic (one noisy disk, many attacks) and
avoids duplicating the tree eight times.

`case-01` is the measured regression baseline
(`scripts/eval/demo.py` → recall 1.0, hallucination 0). The full case
table is in [`../README.md`](../README.md).

```bash
python3 analyze.py --case self-evaluation/case-01   # bundled, deterministic, no key
python3 analyze.py --list                           # shows: bundled / spec-only / download
```
