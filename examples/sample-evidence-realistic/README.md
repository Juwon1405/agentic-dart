# Realistic evidence variant

This tree carries the same ground-truth IOCs as `../sample-evidence/`, but at
**hand-curated production volume** on most surfaces, so detection is exercised
against a realistic signal-to-noise ratio rather than toy single-line inputs.

## How it is built

Most files are **committed hand-curated** at production volume and are *not*
regenerated:

| Surface | Approx volume |
|---|---|
| Windows Security EventLog (`disk/security-events.json`) | ~11,530 lines |
| Supply-chain events (`disk/supplychain-security-events.json`) | 427 lines |
| RDP brute-force (`disk/rdp-brute-events.json`) | 452 lines |
| USB setupapi (`disk/Windows/INF/setupapi.dev.log`) | 107 lines |
| Network / memory / Prefetch / MFT / journald / ... | production-shaped |

Two surfaces ship **IOC-only** and are enriched in-place with deterministic
benign noise by `../../scripts/generate_realistic_evidence.py` (seed
`20260508`):

| Log | IOC | + benign | ratio |
|---|---|---|---|
| `web/logs/access.log` | 27 | 1000 | ~1:37 |
| `mac/var/log/auth.log` | 17 | 500 | ~1:29 |

The generator touches **only those two logs**; every other file is left
byte-for-byte untouched, and its output is byte-identical across runs (so the
working tree stays clean). `measure_accuracy.py --variant realistic`
re-derives the two logs before scoring.

## What this demonstrates

Recall / FPR / hallucination numbers hold on the case-01 reference findings
(F-001, F-013) across both this variant and the reference set — evidence that
the detection functions discriminate IOC from benign at ~1:30 noise, not just
on IOC-dense toy inputs. Full methodology and limitations:
`../../docs/accuracy-report.md`.
