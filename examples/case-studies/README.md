# Case studies

Eleven end-to-end DFIR investigations used to exercise the agent loop and
benchmark per-case detection. Each `case-NN-*/` directory ships a `README.md`
(incident narrative + reasoning hooks) and a `ground-truth.json` (expected
findings, IOCs, ATT&CK mapping). Per-case scoring lives in
`../../scripts/benchmark/score_cases.py`.

## Layer 1 — synthetic (8 cases)

Curated incidents on the bundled `../sample-evidence/` and
`../sample-evidence-realistic/` trees. Used as the deterministic regression
baseline.

| Case | Title |
|---|---|
| 01 | IP-KVM insider |
| 02 | LotL PowerShell |
| 03 | macOS remote admin |
| 04 | Phishing to exfil |
| 05 | Authentication / lateral movement |
| 06 | Web attack to RDP pivot |
| 07 | Ransomware full chain |
| 11 | Supply-chain + AD zero-day |

## Layer 2 — external community datasets (3 cases)

Built on community-verified public datasets. Downloaded on demand by
`../../scripts/benchmark/run_all.py --download`; not bundled in the repo to
keep the clone size down and to defer dataset licensing to the original
publishers.

| Case | Title | Dataset |
|---|---|---|
| 08 | CFReDS hacking case | NIST CFReDS |
| 09 | Hadi challenge 1 | Ali Hadi DFIR challenges |
| 10 | M57 Jean | M57 Patents Corpora |

## Scoring

Per-case results are produced by `score_cases.py` against each
`ground-truth.json`. The headline reference / realistic numbers in
`../../docs/accuracy-report.md` (recall 1.000 on F-001, F-013) are limited to
case-01; cross-case scoring is what `score_cases.py` provides.
