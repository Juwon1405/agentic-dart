# Evidence and case studies

This directory holds the evidence trees and case studies used to exercise and
benchmark dart-mcp / dart-agent.

## Evidence

- **Canonical bundled evidence** — `case-studies/self-evaluation/case-01/evidence_root/`.
  Hand-curated at production volume on most surfaces (Windows Security EventLog
  ~11,530 lines, supply-chain, RDP brute-force, USB setupapi, memory triage).
  The two IOC-only logs (web access, unix auth) are enriched with deterministic
  benign noise to exercise needle-in-haystack recall. This is what
  `scripts/measure_accuracy.py` scores.
- **`sample-evidence/`** — a small (≤30 lines/file), fully IOC-loaded,
  byte-stable CI fixture used by the unit tests. Not a user-selectable evidence
  set.

There is no public `--variant` selector any more: the harness always scores the
one canonical evidence root.

## Case studies

`case-studies/<tier>/case-NN/` — self-contained investigations, each with a
`README.md`, a `truth.json`, and (for the bundled case) `evidence_root/`. The
`self-evaluation/` tier (case-01..08) is synthetic; the `external-evaluation/`
tier (case-01..03) is built on community-verified public datasets (NIST CFReDS,
Ali Hadi, Digital Corpora M57). Run a case with `python3 run_eval.py --case
<tier>/case-NN`; per-case scoring is done by `scripts/benchmark/score_cases.py`.

## Output

`out/` — sample run outputs (e.g. `find-evil-ref-01/`) kept for reference.
