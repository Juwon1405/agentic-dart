# Evidence and case studies

This directory holds the evidence trees and case studies used to exercise and
benchmark dart-mcp / dart-agent.

## Evidence variants

- **`sample-evidence/`** — the deterministic *reference* set. Small
  (≤30 lines/file), fully IOC-loaded, stable SHA-256 hashes. Used as the CI
  regression baseline: any change in detection numbers flags a code change.
- **`sample-evidence-realistic/`** — the *realistic* set. Hand-curated at
  production volume on most surfaces (Windows Security EventLog ~11,530 lines,
  supply-chain, RDP brute-force, USB setupapi, memory triage). The two
  IOC-only logs (web access, unix auth) are enriched with deterministic benign
  noise to exercise needle-in-haystack recall. See its own README for details.

Both variants are scored against the same ground truth by
`scripts/measure_accuracy.py` (`--variant reference` | `--variant realistic`).

## Case studies

`case-studies/case-NN-*/` — eleven end-to-end investigations, each with a
`README.md` and a `ground-truth.json`. Layer 1 (cases 01–07, 11) is synthetic;
Layer 2 (cases 08–10) is built on community-verified public datasets (CFReDS,
Ali Hadi, M57). Per-case scoring is done by
`scripts/benchmark/score_cases.py`.

## Output

`out/` — sample run outputs (e.g. `find-evil-ref-01/`) kept for reference.
