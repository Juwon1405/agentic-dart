# Scripts

Operational scripts for accuracy measurement, evidence enrichment, benchmark
runs, installation, and asset regeneration. None of these are part of the
runtime package surface — they are repository tooling.

## Accuracy measurement

- **`measure_accuracy.py`** — scores case-01 reference findings (F-001 web
  shell, F-013 USB setupapi) against the bundled evidence. Two variants:
  - `python3 scripts/measure_accuracy.py` → `examples/sample-evidence/`
    (reference, deterministic baseline).
  - `python3 scripts/measure_accuracy.py --variant realistic` →
    `examples/sample-evidence-realistic/`. Before scoring, this re-derives
    the two IOC-only logs (web access, unix auth) with deterministic benign
    noise by invoking `generate_realistic_evidence.py`. Output is
    byte-identical across runs, so the working tree stays clean.
- **`measure_cfreds.py`** — Layer 2 / case-08 (CFReDS) standalone scorer.

## Evidence enrichment

- **`generate_realistic_evidence.py`** — enriches ONLY the two IOC-only logs
  in `examples/sample-evidence-realistic/` (web access 27 → 1027, unix auth
  17 → 517) in-place with deterministic benign noise (seed `20260508`). It
  does **not** touch any other file in the realistic tree — security
  EventLog, supply-chain, RDP brute, USB setupapi, memory triage, etc. are
  all committed hand-curated. The script intentionally avoids
  `rmtree`/`copytree` of the reference set over the realistic tree, since
  that destroys hand-curated evidence with no reference counterpart.

## Installation / setup

- **`install.sh`** — one-shot installer for the five packages
  (`dart_audit`, `dart_mcp`, `dart_agent`, `dart_corr`, `dart_playbook`) in
  editable mode plus a pinned `pytest` for the test suite.

## Benchmarking

- **`benchmark/`** — Layer 2 case orchestration (`run_all.py`,
  `download.py`, `score_cases.py`). See `benchmark/README.md` for the
  variant model and CI integration.

## Assets

- **`regenerate_hero.py`** — regenerates the project hero image
  (`agentic-dart-hero.png`) referenced from `README.md` and the profile
  README. Asset regeneration only — not a runtime path.
