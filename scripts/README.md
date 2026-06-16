# Scripts

Operational scripts for accuracy measurement, evidence enrichment, benchmark
runs, installation, and asset regeneration. None of these are part of the
runtime package surface — they are repository tooling.

## Accuracy measurement

- **`scripts/eval/demo.py`** — scores the case-01 findings (F-001 web shell,
  F-013 USB setupapi) against the **canonical bundled evidence**
  (`examples/case-studies/self-evaluation/case-01/evidence_root/`). There is no
  `--variant` selector any more. Before scoring it re-derives the two IOC-only
  logs (web access, unix auth) with deterministic benign noise by invoking
  `generate_realistic_evidence.py`; output is byte-identical across runs, so the
  working tree stays clean.
- **`healthcheck.py`** — API-free readiness check (imports, dependency versions,
  MCP tool surface, adapter `--help`, tiered case layout, `analyze` fail-fast).

## Evidence enrichment

- **`generate_realistic_evidence.py`** — enriches ONLY the two IOC-only logs in
  the canonical bundled evidence root (web access 27 → 1027, unix auth
  17 → 517) in-place with deterministic benign noise (seed `20260508`). It
  does **not** touch any other file — security EventLog, supply-chain, RDP
  brute, USB setupapi, memory triage, etc. are all committed hand-curated. The
  script intentionally avoids `rmtree`/`copytree` over the canonical evidence
  tree, since that would destroy hand-curated evidence.

## Installation / setup

- **`install.sh`** — OS-aware (`--os auto|ubuntu|centos|macos`), installs into the active interpreter
  installer; installs the packages editable, clones+installs the collector
  adapter, and optionally stages SIFT (`--install-sift`, via `cast`) and the
  Eric Zimmerman Tools (`--install-eztools`, .NET 9). See `install.sh --help`.

## Benchmarking

- **`benchmark/`** — external-tier dataset orchestration (`download.py`,
  `scripts/eval/score.py`, `validate_ground_truth.py`, and the lower-level
  `scripts/eval/demo.py`). The primary user-facing runner is the repo-root
  `analyze.py`. See `benchmark/README.md`.

## Assets

- **`regenerate_hero.py`** — regenerates the project hero image
  (`agentic-dart-hero.png`) referenced from `README.md` and the profile
  README. Asset regeneration only — not a runtime path.
