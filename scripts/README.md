# Scripts

Operational scripts for accuracy measurement, installation, and asset
regeneration. None of these are part of the
runtime package surface — they are repository tooling.

## Accuracy measurement

- **`scripts/eval/demo.py`** — scores the case-01 findings (F-001 web shell,
  F-013 USB setupapi) against the **canonical bundled evidence**
  (`examples/case-studies/self-evaluation/case-01/evidence_root/`). Output is byte-identical
  across runs, so the working tree stays clean.
- **`healthcheck.py`** — API-free readiness check (imports, dependency versions,
  MCP tool surface, adapter `--help`, tiered case layout, `analyze` fail-fast).

## Installation / setup

- **`install.sh`** — OS-aware (`--os auto|ubuntu|centos|macos`), installs into the active interpreter
  installer; installs the packages editable, clones+installs the collector
  adapter, and optionally stages SIFT (`--install-sift`, via `cast`) and the
  Eric Zimmerman Tools (`--install-eztools`, .NET 9). See `install.sh --help`.

## Evaluation suite

- **`eval/`** — `self.py` / `external.py` (live measurement on the bundled and
  public datasets), `download.py` (dataset fetcher), `score.py`,
  `validate_ground_truth.py` (the CI / pre-commit gate for `truth.json`) and the
  lower-level `demo.py`. The primary user-facing runner is the repo-root
  `analyze.py`. See `scripts/eval/README.md`.

## Assets

- **`regenerate_hero.py`** — draws the hero (`agentic-dfir-hero.png`), the
  social-preview thumbnail (`agentic-dfir-thumbnail.png`) and the wiki banner
  (`docs/wiki-banner.png`) from scratch, deterministically. Asset regeneration
  only — not a runtime path.
