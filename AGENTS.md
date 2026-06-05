# AGENTS.md — Agent Guide for Agentic-DART

> Concise operational guide for Codex and other coding agents. For the full
> rationale see [CLAUDE.md](./CLAUDE.md). When the two overlap, both are
> authoritative; CLAUDE.md carries the longer explanation.

## Project summary

Autonomous DFIR agent. A senior-analyst loop calls **72 typed, read-only** MCP
tools (47 native + 25 SIFT adapters), logs every call in a SHA-256-chained
audit, and emits a findings report. Python 3.10+, MIT, SANS FIND EVIL! 2026.

## Repository map

- `dart_audit/` — SHA-256-chained JSONL audit logger (Python package)
- `dart_mcp/` — custom MCP server, typed read-only forensic functions (Python package)
- `dart_agent/` — iteration controller, deterministic + live loops, auth (Python package)
- `dart_corr/` — DuckDB cross-artifact correlation engine (Python package)
- `dart_playbook/` — senior-analyst YAML playbooks; **data, no `pyproject.toml`, loaded by path**
- `examples/` — `case-studies/`, `sample-evidence/`, `sample-evidence-realistic/`, demos
- `scripts/` — `install.sh`, `benchmark/`, `measure_accuracy.py`, `generate_realistic_evidence.py`
- `tests/` — 102 tests; `dart_corr/tests/` — 14 tests

## Preferred commands

```bash
export PYTHONPATH=dart_audit/src:dart_mcp/src:dart_agent/src:dart_corr/src

# Full suite (expect: 116 passed)
python3 -m pytest tests/ dart_corr/tests/ -q

# Focused
python3 tests/test_mcp_surface.py        # tool-surface drift
python3 tests/test_mcp_bypass.py         # adversarial / read-only guard
python3 -m pytest dart_corr/tests/ -q    # correlation engine

# Offline demo (deterministic, no API key)
bash examples/demo-run.sh

# Accuracy (deterministic; expect recall=1.0 / hallucination=0)
python3 scripts/measure_accuracy.py
```

CI mirrors these (`.github/workflows/ci.yml`) and runs **deterministic only** —
no network, no API key. `dart_corr/tests/` runs as its own pytest step.

## Change rules

- **Never** add a function that writes to the evidence tree, lacks an MCP
  schema, or provides a shell/eval escape. **Never** move a guardrail from
  architecture into the prompt.
- Every new MCP function: read-only, `_safe_resolve` on path args, Pydantic/JSON
  schema, and a bypass test. Update the asserted set in
  `tests/test_mcp_surface.py`.
- New playbook = YAML under `dart_playbook/`, no Python change.
- Preserve sequential tool execution in the deterministic loop — parallelism
  would reorder the audit chain and break byte-stable determinism.
- Measure counts live before writing them (tools 72 / tests 116 / cases 11 /
  findings 99). Sweep all surfaces (README, docs, CHANGELOG, folder READMEs,
  wiki) so no figure goes stale in one place.

## Trading & data safety — N/A here, but the analogue holds

This repo never trades or writes. The equivalent rule: **never** commit real
evidence, credentials, tokens, internal hostnames, company names, colleague
names, or internal codenames. Intentional and allowed: the demo persona
`yushin@siftworkstation`, `/home/yushin/...`, and the author handle
`Juwon1405`.

## Before finishing

1. `python3 -m pytest tests/ dart_corr/tests/ -q` → 116 passed
2. Tool surface still 72 (47 native + 25 SIFT)
3. `measure_accuracy.py` → recall=1.0 / hallucination=0
4. English commit message + English code comments
5. `grep` your touched surfaces for stale numbers/phrasing
