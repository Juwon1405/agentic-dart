# AGENTS.md — Agent Guide for Agentic-DART

> Concise operational guide for Codex and other coding agents. For the full
> rationale see [CLAUDE.md](./CLAUDE.md). When the two overlap, both are
> authoritative; CLAUDE.md carries the longer explanation.
>
> No hard-coded counts live in this file on purpose — they drift on every
> ship and would violate our measure-don't-guess rule. Run the commands below
> for live values.

## Project summary

Autonomous DFIR agent. A senior-analyst loop calls **typed, read-only** MCP
tools (two layers: native pure-Python functions + SIFT-tool adapters), logs
every call in a SHA-256-chained audit, and emits a findings report.
Python 3.10+, MIT, SANS FIND EVIL! 2026.

## Repository map

- `dart_audit/` — SHA-256-chained JSONL audit logger (Python package)
- `dart_mcp/` — custom MCP server, typed read-only forensic functions (Python package)
- `dart_agent/` — iteration controller, deterministic + live loops, auth (Python package)
- `dart_corr/` — DuckDB cross-artifact correlation engine (Python package)
- `dart_playbook/` — senior-analyst YAML playbooks; **data, no `pyproject.toml`, loaded by path**
- `examples/` — `case-studies/{self-evaluation,external-evaluation}/case-NN/` (README + truth.json + evidence_root), `sample-evidence/` (CI fixture), demos
- `scripts/` — `install.sh`, `benchmark/`, `scripts/eval/demo.py`, `generate_realistic_evidence.py`
- `tests/` — main pytest suite; `dart_corr/tests/` — correlation-engine tests

## Preferred commands

```bash
export PYTHONPATH=dart_audit/src:dart_mcp/src:dart_agent/src:dart_corr/src

# Full suite — every test must pass
python3 -m pytest tests/ dart_corr/tests/ -q

# Focused
python3 tests/test_mcp_surface.py        # tool-surface drift (asserts the exact set)
python3 tests/test_mcp_bypass.py         # adversarial / read-only guard
python3 -m pytest dart_corr/tests/ -q    # correlation engine

# Live tool count / native / SIFT split
PYTHONPATH=dart_mcp/src python3 -c "import dart_mcp; t=dart_mcp._REGISTRY; \
s=[k for k in t if k.startswith('sift_')]; print(len(t), len(t)-len(s), len(s))"

# Offline demo (deterministic, no API key)
bash examples/demo-run.sh

# Accuracy (deterministic; recall must stay 1.0, hallucination 0)
python3 -m scripts.eval.demo
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
- Measure counts live before writing them anywhere; prefer pointing at the
  measurement over pinning a figure. If a number must appear in prose, sweep
  every surface (README, docs, CHANGELOG, folder READMEs, wiki) so none drifts.

## Data safety — read-only, no evidence writes

This repo never writes to or mutates the evidence tree. The standing rule: **never** commit real
evidence, credentials, tokens, internal hostnames, company names, colleague
names, or internal codenames. Intentional and allowed: the demo persona
`yushin@siftworkstation`, `/home/yushin/...`, and the author handle
`Juwon1405`.

## Before finishing

1. `python3 -m pytest tests/ dart_corr/tests/ -q` → every test passes
2. Tool surface still matches the set asserted by `tests/test_mcp_surface.py`
3. `scripts/eval/demo.py` → recall 1.0 / hallucination 0 (no regression)
4. English commit message + English code comments
5. `grep` your touched surfaces for stale numbers/phrasing
