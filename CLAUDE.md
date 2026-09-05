# CLAUDE.md — AI Assistant Guide for Agentic-DFIR

> Guidance for Claude Code (and any AI assistant) working in this repository.
> Read this before editing. The rules in **Non-negotiables** are load-bearing:
> they are the product, not style preferences.
>
> This file deliberately carries **no hard-coded counts** (tool / test / case /
> finding totals, or the version number). Those change every time we ship;
> pinning them here would contradict our own *measure-don't-guess* rule and add
> one more surface to keep in sync. For any live number, run the **Verify**
> block — it is the single source of truth.

## What this project is

**Agentic-DFIR** is an autonomous DFIR (Digital Forensics & Incident Response)
agent. A senior-analyst reasoning loop calls **typed, read-only** forensic
tools over MCP, records every call in a **SHA-256-chained audit log**, and
produces a findings report. The guardrails live in the architecture (a
read-only MCP boundary), not in the prompt.

```yaml
Stack:    Python 3.10+, MCP, Anthropic SDK (live mode only)
Surface:  two layers — native pure-Python forensic functions + SIFT-tool adapters
Modes:    deterministic (default) / live / dry-run
License:  MIT
```

Exact tool / test / case / finding counts and the current version are
intentionally **not pinned here** — run **Verify** for live values, or read
`pyproject.toml` / `CHANGELOG.md` for the version.

## Repository map

```
dfir_audit/      SHA-256-chained JSONL logger — tamper-evident audit of every MCP call
dfir_mcp/        Custom MCP server — typed, read-only forensic functions (native + SIFT adapters)
dfir_agent/      Iteration controller, hypothesis tracker, deterministic + live loops
dfir_corr/       Cross-artifact correlation engine — DuckDB joins, contradiction flagging
dfir_playbook/   Senior-analyst YAML playbooks — DATA, not a Python package
examples/        case-studies/{self-evaluation,external-evaluation}/case-NN/ (README+truth.json+evidence_root), demos
scripts/         install.sh, benchmark/, scripts/eval/demo.py, generate_realistic_evidence.py
tests/           the main pytest suite; dfir_corr/tests/ holds the correlation-engine tests
docs/            architecture, accuracy report, case walkthroughs
```

Note: `dfir_audit` / `dfir_mcp` / `dfir_agent` / `dfir_corr` are installable
Python packages (each has a `pyproject.toml`). `dfir_playbook` is a directory
of YAML playbooks with no `pyproject.toml`; it is loaded by path, not imported.

## Run modes (know which one you are touching)

| Mode | Flag | Network / API | Used by |
|---|---|---|---|
| **Deterministic** | `--mode deterministic` (default) | none — scripted analyst calls MCP functions directly | demos, CI, accuracy harness |
| **Live** | `--mode live` | Anthropic API credentials | real-Claude reasoning, fidelity runs |
| **Dry-run** | `--dry-run` | none — exercises live plumbing with a mock LLM | smoke-testing the live path |

CI and `scripts/eval/demo.py` run **deterministic only** — they never
touch the network. Anything you change in live mode (e.g. `dfir_agent/auth.py`)
does not affect CI, the accuracy numbers, or the test suite, which are
mock-backed.

## Non-negotiables (do not break these)

1. **Read-only by construction.** No MCP function may write to, move, or delete
   anything in the evidence tree. Every path argument goes through
   `_safe_resolve`. There is no `execute_shell`, `eval`, `write_file`, or any
   general-purpose escape — and none may be added.
2. **Guardrails stay in architecture, never in the prompt.** If a safety
   property depends on the model "choosing" to behave, it is wrong. Enforce it
   at the MCP boundary.
3. **Every MCP function is typed and tested.** Pydantic/JSON schema required;
   a bypass test in `tests/test_mcp_bypass.py` is required; the exact tool set
   is asserted by `tests/test_mcp_surface.py`.
4. **The audit chain is sacred.** Every successful MCP call appends a
   SHA-256-chained entry. Do not add code paths that mutate or skip the chain.
5. **Determinism in deterministic mode.** Same input → same output, byte-stable.
   Do not introduce nondeterminism (unseeded randomness, parallel tool calls
   that reorder the audit chain, wall-clock-dependent output) into the
   deterministic path.
6. **Counts are measured, never guessed — including in docs.** Before writing
   any number anywhere, measure it live (see **Verify**). Prefer pointing at the
   measurement over pinning a figure that will drift.

## Verify (run before claiming done)

```bash
export PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src

# Full test suite — every test must pass
python3 -m pytest tests/ dfir_corr/tests/ -q

# Tool surface — must exactly match the set asserted by tests/test_mcp_surface.py.
# This prints the live total / native / SIFT split:
PYTHONPATH=dfir_mcp/src python3 -c "import dfir_mcp; t=dfir_mcp._REGISTRY; \
s=[k for k in t if k.startswith('sift_')]; print(len(t), len(t)-len(s), len(s))"

# Accuracy — must not regress: recall stays 1.0, hallucination stays 0
python3 -m scripts.eval.demo
```

When you change a count, do not copy the new number into prose across the repo.
Where a figure must appear (e.g. a release note), treat the **Verify** output as
the source and sweep every surface that already states it — top-level
`README.md`, `docs/`, `CHANGELOG.md`, folder `README.md`s, and the GitHub wiki —
so none goes stale.

## OPSEC (this is a public repository)

Never commit: company names, internal hostnames, colleague names, internal
project codenames, credentials, tokens, or real evidence. The demo persona
(`yushin@siftworkstation`, `/home/yushin/...`) and the author handle
(`Juwon1405`) are intentional and fine. Everything else internal stays out.

## Commit hygiene

- English commit messages and English code comments. Explain *why*, not *what*.
- One logical change per commit.
- After committing, `grep` for leftover stale phrasing across the surfaces you
  touched.
