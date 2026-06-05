# CLAUDE.md — AI Assistant Guide for Agentic-DART

> Guidance for Claude Code (and any AI assistant) working in this repository.
> Read this before editing. The rules in **Non-negotiables** are load-bearing:
> they are the product, not style preferences.

## What this project is

**Agentic-DART** is an autonomous DFIR (Digital Forensics & Incident Response)
agent. A senior-analyst reasoning loop calls **typed, read-only** forensic
tools over MCP, records every call in a **SHA-256-chained audit log**, and
produces a findings report. The guardrails live in the architecture (a
read-only MCP boundary), not in the prompt.

```yaml
Stack:    Python 3.10+, MCP, Anthropic SDK (live mode only)
Surface:  72 MCP tools = 47 native pure-Python + 25 SIFT-tool adapters
Tests:    116 = 102 (tests/) + 14 (dart_corr/tests/)
Cases:    11 case studies, 99 ground-truth findings
Version:  0.7.1
License:  MIT
Entry:    SANS FIND EVIL! 2026
```

## Repository map

```
dart_audit/      SHA-256-chained JSONL logger — tamper-evident audit of every MCP call
dart_mcp/        Custom MCP server — typed, read-only forensic functions (native + SIFT adapters)
dart_agent/      Iteration controller, hypothesis tracker, deterministic + live loops
dart_corr/       Cross-artifact correlation engine — DuckDB joins, contradiction flagging
dart_playbook/   Senior-analyst YAML playbooks (v1/v2/v3) — DATA, not a Python package
examples/        case-studies/, sample-evidence/ (reference), sample-evidence-realistic/, demos
scripts/         install.sh, benchmark/, measure_accuracy.py, generate_realistic_evidence.py
tests/           102 tests; dart_corr/tests/ holds the other 14
docs/            architecture, accuracy report, case walkthroughs
```

Note: `dart_audit` / `dart_mcp` / `dart_agent` / `dart_corr` are installable
Python packages (each has a `pyproject.toml`). `dart_playbook` is a directory
of YAML playbooks with no `pyproject.toml` and is loaded by path, not imported.

## Run modes (know which one you are touching)

| Mode | Flag | Network / API | Used by |
|---|---|---|---|
| **Deterministic** | `--mode deterministic` (default) | none — scripted analyst calls MCP functions directly | demos, CI, accuracy harness |
| **Live** | `--mode live` | Anthropic API (key or OAuth) | real-Claude reasoning, fidelity runs |
| **Dry-run** | `--dry-run` | none — exercises live plumbing with a mock LLM | smoke-testing the live path |

CI and `scripts/measure_accuracy.py` run **deterministic only** — they never
touch the network. Anything you change in live mode (e.g. `dart_agent/auth.py`)
does not affect CI, the accuracy numbers, or the 116 tests, which are
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
6. **Counts are measured, never guessed.** Before writing any number (tool
   count, test count, findings), measure it live. See **Verify** below.

## Verify (run before claiming done)

```bash
export PYTHONPATH=dart_audit/src:dart_mcp/src:dart_agent/src:dart_corr/src

# Full test suite — must be 116 passed
python3 -m pytest tests/ dart_corr/tests/ -q

# Tool surface — must be 72 (47 native + 25 SIFT)
PYTHONPATH=dart_mcp/src python3 -c "import dart_mcp; t=dart_mcp._REGISTRY; \
s=[k for k in t if k.startswith('sift_')]; print(len(t), len(t)-len(s), len(s))"

# Accuracy — must hold recall=1.0 / hallucination=0
python3 scripts/measure_accuracy.py
```

When you change a number anywhere, sweep **all** surfaces so they stay
consistent: top-level `README.md`, `docs/`, `CHANGELOG.md`, every folder
`README.md`, and the GitHub wiki. A figure that is right in one place and stale
in another is a defect.

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
