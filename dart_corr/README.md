# dart-corr

Cross-artifact correlation engine. Python + DuckDB. Performs timeline joins across disk, memory, and network evidence; flags contradictions as `UNRESOLVED`.

## Why a separate engine

The LLM is good at reasoning. It is not good at joining a 5M-row MFT against a 200K-row memory process list under deadline pressure. `dart-corr` does the set algebra; the agent does the interpretation.

## Core operations

- Timeline merge across MFT / Amcache / Prefetch / USB setupapi / Security event log
- Cross-reference disk timeline against memory process tree and network sockets
- Contradiction flagging: when two sources disagree on a fact, mark `UNRESOLVED` — do not smooth over

## Contradiction policy

The agent is architecturally forbidden from reporting a resolved finding when the correlation engine has flagged a contradiction on that same fact. The report must either:

- Resolve the contradiction by running additional MCP calls, or
- Explicitly report the finding as `UNRESOLVED` with both conflicting sources cited

## Status

Scaffolding. First join (MFT ↔ memory process tree) targets mid-May 2026.
