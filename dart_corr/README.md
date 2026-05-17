# dart-corr

Cross-artifact correlation engine. Python + DuckDB. Performs timeline joins across disk, memory, and network evidence; flags contradictions as `UNRESOLVED`.

## Status — v0.7.1

**Extracted and implemented.** The package is no longer a docs-only scaffold. Three public functions are implemented end-to-end:

| Function | Engine | Purpose |
|---|---|---|
| `correlate_events` | proximity join | USB ↔ logon time-proximity (IP-KVM precedes logon → `UNRESOLVED`) |
| `correlate_timeline` | DuckDB `:memory:` | n-source cross-artifact join, contradictions when same actor + different type |
| `correlate_download_to_execution` | filename + window | Corroborate exec against prior download; surfaces revision-required findings |

Plus `load_rules()` for the operator-tunable rule pack in `correlation-rules.yaml`.

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

## Files

```
dart_corr/
├── README.md                  # this file
├── pyproject.toml             # package metadata; depends on duckdb + PyYAML
├── correlation-rules.yaml     # operator-tunable rule pack (9 default rules)
├── src/dart_corr/
│   └── __init__.py            # the engine — three public correlate_* functions
└── tests/
    └── test_dart_corr.py      # 14 tests; pytest dart_corr/tests/
```

## Usage

Direct (without the MCP wire):

```python
import dart_corr

# Time-proximity join
r = dart_corr.correlate_events(
    "hypothesis_001",
    usb_events=[{"ts": "2026-04-29T14:20:00", "is_ip_kvm": True}],
    logon_events=[{"ts": "2026-04-29T14:22:30", "user": "alice"}],
)
# r["contradictions"] now contains one UNRESOLVED record

# n-source DuckDB join with rule pack
r = dart_corr.correlate_timeline(events=mft_rows + evtx_rows + netflow_rows,
                                 window_seconds=300)

# Download → execution corroboration
r = dart_corr.correlate_download_to_execution(downloads, executions)
if r["revision_required"]:
    # at least one execution has no matching download — agent must revise
    ...
```

Via the MCP wire (what the agent uses): the same functions are re-exported through `dart_mcp` with name/schema preserved for backwards compatibility. `dart_mcp.correlate_timeline` adds a thin SQL-injection defense layer on top before delegating to `dart_corr.correlate_timeline`.

## Rule pack

`correlation-rules.yaml` ships with 9 default contradiction patterns including `ip_kvm_precedes_logon`, `pth_with_timestomp_pre_existence`, `dcsync_from_non_dc_host`, and `signed_vendor_binary_spawns_recon`. Operators add/remove/tune rules in this file; no Python changes required.

## Tests

```bash
PYTHONPATH=dart_corr/src python3 -m pytest dart_corr/tests/ -v
# 14 passed
```

Tests run independent of `dart_mcp`. The dart_mcp wrappers exist only to expose these functions on the MCP wire; the engine itself has no MCP coupling.
