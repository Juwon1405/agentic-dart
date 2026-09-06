# dfir-corr

`dfir-corr` is the cross-artifact correlation engine: Python plus DuckDB, performing timeline joins across disk, memory and network evidence and surfacing disagreements between artifacts as `UNRESOLVED` rather than smoothing them over. It is the component that keeps the agent from believing whatever the first source told it. This page explains what the package owns, the three public functions and their exact signatures, the rule pack, how the same functions reach the MCP wire, and how to run its tests.

## Status

**Stable — extracted and implemented.** Since v0.7.1 `dfir_corr` is a real standalone package, extracted from the inline implementation that previously lived in `dfir_mcp`. Three public functions are implemented end-to-end:

| Function | Engine | Purpose |
|---|---|---|
| `correlate_events` | proximity join | USB ↔ logon time-proximity (IP-KVM precedes logon → `UNRESOLVED`) |
| `correlate_timeline` | DuckDB `:memory:` | n-source cross-artifact join; contradictions when same actor + different type |
| `correlate_download_to_execution` | filename + window | Corroborate execution against a prior download; surfaces revision-required findings |

Plus `load_rules()` for the operator-tunable rule pack in `correlation-rules.yaml`. `dfir_corr.__version__` reports the package version (2.0.0 in the current release).

## What it owns

- The correlation rule pack (`dfir_corr/correlation-rules.yaml`)
- DuckDB-backed in-process joins for time-proximity correlation
- The contradiction records: every disagreement is returned with `status: "UNRESOLVED"` and is never auto-resolved by the engine
- The three engine functions behind the MCP-surface tools `correlate_events`, `correlate_timeline` and `correlate_download_to_execution`

## What it does *not* own

- Hypothesis revision — that's [dfir-agent](../dfir_agent/README.md)'s job
- Storing audit entries — that's [dfir-audit](../dfir_audit/README.md)'s job
- The artifacts themselves — those come from [dfir-mcp](../dfir_mcp/README.md) functions
- I/O and agent state — every function is pure: inputs arrive as Python data structures, each call is independent

## Why a separate engine

The LLM is good at reasoning. It is not good at joining a 5M-row MFT against a 200K-row memory process list under time pressure. `dfir-corr` does the set algebra; the agent does the interpretation.

## The mechanical guarantee

When two artifacts disagree on a fact, `dfir-corr` flags it.

**Example from the [Pass-the-Hash with timestomp case study](../docs/case-pth-timestomp.md):**

| Source | Claim |
|---|---|
| Auth events (4624) | Pass-the-Hash at `14:23:09 UTC` |
| MFT `$SI` vs `$FN` | Timestomp at `14:21:55 UTC` (74 sec earlier) |

A naive LLM agent might pick whichever claim supports its current hypothesis. `dfir-corr` raises `UNRESOLVED` and forces the agent to revise — there must be a third explanation that reconciles both, or the hypothesis is wrong. The rule that fires here is `pth_with_timestomp_pre_existence` in the rule pack.

## Core operations

- Timeline merge across MFT / Amcache / Prefetch / USB setupapi / Security event log
- Cross-reference disk timeline against memory process tree and network sockets
- Contradiction flagging: when two sources disagree on a fact, mark `UNRESOLVED` — do not smooth over

## Contradiction policy

The agent is architecturally forbidden from reporting a resolved finding when the correlation engine has flagged a contradiction on that same fact. The report must either:

- Resolve the contradiction by running additional MCP calls, or
- Explicitly report the finding as `UNRESOLVED` with both conflicting sources cited

The playbook's phase P6 encodes the same rule, and the deterministic agent's `report.json` carries an `unresolved` list for anything left open.

## Why DuckDB

`dfir-corr` runs in-process (no server, no port). For multi-million-row MFT timelines, naive Python joins run out of memory. DuckDB handles 5M+ row joins in seconds, all without leaving the process.

`correlate_timeline` normalises every event into one in-memory table — `ts`, `source`, `actor`, `target`, `type` and the raw record — and self-joins it inside `window_seconds`, treating rows that share an actor or target as correlations and rows that share an actor or target but disagree on the event type as contradictions. The agent doesn't write SQL. It supplies the events and a window; the engine returns the records.

## Usage

Direct (without the MCP wire):

```python
import dfir_corr

# Time-proximity join (defaults: proximity_seconds=600)
r = dfir_corr.correlate_events(
    "hypothesis_001",
    usb_events=[{"ts": "2026-04-29T14:20:00", "is_ip_kvm": True}],
    logon_events=[{"ts": "2026-04-29T14:22:30", "user": "alice"}],
)
# r["contradictions"] holds one record:
# {"rule": "ip_kvm_precedes_logon", "usb_event": ..., "logon_event": ...,
#  "delta_seconds": 150, "severity": "high", "status": "UNRESOLVED"}
# r also carries hypothesis_id, usb_event_count, logon_event_count, clean_correlations

# n-source DuckDB join (defaults: rules=None, window_seconds=300)
r = dfir_corr.correlate_timeline(events=mft_rows + evtx_rows + netflow_rows,
                                 window_seconds=300)
# keys: correlations, contradictions, normalized_event_count, window_seconds,
#       correlations_truncated_at

# Download -> execution corroboration (defaults: window_seconds=86400)
r = dfir_corr.correlate_download_to_execution(downloads, executions)
if r["revision_required"]:
    # at least one execution has no matching download — agent must revise
    ...
# keys: corroborated, uncorroborated, download_count, execution_count,
#       revision_required, window_seconds

rules = dfir_corr.load_rules()          # {"rules": [...], "_loaded_from": "<path>"}
```

Event dicts are tolerant on field names: `ts` or `timestamp`; `actor` or `user`; `target`, `path` or `image`; `type` or `event_type`. Timestamps are accepted in ISO-8601 with or without fractional seconds and with or without a UTC offset, and in the `YYYY-MM-DD HH:MM:SS` form Plaso and EVTX exports use.

Via the MCP wire (what the agent uses): the same functions are re-exported through `dfir_mcp` with name and schema preserved. `dfir_mcp.correlate_events` delegates directly. `dfir_mcp.correlate_timeline` keeps two things at the boundary: a back-compat result shape for existing case studies, and the defence for user-supplied `rules` strings — a strict character allow-list plus a forbidden-keyword list (`union`, `insert`, `update`, `delete`, `drop`, `create`, `alter`, `attach`, `copy`, `pragma`, `read_csv`, `read_parquet`, `export`, `install`, `load`, `exec`, `describe`, `explain` and similar) applied before any fragment reaches DuckDB. Rejected rules come back as `{"rule": ..., "error": "rule rejected: ..."}` rather than raising; `tests/test_mcp_bypass.py::test_correlate_timeline_rejects_sql_injection_attempts` covers it. Both call paths produce identical engine output.

## Rule pack

`correlation-rules.yaml` ships with 9 default contradiction patterns, each declared as `name`, `description`, `source_a`, `source_b`, `window_seconds` and `severity`:

`ip_kvm_session_overlaps_vpn_session`, `ip_kvm_precedes_logon`, `lolbin_followed_by_exfil`, `pth_with_timestomp_pre_existence`, `disk_process_exit_vs_memory_alive`, `kerberos_pkinit_anomalous_origin`, `signed_vendor_binary_spawns_recon`, `dcsync_from_non_dc_host`, `log_clear_after_admin_action`.

Operators add, remove or tune rules in this file; no Python changes required. `load_rules(path=None)` reads the shipped file by default and records where it loaded from under `_loaded_from`.

## Files

```
dfir_corr/
├── README.md                  # this file
├── pyproject.toml             # dfir-corr; depends on duckdb + PyYAML
├── correlation-rules.yaml     # operator-tunable rule pack (9 default rules)
├── src/dfir_corr/
│   └── __init__.py            # the engine — three public correlate_* functions + load_rules
└── tests/
    └── test_dfir_corr.py      # engine tests, independent of dfir_mcp
```

## Tests

```bash
PYTHONPATH=dfir_corr/src python3 -m pytest dfir_corr/tests/ -v
```

The engine tests run independent of `dfir_mcp`; the repository-wide invocation in [`tests/README.md`](../tests/README.md) includes `dfir_corr/tests/` alongside `tests/`. The `dfir_mcp` wrappers exist only to expose these functions on the MCP wire; the engine itself has no MCP coupling. The supported install path (`scripts/install.sh`) installs `dfir_mcp` and `dfir_corr` editable together — a wheel-only install without `dfir_corr` raises `ImportError` on the `correlate_*` tools.

## See also

- [Architecture — Why DuckDB](../docs/architecture.md#why-duckdb)
- [Threat model](../docs/threat-model.md)
- [Case study: Pass-the-Hash with timestomp](../docs/case-pth-timestomp.md) — worked example of `UNRESOLVED` driving revision
- [dfir-mcp](../dfir_mcp/README.md) — the wire wrappers and the SQL-injection defence
- [dfir-playbook](../dfir_playbook/README.md) — phase P6, contradiction handling
