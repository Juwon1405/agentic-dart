# dfir-mcp

`dfir-mcp` is the custom MCP (Model Context Protocol) server that exposes Agentic-DFIR's typed, schema-validated, **read-only** forensic functions to the agent. It is the primary enforcement layer for the project's evidence-integrity guarantee: the agent can call exactly what this package registers and nothing else. This page explains what the package owns, how the 73-tool surface is registered and guarded, how to run the server, and which tests hold the boundary in place. Per-function reference lives in the [MCP function catalog](../docs/mcp-function-catalog.md); adapter internals live in [SIFT Workstation adapter layer](../docs/sift-adapter-layer.md).

## What it is

A custom MCP server, implemented in Python, that exposes **the typed forensic function surface** (native functions plus SIFT Workstation adapters) to the agent. It runs over stdio and speaks JSON-RPC 2.0. `dfir-mcp` is the security boundary of the project. Everything else is convenience.

## What it is NOT

It is *not* a wrapper that translates LLM intent into shell commands. There is no `execute_shell`. There is no `query_evidence(sql)`. There is no escape hatch.

## Design principle

The agent's toolkit is the set of functions this server exposes. **Nothing else.**

- No `execute_shell()`
- No `write_file()`
- No `mount()` / `umount()`
- No outbound network

If a destructive capability is not part of the MCP surface, the agent cannot invoke it. This is architectural, not prompt-based. The names that are intentionally never registered — `execute_shell`, `write_file`, `mount`, `delete_file`, `network_egress`, `spawn_process`, `kill_process` — are recorded in `dfir_mcp/__init__.py` (`__forbidden_never_registered`) and asserted absent by `tests/test_mcp_bypass.py` and `tests/test_mcp_surface.py`.

## Two layers of typed read-only tools

| Layer | Count | Source | When to use |
|---|---:|---|---|
| **Native** | 48 | Pure Python in `dfir_mcp/__init__.py` and the `_v04_expansion`, `_v05_supply_chain`, `_v06_macos_linux`, `_v07_sigma` modules | Always available; nothing to install beyond the package |
| **SIFT adapters** | 25 | Subprocess wrappers in `dfir_mcp/sift_adapters/` | When deployed on SIFT Workstation (or any host with the wrapped binaries on `PATH`) |
| **Total** | **73** | | |

The SIFT adapter layer wraps the SIFT Workstation toolchain behind the same read-only MCP boundary. Importing `dfir_mcp` imports the adapter subpackage, so adapters appear in `list_tools()` alongside the native functions whether or not the binaries are installed; a missing binary surfaces as `SiftToolNotFoundError` at call time. The registry is the arbiter of the count:

```bash
PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src \
  python3 -c "from dfir_mcp import list_tools; print(len(list_tools()))"
# -> 73
```

## The typed MCP surface

Names below are the live registry, grouped the way `tests/test_mcp_surface.py` declares the exact expected set. Signatures, artifacts read, MITRE mapping and references for each function are in the [MCP function catalog](../docs/mcp-function-catalog.md).

### Native functions (48)

- **Windows execution & traces (4)** — `get_amcache` (AmCache.hve), `parse_prefetch`, `parse_shimcache` (Application Compatibility cache), `get_process_tree` (process tree from a snapshot CSV)
- **Windows user activity (3)** — `analyze_usb_history` (SYSTEM hive + `setupapi.dev.log`), `parse_shellbags`, `extract_mft_timeline` (window-bounded, `$SI` vs `$FN`)
- **Windows system state (3)** — `list_scheduled_tasks`, `detect_persistence` (Run keys + Services + Tasks), `analyze_event_logs`
- **Windows registry (1)** — `parse_registry_hive` (generic hive reader, added in v0.5.4)
- **macOS (3)** — `parse_unified_log`, `parse_knowledgec` (KnowledgeC.db), `parse_fsevents`
- **Browser & exfiltration (4)** — `parse_browser_history`, `analyze_downloads` (Mark-of-the-Web handling), `correlate_download_to_execution`, `detect_exfiltration`
- **Authentication & lateral movement (5)** — `analyze_windows_logons`, `detect_lateral_movement` (PsExec, WMIExec), `analyze_kerberos_events` (Kerberoasting / AS-REP roasting), `analyze_unix_auth`, `detect_privilege_escalation`
- **Web/WAS + RDP brute force (3)** — `analyze_web_access_log` (Apache/Nginx combined and IIS W3C; 16 attack-pattern rules covering SQLi, XSS, LFI, RCE, SSRF, Log4Shell and webshell upload, plus scanner user-agents, 4xx/5xx spikes per source IP and long-URL anomalies), `detect_webshell` (suspicious extensions in user-writable directories, `eval(base64_decode($_POST))`-style content signatures, recent-modification outliers, known shell names such as c99, r57, WSO and China Chopper), `detect_brute_force_rdp` (credential stuffing vs spray vs single-account)
- **MITRE gap fillers (4)** — `detect_credential_access` (T1003: Mimikatz, SAM, NTDS, `comsvcs.dll` LOLBin), `detect_ransomware_behavior` (T1486/T1489/T1490), `detect_defense_evasion` (T1070: log clearing, timestomp, MFT `$SI` vs `$FN`), `detect_discovery` (T1033/T1057/T1082/T1016/T1018/T1049/T1069/T1087/T1482)
- **Cross-artifact (2)** — `correlate_events`, `correlate_timeline` (DuckDB join) — thin wrappers that delegate to [dfir-corr](../dfir_corr/README.md)
- **Linux + macOS expansion (4, added in v0.4)** — `parse_auditd_log`, `parse_systemd_journal`, `parse_bash_history`, `parse_launchd_plist`
- **Supply-chain IOC sweeps (6, added in v0.6.0)** — `scan_pth_files_for_supply_chain_iocs`, `detect_pypi_typosquatting`, `detect_nodejs_install_hooks`, `detect_python_backdoor_persistence`, `detect_credential_file_access`, `grep_shell_history_for_c2` (T1195.002, T1547, T1552, T1059.006)
- **macOS quarantine + Linux cron + DNS tunneling (3, added in v0.6.1)** — `parse_macos_quarantine` (T1204 download provenance), `parse_linux_cron_jobs` (T1053.003), `detect_dns_tunneling` (TA0011 / T1071.004: entropy, volume and Iodine/dnscat2 signatures)
- **Linux text logs + shell history (2, added in v0.7.1)** — `parse_linux_text_log` (apache/nginx access, syslog, messages, auditd dispatcher text), `parse_linux_shell_history` (bash/zsh, `HISTTIMEFORMAT`-aware)
- **Sigma matcher (1, added in v1.1.0)** — `match_sigma_rules`, applies the versioned rule pack in [`dfir_sigma/`](../dfir_sigma/README.md) to parsed events

### SIFT adapters (25)

| Adapter | Wraps |
|---|---|
| `sift_vol3_windows_pslist`, `_pstree`, `_psscan`, `_cmdline`, `_netscan`, `_malfind`, `_dlllist`, `_svcscan`, `_runkey`, `sift_vol3_linux_pslist`, `sift_vol3_linux_bash`, `sift_vol3_mac_bash` (×12) | Volatility 3 plugins (v2.27+, the version on the current SIFT Workstation) |
| `sift_mftecmd_parse` / `sift_mftecmd_timestomp` | Eric Zimmerman MFTECmd |
| `sift_evtxecmd_parse` / `sift_evtxecmd_filter_eids` | Eric Zimmerman EvtxECmd |
| `sift_pecmd_parse` / `sift_pecmd_run_history` | Eric Zimmerman PECmd |
| `sift_recmd_run_batch` / `sift_recmd_query_key` | Eric Zimmerman RECmd |
| `sift_amcacheparser_parse` | Eric Zimmerman AmcacheParser |
| `sift_yara_scan_file` / `sift_yara_scan_dir` | YARA |
| `sift_plaso_log2timeline` / `sift_plaso_psort` | Plaso |

That is 12 Volatility 3, 9 Eric Zimmerman, 2 YARA and 2 Plaso adapters. All functions return structured JSON, with cursor/limit arguments on high-volume readers. Evidence inputs are constrained to `DFIR_EVIDENCE_ROOT`; Plaso storage outputs are constrained to `DFIR_DERIVED_ROOT` so generated timelines do not modify evidence.

## The schema

Every function is registered with the `@tool(name, description, schema)` decorator in `dfir_mcp/src/dfir_mcp/__init__.py`, which places a `ToolSpec` (name, description, JSON schema, handler) in the registry. `list_tools()` returns `{name, description, inputSchema}` for each entry; `call_tool(name, arguments)` validates before dispatching to the handler:

- An unregistered name raises `KeyError("ToolNotFound: '<name>' is not exposed by dfir-mcp")`. The handler is never looked up.
- A missing required argument or an argument the schema does not declare raises `TypeError` before the handler is called (unless the schema opts in with `additionalProperties`).
- A value of the wrong JSON type raises `TypeError`; a value outside a declared `enum`, `minimum` or `maximum` raises `ValueError`.
- Schema defaults are filled in so handlers always receive a complete argument set.

Path arguments go through `_safe_resolve`, which:

- Refuses non-string or empty values
- Refuses paths containing NUL bytes
- Refuses paths longer than 1024 characters, and any path whose resolution fails at the OS level
- Resolves the path relative to `EVIDENCE_ROOT` and refuses anything that lands outside it — this is what rejects `..` segments and absolute paths outside the root
- Returns the resolved absolute path inside `EVIDENCE_ROOT` if and only if the resolution stayed inside the read-only mount

Violations raise `PathTraversalAttempt`. `EVIDENCE_ROOT` is read once from the `DFIR_EVIDENCE_ROOT` environment variable (default `/mnt/evidence`). The SIFT adapters import the same `EVIDENCE_ROOT`, `_safe_resolve` and `_sha256` helpers, so they share one sandbox with the native functions.

## Pagination

High-volume readers (MFT timelines, event logs, web access logs, registry hives and similar) declare `cursor` and `limit` in their schema, with schema-enforced maximums, and return one page per call. There is no "return everything" mode for those functions. This is for context-window safety: a multi-million-row MFT export does not fit in any current LLM context window. The agent receives a page, decides if it needs more, and explicitly requests the next page.

## Running the server

Two stdio entry points wrap the same registry:

```bash
# MCP-SDK server (requires the `stdio` extra: pip install "mcp<2", or dfir_mcp[stdio]).
# This is what `python3 -m dfir_agent --mode live` launches as a subprocess.
python3 -m dfir_mcp.server_stdio

# Register it with Claude Code so the surface can be called interactively
claude mcp add agentic-dfir -s user -- python3 -m dfir_mcp.server_stdio

# Dependency-free JSON-RPC 2.0 implementation (protocol version 2024-11-05)
python3 -m dfir_mcp.server
```

Server-side diagnostics go to stderr so they never corrupt the JSON-RPC stream on stdout. Deterministic mode (`--mode deterministic`) does not need a server at all: it imports the registry in-process and calls `call_tool` directly. See [Live mode](../docs/live-mode.md) for the wire-level walk-through.

## The bypass tests

`tests/test_mcp_bypass.py` asserts that:

| Attack | Expected result | Test |
|---|---|---|
| Call an unregistered function (`execute_shell`, `eval`, etc.) | `ToolNotFound` (`KeyError`) | `test_unregistered_destructive_function_raises_ToolNotFound` |
| Pass `..` in a path argument | rejected by `_safe_resolve` | `test_relative_path_traversal_is_blocked` |
| Pass an absolute path outside `EVIDENCE_ROOT` | rejected | `test_absolute_path_escape_is_blocked` |
| Pass a NUL-byte-truncated path | rejected | `test_null_byte_truncation_is_blocked` |
| Surface drift — a function appears that was not declared, or a declared one disappears | test fails | `test_surface_is_exact_positive_and_negative_set` |
| Submit SQL DDL/DML or DuckDB metafunctions as a `correlate_timeline` rule | rejected at the wire boundary | `test_correlate_timeline_rejects_sql_injection_attempts` |
| Handlers run against the evidence root | no new files appear under the evidence root afterwards | `test_handler_does_not_write_outside_root` |

`tests/test_mcp_surface.py` repeats the exact-set check (`test_registered_tools_are_exact_set`) and asserts that `call_tool` enforces the advertised schema. Run them with `pytest tests/test_mcp_bypass.py tests/test_mcp_surface.py`. Any change that breaks one is a release blocker.

## Audit side-tap

`dfir-mcp` itself does not write the audit log; the calling agent does, and it has a single call primitive to do it with. In deterministic mode `DeterministicAnalyst._call` in [dfir-agent](../dfir_agent/README.md) invokes `call_tool` and immediately records the call through [`dfir_audit.AuditLogger`](../dfir_audit/README.md) — tool name, validated inputs, SHA-256 digest of the output, iteration and the finding IDs it supports — before the result is consumed. In live mode the controller records every MCP call in `live_tool_calls.jsonl`. Every native function hashes the evidence files it reads (`_sha256`), and every SIFT adapter returns the SHA-256 of its primary input and of any intermediate output file, so both records chain to the artifacts that were actually read.

## Status

Active development — function-by-function. Each new function lands with:

- JSON Schema for inputs
- Unit tests against reference data (or registration tests for adapters)
- Documented failure modes (`SiftToolNotFoundError` for missing binaries, `SiftToolFailedError` for non-zero exit or timeout, `PathTraversalAttempt` for escapes)
- SHA-256 audit chain compatibility

## Adding a function

The PR checklist is in [Contributing](../CONTRIBUTING.md). The short version:

1. Read-only by construction (no write paths in the implementation)
2. Use `_safe_resolve` for any path argument
3. JSON schema declared through the `@tool` decorator
4. Cursor-paginated output for anything that can be large
5. Exact-set tests updated — `tests/test_mcp_surface.py::test_registered_tools_are_exact_set` and `tests/test_mcp_bypass.py::test_surface_is_exact_positive_and_negative_set` — plus a negative test where the function introduces a new argument class
6. Test evidence added under each case's `evidence_root/`
7. The [MCP function catalog](../docs/mcp-function-catalog.md), [Platform support](../docs/platform-support.md) and [Accuracy report](../docs/accuracy-report.md) updated

PRs that miss any of these will be sent back.

## Files

```
dfir_mcp/
├── README.md
├── pyproject.toml                 # dfir-mcp; deps duckdb, python-registry; extra [stdio] = mcp<2
└── src/dfir_mcp/
    ├── __init__.py                # registry (@tool, list_tools, call_tool), _safe_resolve, native functions
    ├── _v04_expansion.py          # Linux + macOS coverage (4 functions)
    ├── _v05_supply_chain.py       # supply-chain IOC sweeps (6 functions)
    ├── _v06_macos_linux.py        # macOS quarantine, Linux cron, DNS tunneling (3 functions)
    ├── _v07_sigma.py              # match_sigma_rules
    ├── server.py                  # dependency-free JSON-RPC 2.0 stdio server
    ├── server_stdio.py            # MCP-SDK stdio server (used by live mode)
    └── sift_adapters/
        ├── __init__.py            # imports every adapter module -> @tool registration
        ├── _common.py             # subprocess helpers, timeouts, SiftToolNotFoundError / SiftToolFailedError
        ├── volatility3.py  mftecmd.py  evtxecmd.py  pecmd.py
        ├── recmd.py  amcacheparser.py  yara.py  plaso.py
```

## See also

- [MCP function catalog](../docs/mcp-function-catalog.md) — every native function, entry by entry
- [SIFT Workstation adapter layer](../docs/sift-adapter-layer.md) — adapter contract, binary resolution, derived root
- [Architecture](../docs/architecture.md) — why a typed surface is the boundary
- [Threat model](../docs/threat-model.md) — what "read-only" means precisely, layer by layer
- [dfir-corr](../dfir_corr/README.md) — the engine behind `correlate_events` and `correlate_timeline`
- [Contributing](../CONTRIBUTING.md) — PR checklist
