# dart-mcp

Custom MCP server that exposes typed, schema-validated, **read-only** forensic functions to Claude Code. The primary enforcement layer for Agentic-DART's evidence integrity guarantee.

## Design principle

The agent's toolkit is the set of functions this server exposes. **Nothing else.**

- No `execute_shell()`
- No `write_file()`
- No `mount()` / `umount()`
- No outbound network

If a destructive capability is not part of the MCP surface, the agent cannot invoke it. This is architectural, not prompt-based.

## Two layers of typed read-only tools

| Layer | Count | Source | When to use |
|---|---:|---|---|
| **Native** | 35 | Pure Python in `dart_mcp/__init__.py` | Always available, fresh-clone demo |
| **SIFT adapters** | 25 | Subprocess wrappers in `dart_mcp/sift_adapters/` | When deployed on SIFT Workstation |
| **Total** | **60** | | |

The SIFT adapter layer brings agentic-dart into explicit alignment with the SANS FIND EVIL! 2026 **Custom MCP Server** pattern. See the project root README's `## SIFT Workstation alignment` section.

## Exposed functions (selected — full list via `list_tools()`)

### Native (Windows execution + persistence)
| Function | Purpose |
|---|---|
| `get_amcache()` | Parse Amcache.hve, return structured JSON |
| `extract_mft_timeline(start, end)` | Window-bounded MFT timeline |
| `parse_prefetch(target)` | Prefetch for a single target |
| `analyze_usb_history()` | USB setupapi + registry USB history |
| `list_scheduled_tasks()` | System-wide scheduled task enumeration |
| `detect_persistence()` | Run keys + Services + Tasks (3 mechanisms) |

### SIFT adapters (subprocess into SIFT Workstation tooling)
| Adapter | Wraps |
|---|---|
| `sift_vol3_windows_pslist` etc. (×12) | Volatility 3 v2.27 plugins |
| `sift_mftecmd_parse` / `sift_mftecmd_timestomp` | Eric Zimmerman MFTECmd |
| `sift_evtxecmd_parse` / `sift_evtxecmd_filter_eids` | Eric Zimmerman EvtxECmd |
| `sift_pecmd_parse` / `sift_pecmd_run_history` | Eric Zimmerman PECmd |
| `sift_recmd_run_batch` / `sift_recmd_query_key` | Eric Zimmerman RECmd |
| `sift_amcacheparser_parse` | Eric Zimmerman AmcacheParser |
| `sift_yara_scan_file` / `sift_yara_scan_dir` | YARA |
| `sift_plaso_log2timeline` / `sift_plaso_psort` | Plaso |

All functions return cursor-paginated JSON. None accept arbitrary file paths outside `DART_EVIDENCE_ROOT`.

## Status

Active development — function-by-function. Each new function lands with:

- JSON Schema for inputs
- Unit tests against reference data (or registration tests for adapters)
- Documented failure modes (`SiftToolNotFoundError` for missing binaries, `PathTraversalAttempt` for escapes)
- SHA-256 audit chain compatibility

See [`../docs/architecture.md`](../docs/architecture.md) for the design rationale.
