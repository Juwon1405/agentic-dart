# dart-mcp

Custom MCP server that exposes typed, schema-validated, **read-only** forensic functions to Claude Code. The primary enforcement layer for Agentic-DART's evidence integrity guarantee.

## Design principle

The agent's toolkit is the set of functions this server exposes. **Nothing else.**

- No `execute_shell()`
- No `write_file()`
- No `mount()` / `umount()`
- No outbound network

If a destructive capability is not part of the MCP surface, the agent cannot invoke it. This is architectural, not prompt-based.

## Exposed functions (initial set)

| Function | Purpose |
|---|---|
| `get_amcache()` | Parse Amcache.hve, return structured JSON |
| `extract_mft_timeline(start, end)` | Window-bounded MFT timeline |
| `parse_prefetch(target)` | Prefetch for a single target |
| `analyze_usb_history()` | USB setupapi + registry USB history |
| `list_scheduled_tasks()` | System-wide scheduled task enumeration |
| `correlate_events(hypothesis_id)` | Delegates to `dart-corr` |

All functions return cursor-paginated JSON. None accept arbitrary file paths outside the evidence mount.

## Status

Active development — function-by-function. Each new function lands with:

- Pydantic schema for inputs and outputs
- Unit tests against reference data
- Documented failure modes

See [`../docs/architecture.md`](../docs/architecture.md) for the design rationale.
