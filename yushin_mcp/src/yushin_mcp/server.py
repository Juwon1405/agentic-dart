"""yushin-mcp stdio server — speaks JSON-RPC 2.0 per the MCP spec.

Launch from Claude Code with:

    claude mcp add yushin python3 -m yushin_mcp.server

The server exposes exactly the set of tools registered via @tool. Nothing
else is reachable. This is the 'live' runtime used by the `--mode live`
path; the `--mode deterministic` path used in CI does not need this
because it imports the tool registry in-process.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import list_tools, call_tool

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "yushin-mcp", "version": "0.2.0"}


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _error(req_id, code, message):
    _send({"jsonrpc": "2.0", "id": req_id,
           "error": {"code": code, "message": message}})


def _handle(req: dict) -> None:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        _send({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        })
    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": req_id,
               "result": {"tools": list_tools()}})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            out = call_tool(name, args)
            _send({"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": json.dumps(out)}],
                "isError": False,
            }})
        except KeyError as e:
            # Unknown/unregistered tool — return MCP-level error, not exception
            _error(req_id, -32601, str(e))
        except Exception as e:
            _error(req_id, -32000, f"{type(e).__name__}: {e}")
    elif method in ("notifications/initialized", "notifications/cancelled"):
        pass  # notifications have no id
    else:
        _error(req_id, -32601, f"method not found: {method}")


def main() -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        _handle(req)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
