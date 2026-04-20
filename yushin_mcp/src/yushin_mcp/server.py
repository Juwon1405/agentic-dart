"""MCP server entry point.

Wires yushin_mcp's typed function registry to the Model Context Protocol
via stdio transport. Run as:

    python -m yushin_mcp.server

Claude Code registers this with:

    claude mcp add yushin-mcp --transport stdio \\
        --command python --args -m,yushin_mcp.server
"""
from __future__ import annotations

import asyncio
import json
import sys

from . import list_tools, call_tool


async def _serve_stdio() -> None:
    """Minimal JSON-RPC over stdio loop, compatible with the MCP handshake.

    We ship a hand-rolled transport here to keep the MVP zero-dep. Swap in
    `mcp.server.stdio` from the official SDK in W3 for full MCP features
    (resource, prompt, sampling). Tool-calling semantics below match the
    JSON-RPC 2.0 shape the SDK expects.
    """
    reader = asyncio.StreamReader()
    loop = asyncio.get_event_loop()
    transport_in, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )

    def send(msg: dict) -> None:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            req = json.loads(line.decode())
        except json.JSONDecodeError:
            continue

        rid = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        try:
            if method == "initialize":
                result = {"protocolVersion": "2025-06-18",
                          "serverInfo": {"name": "yushin-mcp", "version": "0.1.0"},
                          "capabilities": {"tools": {}}}
            elif method == "tools/list":
                result = {"tools": list_tools()}
            elif method == "tools/call":
                name = params["name"]
                args = params.get("arguments") or {}
                result = {"content": [{"type": "text",
                                       "text": json.dumps(call_tool(name, args))}]}
            elif method == "notifications/initialized":
                continue  # No response required
            else:
                send({"jsonrpc": "2.0", "id": rid,
                      "error": {"code": -32601, "message": f"method not found: {method}"}})
                continue
            send({"jsonrpc": "2.0", "id": rid, "result": result})
        except Exception as e:
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32000, "message": str(e)}})


def main() -> int:
    try:
        asyncio.run(_serve_stdio())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
