"""MCP stdio server entrypoint for dart-mcp.

Run with:
    python3 -m dart_mcp.server_stdio

This wraps the internal function registry (_REGISTRY) in the standard
MCP protocol so external agents — Claude Code, Claude Desktop, our own
dart_agent --mode live — can discover and call forensic tools over
stdio JSON-RPC without knowing anything about Python internals.

Design note: the MCP protocol itself is the attack surface. Any function
not registered via @tool() cannot be reached over this transport.
That property is asserted by tests/test_live_mcp.py.
"""
from __future__ import annotations

import asyncio
import json
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from . import _REGISTRY, call_tool, list_tools


# MCP Server instance. Name is what shows up to clients.
app = Server("dart-mcp")


@app.list_tools()
async def handle_list_tools() -> list[Tool]:
    """Advertise every registered forensic function to the MCP client.

    The client sees exactly the functions we register — nothing more,
    nothing less. This is the architectural guardrail over the wire.
    """
    out = []
    for spec in list_tools():
        out.append(Tool(
            name=spec["name"],
            description=spec["description"],
            inputSchema=spec["inputSchema"],
        ))
    return out


@app.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a registered function. Any attempt to call something not in
    _REGISTRY raises the same KeyError the in-process path would raise."""
    try:
        result = call_tool(name, arguments or {})
        return [TextContent(
            type="text",
            text=json.dumps(result, default=str, indent=2),
        )]
    except KeyError as e:
        # Surface the ToolNotFound error as a structured result so the
        # agent can reason about it rather than crashing.
        return [TextContent(
            type="text",
            text=json.dumps({"error": "ToolNotFound", "detail": str(e)}),
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=json.dumps({"error": type(e).__name__, "detail": str(e)[:500]}),
        )]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
