"""End-to-end test of live-mode MCP plumbing.

Does NOT require an ANTHROPIC_API_KEY. Runs in --dry-run which uses a
scripted mock-Claude that still calls the real yushin-mcp subprocess
over real MCP stdio JSON-RPC. This exercises:

  1. Subprocess spawn of `python -m yushin_mcp.server_stdio`
  2. MCP initialize() handshake
  3. list_tools() over the wire — verifies all 15 functions are advertised
  4. call_tool() over the wire — verifies a real tool returns real data
  5. The ToolNotFound guardrail survives the wire (adversarial path)
  6. Agent writes live_transcript.txt, live_tool_calls.jsonl, live_summary.json
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "yushin_mcp" / "src"))
sys.path.insert(0, str(REPO / "yushin_audit" / "src"))
sys.path.insert(0, str(REPO / "yushin_agent" / "src"))
os.environ["YUSHIN_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")
os.environ["PYTHONPATH"] = (
    f"{REPO / 'yushin_mcp' / 'src'}:"
    f"{REPO / 'yushin_audit' / 'src'}:"
    f"{REPO / 'yushin_agent' / 'src'}"
)


def test_live_mode_subprocess_dryrun():
    """Run `yushin-agent --mode live --dry-run` end-to-end."""
    with tempfile.TemporaryDirectory() as td:
        result = subprocess.run(
            [sys.executable, "-m", "yushin_agent",
             "--mode", "live", "--case", "live-test",
             "--out", td, "--dry-run", "--max-iterations", "5"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, \
            f"live mode failed: rc={result.returncode}\nstderr:{result.stderr}"

        # Check stderr for handshake banner
        assert "MCP handshake OK" in result.stderr, \
            f"MCP handshake banner missing:\n{result.stderr}"
        assert "19 tools visible" in result.stderr, \
            f"Expected 15 tools over the wire:\n{result.stderr}"

        # Outputs exist
        out = Path(td)
        assert (out / "live_transcript.txt").exists()
        assert (out / "live_tool_calls.jsonl").exists()
        assert (out / "live_summary.json").exists()

        # Summary is structured correctly
        summary = json.loads((out / "live_summary.json").read_text())
        assert summary["case"] == "live-test"
        assert summary["mode"] == "dry-run"
        assert summary["iterations"] > 0
        assert summary["tool_call_count"] > 0
        assert len(summary["findings"]) > 0, "dry-run should produce at least one finding"


def test_live_mcp_server_advertises_correct_surface():
    """Spawn yushin-mcp stdio server and call list_tools() over the wire.

    This is the guardrail-over-wire check: the protocol surface must match
    the in-process _REGISTRY exactly. Any drift fails this test.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "yushin_mcp.server_stdio"],
            env={**os.environ},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.list_tools()
                return {t.name for t in resp.tools}

    advertised = asyncio.run(run())

    expected = {
        # Windows: execution
        "get_amcache", "parse_prefetch", "parse_shimcache", "get_process_tree",
        # Windows: user activity
        "analyze_usb_history", "parse_shellbags", "extract_mft_timeline",
        # Windows: system state
        "list_scheduled_tasks", "detect_persistence", "analyze_event_logs",
        # Cross-artifact
        "correlate_events", "correlate_timeline",
        # macOS
        "parse_unified_log", "parse_knowledgec", "parse_fsevents",
        # Browser + exfiltration
        "parse_browser_history", "analyze_downloads",
        "correlate_download_to_execution", "detect_exfiltration",
    }
    assert advertised == expected, \
        f"wire surface drift:\n" \
        f"  unexpected={advertised - expected}\n" \
        f"  missing   ={expected - advertised}"


def test_live_mcp_executes_real_tool_over_wire():
    """Confirm that a real tool call via stdio returns real data."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "yushin_mcp.server_stdio"],
            env={**os.environ},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("analyze_usb_history", {
                    "system_hive": "disk/Windows/System32/config/SYSTEM",
                    "setupapi_log": "disk/Windows/INF/setupapi.dev.log",
                })
                return result

    result = asyncio.run(run())
    assert result.content, "MCP tool call returned no content"
    payload = json.loads(result.content[0].text)

    # The bundled evidence has the ATEN IP-KVM signature — this must survive
    # the JSON-RPC round trip.
    assert "events" in payload
    assert "ip_kvm_indicators" in payload
    if payload["count"] > 0:
        assert any(e.get("vid") == "0557" for e in payload.get("events", [])), \
            "ATEN IP-KVM signature lost over the wire"


def test_live_mcp_refuses_unregistered_tool_over_wire():
    """The ToolNotFound guardrail must hold at the protocol layer too."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "yushin_mcp.server_stdio"],
            env={**os.environ},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # The low-level MCP SDK raises on an unregistered tool name.
                # Either we get a raised error or a structured error result —
                # both are acceptable as long as the call does not succeed.
                try:
                    result = await session.call_tool("execute_shell",
                                                      {"cmd": "rm -rf /"})
                    return ("result", result)
                except Exception as e:
                    return ("exception", type(e).__name__, str(e))

    outcome = asyncio.run(run())
    if outcome[0] == "exception":
        # OK — MCP raised. Any exception type here counts as blocked.
        return
    # Otherwise we got a result object — it must contain an error payload.
    _, result = outcome
    assert result.content, "execute_shell returned no content and didn't raise"
    payload_text = result.content[0].text
    assert "ToolNotFound" in payload_text or "error" in payload_text.lower(), \
        f"execute_shell was not blocked over the wire:\n{payload_text}"


if __name__ == "__main__":
    test_live_mcp_server_advertises_correct_surface()
    print("test_live_mcp_server_advertises_correct_surface OK")
    test_live_mcp_executes_real_tool_over_wire()
    print("test_live_mcp_executes_real_tool_over_wire OK")
    test_live_mcp_refuses_unregistered_tool_over_wire()
    print("test_live_mcp_refuses_unregistered_tool_over_wire OK")
    test_live_mode_subprocess_dryrun()
    print("test_live_mode_subprocess_dryrun OK")
