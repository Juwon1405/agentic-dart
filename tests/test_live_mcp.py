"""End-to-end test of live-mode MCP plumbing.

Does NOT require an ANTHROPIC_API_KEY. Runs in --dry-run which uses a
scripted mock-Claude that still calls the real dfir-mcp subprocess
over real MCP stdio JSON-RPC. This exercises:

  1. Subprocess spawn of `python -m dfir_mcp.server_stdio`
  2. MCP initialize() handshake
  3. list_tools() over the wire — verifies all 73 functions are advertised
     (48 native + 25 SIFT Workstation adapters)
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
sys.path.insert(0, str(REPO / "dfir_mcp" / "src"))
sys.path.insert(0, str(REPO / "dfir_audit" / "src"))
sys.path.insert(0, str(REPO / "dfir_agent" / "src"))
os.environ["DFIR_EVIDENCE_ROOT"] = str(REPO / "tests" / "fixtures" / "evidence")
_existing_pythonpath = os.environ.get("PYTHONPATH")
_repo_pythonpath = os.pathsep.join([
    str(REPO / "dfir_mcp" / "src"),
    str(REPO / "dfir_audit" / "src"),
    str(REPO / "dfir_agent" / "src"),
    str(REPO / "dfir_corr" / "src"),
])
os.environ["PYTHONPATH"] = (
    _repo_pythonpath if not _existing_pythonpath
    else os.pathsep.join([_repo_pythonpath, _existing_pythonpath])
)


def test_live_mode_subprocess_dryrun():
    """Run `dfir-agent --mode live --dry-run` end-to-end."""
    with tempfile.TemporaryDirectory() as td:
        result = subprocess.run(
            [sys.executable, "-m", "dfir_agent",
             "--mode", "live", "--case", "live-test",
             "--out", td, "--dry-run", "--max-iterations", "5"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, \
            f"live mode failed: rc={result.returncode}\nstderr:{result.stderr}"

        # Check stderr for handshake banner
        assert "MCP handshake OK" in result.stderr, \
            f"MCP handshake banner missing:\n{result.stderr}"
        assert "tools visible" in result.stderr, \
            f"Expected tool surface to be enumerated over the wire:\n{result.stderr}"

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


def test_dryrun_mock_does_not_emit_uncorroborated_finding():
    """The scripted mock must not claim a finding the tools did not support."""
    from dfir_agent.live import LiveRunState, _run_with_mock_claude

    class Content:
        def __init__(self, text: str):
            self.text = text

    class Result:
        def __init__(self, payload: dict):
            self.content = [Content(json.dumps(payload))]

    class NoCorrelationSession:
        async def call_tool(self, name, args):
            if name == "analyze_usb_history":
                return Result({"ip_kvm_indicators": [{"vid": "0557", "pid": "2419"}]})
            if name == "correlate_timeline":
                return Result({"kvm_precedes_logon": []})
            return Result({})

    with tempfile.TemporaryDirectory() as td:
        state = LiveRunState(case="dryrun-no-corr", out_dir=Path(td), max_iterations=4)
        transcript = asyncio.run(_run_with_mock_claude("prompt", state, NoCorrelationSession()))

        assert state.findings == []
        assert "No dry-run finding emitted" in transcript


def test_live_mcp_server_advertises_correct_surface():
    """Spawn dfir-mcp stdio server and call list_tools() over the wire.

    This is the guardrail-over-wire check: the protocol surface must match
    the in-process _REGISTRY exactly. Any drift fails this test.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "dfir_mcp.server_stdio"],
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
        # Authentication & lateral movement
        "analyze_windows_logons", "detect_lateral_movement",
        "analyze_kerberos_events", "analyze_unix_auth",
        "detect_privilege_escalation",
        # Web/WAS + RDP brute force (initial access vectors)
        "analyze_web_access_log", "detect_webshell",
        "detect_brute_force_rdp",
        # MITRE ATT&CK gap-fillers (credentials, ransomware, evasion, discovery)
        "detect_credential_access", "detect_ransomware_behavior",
        "detect_defense_evasion", "detect_discovery",
        # v0.4 Linux + macOS expansion
        "parse_auditd_log", "parse_systemd_journal", "parse_bash_history", "parse_launchd_plist",
        # v0.5.4 generic registry hive parsing (closes CFReDS gap G-001 / issue #52)
        "parse_registry_hive",
        # v0.5 SIFT Workstation tool adapters (Custom MCP Server pattern)
        "sift_vol3_windows_pslist", "sift_vol3_windows_pstree",
        "sift_vol3_windows_psscan", "sift_vol3_windows_cmdline",
        "sift_vol3_windows_netscan", "sift_vol3_windows_malfind",
        "sift_vol3_windows_dlllist", "sift_vol3_windows_svcscan",
        "sift_vol3_windows_runkey", "sift_vol3_linux_pslist",
        "sift_vol3_linux_bash", "sift_vol3_mac_bash",
        "sift_mftecmd_parse", "sift_mftecmd_timestomp",
        "sift_evtxecmd_parse", "sift_evtxecmd_filter_eids",
        "sift_pecmd_parse", "sift_pecmd_run_history",
        "sift_recmd_run_batch", "sift_recmd_query_key",
        "sift_amcacheparser_parse",
        "sift_yara_scan_file", "sift_yara_scan_dir",
        "sift_plaso_log2timeline", "sift_plaso_psort",
        # v0.5 supply-chain attack IOC sweeps
        "scan_pth_files_for_supply_chain_iocs",
        "detect_pypi_typosquatting",
        "detect_nodejs_install_hooks",
        "detect_python_backdoor_persistence",
        "detect_credential_file_access",
        "grep_shell_history_for_c2",
        # v0.6.1 macOS quarantine + Linux cron + DNS tunneling
        "parse_macos_quarantine",
        "parse_linux_cron_jobs",
        "detect_dns_tunneling",
        # v0.7.0 Linux DFIR triplet (parse_linux_cron_jobs already counted above)
        "parse_linux_text_log",
        "parse_linux_shell_history",
        # v0.7 Sigma detection-rule matcher.
        "match_sigma_rules",
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
            args=["-m", "dfir_mcp.server_stdio"],
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
            args=["-m", "dfir_mcp.server_stdio"],
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
