"""Tests for the extended surface added in the breadth/depth expansion:
  parse_evtx, volatility_summary, parse_knowledgec,
  parse_fsevents, parse_unified_log, duckdb_timeline_correlate,
  and the MCP stdio server (dart_mcp.server)."""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dart_mcp" / "src"))
os.environ["DART_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")

from dart_mcp import call_tool, list_tools


def test_parse_evtx_filters_by_event_id_and_window():
    r = call_tool("parse_evtx", {
        "evtx_path": "logs/security_sample.evtx",
        "event_ids": [4688, 4698],  # Process + Scheduled task creation
        "start": "2026-03-15 14:00:00",
        "end":   "2026-03-15 15:00:00",
    })
    assert r.get("total", 0) >= 2, f"expected >=2 matches, got {r}"
    ids = {it["event_id"] for it in r["items"]}
    assert 4688 in ids and 4698 in ids, f"missing expected event ids: {ids}"
    assert not any(it["event_id"] == 4663 for it in r["items"]), \
        "event_id filter not enforced"


def test_volatility_summary_surfaces_injection_and_c2():
    r = call_tool("volatility_summary", {"memdump_path": "memory/memdump.raw"})
    assert r.get("suggested_profile") == "Win10x64_19041"
    assert any(proc["injected"] for proc in r["injection_flags"]), \
        "injected process not surfaced"
    assert "192.0.2.88" in r["c2_candidate_ips"], \
        f"C2 candidate not extracted: {r.get('c2_candidate_ips')}"


def test_parse_knowledgec_decodes_cocoa_dates():
    r = call_tool("parse_knowledgec", {
        "db_path": "macos/KnowledgeC.db",
        "stream": "/app/usage",
    })
    assert r["count"] >= 3, f"expected >=3 app usage entries: {r}"
    for item in r["items"]:
        assert item["start"] and item["start"].startswith("20"), \
            f"cocoa date not decoded: {item}"
    apps = {it["value"] for it in r["items"]}
    assert "com.microsoft.rdc.macos" in apps, \
        f"RDC usage not surfaced (IR-relevant): {apps}"


def test_parse_fsevents_catches_launchagent_creation():
    r = call_tool("parse_fsevents", {
        "fsevents_csv": "macos/fsevents_sample.csv",
        "flag_contains": "ItemCreated",
    })
    created_paths = [it["path"] for it in r["items"]]
    assert any("/Library/LaunchAgents/" in p for p in created_paths), \
        f"LaunchAgent creation not caught: {created_paths}"


def test_parse_unified_log_filters_by_process():
    r = call_tool("parse_unified_log", {
        "log_csv": "macos/unified_log_sample.csv",
        "process": "Gatekeeper",
    })
    assert r["count"] == 1, f"process filter not exact: {r}"
    assert "disabled" in r["items"][0]["message"].lower()


def test_duckdb_correlate_joins_evtx_and_fsevents():
    r = call_tool("duckdb_timeline_correlate", {
        "sources": [
            {"name": "evtx",    "path": "logs/security_sample.evtx.csv",
             "time_column": "TimeCreated"},
            {"name": "fsevents", "path": "macos/fsevents_sample.csv",
             "time_column": "timestamp"},
        ],
        "window_seconds": 300,
    })
    assert r.get("pair_count", 0) > 0, f"DuckDB found no correlations: {r}"
    # A 4698 task registration at 14:22:03 + fsevent 14:22:50 -> 47s apart, should pair
    deltas = [p["delta_seconds"] for p in r["pairs"]]
    assert min(deltas) <= 300


def test_mcp_stdio_server_handles_initialize_and_tools_list():
    proc = subprocess.Popen(
        [sys.executable, "-m", "dart_mcp.server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(REPO), text=True,
        env={**os.environ,
             "PYTHONPATH": str(REPO / "dart_mcp" / "src"),
             "DART_EVIDENCE_ROOT": os.environ["DART_EVIDENCE_ROOT"]},
    )
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    tlist = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    out, err = proc.communicate(
        json.dumps(init) + "\n" + json.dumps(tlist) + "\n",
        timeout=10,
    )
    lines = [l for l in out.strip().split("\n") if l.strip()]
    assert len(lines) == 2, f"expected 2 responses, got {len(lines)}: {err}"
    init_resp = json.loads(lines[0])
    tools_resp = json.loads(lines[1])
    assert init_resp["result"]["serverInfo"]["name"] == "dart-mcp"
    tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
    # All 13 functions present: 7 from before + 6 new
    assert len(tool_names) == 13, f"expected 13 tools, got {tool_names}"
    for expected in ["get_amcache", "match_sigma_rules",
                     "parse_evtx", "volatility_summary",
                     "parse_knowledgec", "duckdb_timeline_correlate"]:
        assert expected in tool_names, f"{expected} missing from stdio server"


def test_mcp_stdio_server_refuses_unregistered_tool():
    proc = subprocess.Popen(
        [sys.executable, "-m", "dart_mcp.server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(REPO), text=True,
        env={**os.environ,
             "PYTHONPATH": str(REPO / "dart_mcp" / "src"),
             "DART_EVIDENCE_ROOT": os.environ["DART_EVIDENCE_ROOT"]},
    )
    bad = {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
           "params": {"name": "execute_shell", "arguments": {"cmd": "rm -rf /"}}}
    out, err = proc.communicate(json.dumps(bad) + "\n", timeout=10)
    resp = json.loads(out.strip().split("\n")[0])
    assert "error" in resp, f"destructive call not refused by stdio server: {resp}"
    assert "ToolNotFound" in resp["error"]["message"]


if __name__ == "__main__":
    for fn_name in [
        "test_parse_evtx_filters_by_event_id_and_window",
        "test_volatility_summary_surfaces_injection_and_c2",
        "test_parse_knowledgec_decodes_cocoa_dates",
        "test_parse_fsevents_catches_launchagent_creation",
        "test_parse_unified_log_filters_by_process",
        "test_duckdb_correlate_joins_evtx_and_fsevents",
        "test_mcp_stdio_server_handles_initialize_and_tools_list",
        "test_mcp_stdio_server_refuses_unregistered_tool",
    ]:
        globals()[fn_name]()
        print(f"{fn_name} OK")
