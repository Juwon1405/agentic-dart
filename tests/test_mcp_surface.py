"""Tests for yushin-mcp: the agent attack surface is a hard-coded set."""
import sys
from pathlib import Path
SRC = Path(__file__).resolve().parents[1] / "yushin_mcp" / "src"
sys.path.insert(0, str(SRC))

from yushin_mcp import list_tools, call_tool


def test_registered_tools_are_exact_set():
    names = {t["name"] for t in list_tools()}
    expected = {"get_amcache", "analyze_usb_history", "extract_mft_timeline",
                "parse_prefetch", "list_scheduled_tasks", "correlate_events", "match_sigma_rules", "parse_evtx", "volatility_summary", "parse_knowledgec", "parse_fsevents", "parse_unified_log", "duckdb_timeline_correlate"}
    assert names == expected, f"surface drift: {names ^ expected}"


def test_destructive_functions_are_not_exposed():
    forbidden = ["execute_shell", "write_file", "mount", "umount",
                 "system", "eval", "network_egress", "delete_file"]
    names = {t["name"] for t in list_tools()}
    for f in forbidden:
        assert f not in names


def test_calling_unregistered_function_raises():
    try:
        call_tool("execute_shell", {"cmd": "rm -rf /"})
    except KeyError as e:
        assert "ToolNotFound" in str(e)
        return
    raise AssertionError("should have raised KeyError(ToolNotFound)")


if __name__ == "__main__":
    test_registered_tools_are_exact_set(); print("test_registered_tools_are_exact_set OK")
    test_destructive_functions_are_not_exposed(); print("test_destructive_functions_are_not_exposed OK")
    test_calling_unregistered_function_raises(); print("test_calling_unregistered_function_raises OK")
