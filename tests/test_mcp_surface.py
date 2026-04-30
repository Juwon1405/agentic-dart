"""Tests for dart-mcp: the agent attack surface is a hard-coded set."""
import sys
from pathlib import Path
SRC = Path(__file__).resolve().parents[1] / "dart_mcp" / "src"
sys.path.insert(0, str(SRC))

from dart_mcp import list_tools, call_tool


def test_registered_tools_are_exact_set():
    names = {t["name"] for t in list_tools()}
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
        # Browser + exfiltration (infection vector + data loss)
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
    }
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
