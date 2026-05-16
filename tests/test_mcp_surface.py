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
        # v0.4 Linux + macOS expansion
        "parse_auditd_log", "parse_systemd_journal", "parse_bash_history", "parse_launchd_plist",
        # v0.5.4 generic registry hive parsing (closes CFReDS gap G-001 / issue #52)
        "parse_registry_hive",
        # v0.5 SIFT Workstation tool adapters (Custom MCP Server pattern)
        # volatility3 (12)
        "sift_vol3_windows_pslist", "sift_vol3_windows_pstree",
        "sift_vol3_windows_psscan", "sift_vol3_windows_cmdline",
        "sift_vol3_windows_netscan", "sift_vol3_windows_malfind",
        "sift_vol3_windows_dlllist", "sift_vol3_windows_svcscan",
        "sift_vol3_windows_runkey", "sift_vol3_linux_pslist",
        "sift_vol3_linux_bash", "sift_vol3_mac_bash",
        # Eric Zimmerman tools (7)
        "sift_mftecmd_parse", "sift_mftecmd_timestomp",
        "sift_evtxecmd_parse", "sift_evtxecmd_filter_eids",
        "sift_pecmd_parse", "sift_pecmd_run_history",
        "sift_recmd_run_batch", "sift_recmd_query_key",
        "sift_amcacheparser_parse",
        # YARA (2)
        "sift_yara_scan_file", "sift_yara_scan_dir",
        # Plaso (2)
        "sift_plaso_log2timeline", "sift_plaso_psort",
        # v0.5 supply-chain attack IOC sweeps (6 functions, cross-platform).
        # Ported and generalized from yushin-mac-artifact-collector. Covers the
        # litellm PyPI supply-chain attack (2026-03) pattern and generalizes
        # to npm typosquat / preinstall hook abuse / credential exfiltration.
        "scan_pth_files_for_supply_chain_iocs",
        "detect_pypi_typosquatting",
        "detect_nodejs_install_hooks",
        "detect_python_backdoor_persistence",
        "detect_credential_file_access",
        "grep_shell_history_for_c2",
        # v0.6.1 macOS quarantine + Linux cron + DNS tunneling (3 functions).
        # Adds T1204 download provenance (Sarah Edwards QuarantineV2 schema),
        # T1053.003 cron enumeration with attacker-pattern flagging, and
        # TA0011/T1071.004 DNS C2 detection (Iodine/dnscat2 signatures +
        # entropy + volume heuristics).
        "parse_macos_quarantine",
        "parse_linux_cron_jobs",
        "detect_dns_tunneling",
        # v0.7.0 Linux DFIR triplet for case-09 (Hadi Challenge 1) coverage.
        # parse_linux_text_log handles apache/nginx access, syslog, messages,
        # auditd dispatcher text; parse_linux_shell_history covers bash/zsh
        # with HISTTIMEFORMAT awareness. parse_linux_cron_jobs already lives
        # in v0.6.1 module above. Closes 5 of 7 case-09 ground-truth gaps.
        "parse_linux_text_log",
        "parse_linux_shell_history",
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
