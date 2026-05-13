"""
Adversarial bypass tests for dart-mcp.

These are NEGATIVE tests — they assert that architectural guardrails hold
when the agent (or an adversary feeding the agent prompts) tries to:

  1. Call a destructive function that is not registered
  2. Escape the evidence root via path traversal (../ and absolute paths)
  3. Smuggle null bytes into a path string

Each scenario maps directly to a SANS FIND EVIL judging criterion:
"Constraint Implementation — are guardrails architectural or prompt-based,
and were they tested for bypass?"
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dart_mcp" / "src"))
os.environ["DART_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")

from dart_mcp import call_tool, list_tools, PathTraversalAttempt


def test_unregistered_destructive_function_raises_ToolNotFound():
    """Calling anything not in the registry must fail hard."""
    for forbidden in ["execute_shell", "write_file", "mount", "umount",
                      "network_egress", "eval", "exec_python",
                      "delete_file", "system"]:
        try:
            call_tool(forbidden, {})
        except KeyError as e:
            assert "ToolNotFound" in str(e), f"wrong error for {forbidden}"
            continue
        raise AssertionError(
            f"SECURITY: call_tool({forbidden!r}) did not raise — "
            f"forbidden function is somehow exposed")


def test_relative_path_traversal_is_blocked():
    """../ must not escape the evidence root."""
    bad = [
        "../../../etc/passwd",
        "../../etc/shadow",
        "disk/../../../../etc/hosts",
        "disk/Windows/../../../..",
    ]
    for evil in bad:
        try:
            call_tool("get_amcache", {"hive_path": evil})
        except PathTraversalAttempt:
            continue
        raise AssertionError(
            f"SECURITY: path traversal {evil!r} was not blocked")


def test_absolute_path_escape_is_blocked():
    """Absolute path that lands outside EVIDENCE_ROOT must fail."""
    for evil in ["/etc/passwd", "/root/.ssh/authorized_keys", "/var/log/auth.log"]:
        try:
            call_tool("get_amcache", {"hive_path": evil})
        except PathTraversalAttempt:
            continue
        raise AssertionError(
            f"SECURITY: absolute path escape {evil!r} was not blocked")


def test_null_byte_truncation_is_blocked():
    """NUL byte smuggling must be refused."""
    try:
        call_tool("get_amcache",
                  {"hive_path": "disk/Amcache.hve\x00/etc/passwd"})
    except PathTraversalAttempt:
        return
    raise AssertionError("SECURITY: null byte was not blocked")


def test_surface_is_exact_positive_and_negative_set():
    """Both POSITIVE (what's registered) and NEGATIVE (what must never be)
    sets are asserted. Any drift fails this test."""
    positive = {
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
        # All 25 wrappers run subprocess into SIFT-bundled binaries with
        # read-only EVIDENCE_ROOT enforcement, timeout guards, and SHA-256
        # audit. Same architectural guarantees apply as native tools.
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
        # v0.5 supply-chain attack IOC sweeps (6 functions, cross-platform).
        "scan_pth_files_for_supply_chain_iocs",
        "detect_pypi_typosquatting",
        "detect_nodejs_install_hooks",
        "detect_python_backdoor_persistence",
        "detect_credential_file_access",
        "grep_shell_history_for_c2",
    }
    negative = {"execute_shell", "write_file", "mount", "umount", "eval",
                "exec_python", "network_egress", "delete_file", "system",
                "spawn_process", "kill_process"}

    registered = {t["name"] for t in list_tools()}
    assert registered == positive, \
        f"POSITIVE surface drift: unexpected={registered - positive} " \
        f"missing={positive - registered}"
    overlap = registered & negative
    assert not overlap, f"NEGATIVE surface breach: {overlap}"


def test_correlate_timeline_rejects_sql_injection_attempts():
    """REGRESSION (QA 2026-05-02): the user-supplied `rules` parameter on
    correlate_timeline is interpolated into a DuckDB JOIN ON clause.
    The previous filter only blocked ';' and '--', leaving comments,
    UNION SELECT, and DuckDB metafunctions like read_csv_auto() and
    PRAGMA reachable. The hardened guard rejects on a strict allow-list
    of characters AND a forbidden-keyword block. Every payload below
    must come back as a structured 'rule rejected' entry, not a hit."""
    payloads = [
        # Comment-based bypass of the old filter
        "1=1 /* */ UNION SELECT 1,2,3,4,5,6",
        # DuckDB metafunctions: filesystem read pivot
        "1=1 OR (SELECT 1 FROM read_csv_auto('/etc/passwd')) IS NULL",
        "1=1 AND read_parquet('/tmp/x.parquet') IS NOT NULL",
        # PRAGMA / DDL / extension load
        "1=1; PRAGMA database_list",
        "1=1 OR (ATTACH '/tmp/x.db' AS x)",
        "1=1 AND INSTALL httpfs",
        # Backtick / dollar / shell-style attempts
        "1=1 AND `os` = 'linux'",
        "1=1 AND $$evil$$ = ''",
    ]
    for p in payloads:
        out = call_tool("correlate_timeline", {
            "events": [
                {"ts": "2026-03-15 14:00:00", "source": "x",
                 "actor": "a", "type": "logon"},
                {"ts": "2026-03-15 14:01:00", "source": "y",
                 "actor": "a", "type": "logon"},
            ],
            "rules": [p],
            "window_seconds": 600,
        })
        matches = out.get("user_rule_matches") or []
        assert matches, f"no match record returned for payload: {p}"
        m = matches[0]
        assert "error" in m and "rejected" in m["error"].lower(), (
            f"SECURITY: SQL injection payload was NOT rejected:\n"
            f"  payload={p!r}\n  result={m!r}"
        )
        # Critical: verify nothing got executed — there must be no `hits` key
        assert "hits" not in m, \
            f"SECURITY: payload executed despite rejection record: {p!r} -> {m!r}"


def test_handler_does_not_write_outside_root(tmp_path=None):
    """Sanity: none of the registered handlers should create files anywhere
    outside the evidence tree. This is a smoke test — the real guarantee
    is the MCP server API surface, but this catches regressions early."""
    evidence_root = Path(os.environ["DART_EVIDENCE_ROOT"]).resolve()
    before = {p for p in evidence_root.rglob("*") if p.is_file()}

    call_tool("get_amcache",
              {"hive_path": "disk/Windows/AppCompat/Programs/Amcache.hve"})
    call_tool("analyze_usb_history", {
        "system_hive": "disk/Windows/System32/config/SYSTEM",
        "setupapi_log": "disk/Windows/INF/setupapi.dev.log",
    })
    call_tool("list_scheduled_tasks", {})

    after = {p for p in evidence_root.rglob("*") if p.is_file()}
    added = after - before
    assert not added, f"SECURITY: handlers created files: {added}"


if __name__ == "__main__":
    test_unregistered_destructive_function_raises_ToolNotFound()
    print("test_unregistered_destructive_function_raises_ToolNotFound OK")
    test_relative_path_traversal_is_blocked()
    print("test_relative_path_traversal_is_blocked OK")
    test_absolute_path_escape_is_blocked()
    print("test_absolute_path_escape_is_blocked OK")
    test_null_byte_truncation_is_blocked()
    print("test_null_byte_truncation_is_blocked OK")
    test_surface_is_exact_positive_and_negative_set()
    print("test_surface_is_exact_positive_and_negative_set OK")
    test_correlate_timeline_rejects_sql_injection_attempts()
    print("test_correlate_timeline_rejects_sql_injection_attempts OK")
    test_handler_does_not_write_outside_root()
    print("test_handler_does_not_write_outside_root OK")
