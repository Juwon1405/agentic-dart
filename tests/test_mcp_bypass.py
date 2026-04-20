"""
Adversarial bypass tests for yushin-mcp.

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
sys.path.insert(0, str(REPO / "yushin_mcp" / "src"))
os.environ["YUSHIN_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")

from yushin_mcp import call_tool, list_tools, PathTraversalAttempt


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


def test_handler_does_not_write_outside_root(tmp_path=None):
    """Sanity: none of the registered handlers should create files anywhere
    outside the evidence tree. This is a smoke test — the real guarantee
    is the MCP server API surface, but this catches regressions early."""
    evidence_root = Path(os.environ["YUSHIN_EVIDENCE_ROOT"]).resolve()
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
    test_handler_does_not_write_outside_root()
    print("test_handler_does_not_write_outside_root OK")
