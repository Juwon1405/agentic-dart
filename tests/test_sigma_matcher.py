"""Tests for yushin-mcp.match_sigma_rules — the 7th MCP function."""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "yushin_mcp" / "src"))
os.environ["YUSHIN_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")

from yushin_mcp import call_tool


def test_sigma_matcher_catches_ip_kvm():
    r = call_tool("match_sigma_rules", {
        "rule_dir":       "sigma-rules",
        "event_log_path": "event-logs/unified_events.jsonl",
    })
    assert r.get("rule_count", 0) >= 2, f"rules not loaded: {r}"
    assert r.get("event_count", 0) >= 5, f"events not loaded: {r}"
    matched_titles = {m["rule_title"] for m in r.get("matches", [])}
    assert "IP-KVM USB Device Insertion" in matched_titles, \
        f"IP-KVM rule did not fire: {matched_titles}"
    assert any("ATEN" in m["event"].get("device", "")
               for m in r["matches"]), "ATEN device not in matched event"


def test_sigma_matcher_catches_scheduled_task():
    r = call_tool("match_sigma_rules", {
        "rule_dir":       "sigma-rules",
        "event_log_path": "event-logs/unified_events.jsonl",
    })
    titles = {m["rule_title"] for m in r.get("matches", [])}
    assert "Scheduled Task Created Shortly After Unusual USB Insertion" in titles, \
        f"scheduled task rule did not fire: {titles}"


def test_sigma_matcher_ignores_legitimate_usb():
    r = call_tool("match_sigma_rules", {
        "rule_dir":       "sigma-rules",
        "event_log_path": "event-logs/unified_events.jsonl",
    })
    for m in r.get("matches", []):
        if m["rule_title"] == "IP-KVM USB Device Insertion":
            ev = m["event"]
            assert ev.get("vid") == "0557" and ev.get("pid") == "2419", \
                f"rule over-matched: {ev}"


if __name__ == "__main__":
    test_sigma_matcher_catches_ip_kvm()
    print("test_sigma_matcher_catches_ip_kvm OK")
    test_sigma_matcher_catches_scheduled_task()
    print("test_sigma_matcher_catches_scheduled_task OK")
    test_sigma_matcher_ignores_legitimate_usb()
    print("test_sigma_matcher_ignores_legitimate_usb OK")
