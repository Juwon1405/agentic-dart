"""Tests for dart_corr — the extracted correlation engine.

These exercise dart_corr in isolation, without dart_mcp wrapping.
Same inputs as the dart_mcp surface tests must produce identical
outputs (the dart_mcp wrappers are thin pass-throughs)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import dart_corr  # noqa: E402


# ─── correlate_events ─────────────────────────────────────────────────────

def test_correlate_events_flags_ip_kvm_before_logon():
    usb = [{"ts": "2026-04-29T14:20:00", "is_ip_kvm": True,
            "device": "VendorX KVM"}]
    logon = [{"ts": "2026-04-29T14:22:30", "user": "alice", "type": 2}]
    r = dart_corr.correlate_events("h_001", usb, logon, proximity_seconds=600)
    assert r["hypothesis_id"] == "h_001"
    assert r["usb_event_count"] == 1
    assert r["logon_event_count"] == 1
    assert len(r["contradictions"]) == 1
    c = r["contradictions"][0]
    assert c["rule"] == "ip_kvm_precedes_logon"
    assert c["status"] == "UNRESOLVED"
    assert c["delta_seconds"] == 150


def test_correlate_events_ignores_non_ip_kvm_usb():
    usb = [{"ts": "2026-04-29T14:20:00", "is_ip_kvm": False,
            "device": "SanDisk USB drive"}]
    logon = [{"ts": "2026-04-29T14:22:30", "user": "alice"}]
    r = dart_corr.correlate_events("h_002", usb, logon)
    assert r["contradictions"] == []


def test_correlate_events_respects_proximity_window():
    usb = [{"ts": "2026-04-29T14:00:00", "is_ip_kvm": True}]
    logon = [{"ts": "2026-04-29T14:30:00", "user": "bob"}]
    r = dart_corr.correlate_events("h_003", usb, logon, proximity_seconds=600)
    # 30 min apart > 10 min window → no flag
    assert r["contradictions"] == []


def test_correlate_events_handles_malformed_timestamps():
    usb = [{"ts": "not-a-date", "is_ip_kvm": True}]
    logon = [{"ts": "2026-04-29T14:22:30"}]
    r = dart_corr.correlate_events("h_004", usb, logon)
    # malformed input drops silently — does not crash
    assert r["contradictions"] == []


# ─── correlate_timeline ───────────────────────────────────────────────────

def test_correlate_timeline_empty_input():
    r = dart_corr.correlate_timeline([])
    assert r["normalized_event_count"] == 0
    assert r["correlations"] == []
    assert r["contradictions"] == []


def test_correlate_timeline_finds_cross_source_actor_match():
    events = [
        {"ts": "2026-04-29T14:23:09", "source": "evtx_security",
         "actor": "alice", "type": "logon_4624"},
        {"ts": "2026-04-29T14:23:12", "source": "mft_journal",
         "actor": "alice", "type": "file_create",
         "target": "C:/Users/alice/Documents/payload.dll"},
    ]
    r = dart_corr.correlate_timeline(events, window_seconds=60)
    assert r["normalized_event_count"] == 2
    # Cross-source actor match in 3-second window
    assert len(r["correlations"]) >= 1
    # Different types on same actor → contradiction
    assert len(r["contradictions"]) >= 1
    c = r["contradictions"][0]
    assert c["actor"] == "alice"
    assert c["status"] == "UNRESOLVED"


def test_correlate_timeline_no_match_outside_window():
    events = [
        {"ts": "2026-04-29T14:00:00", "source": "a", "actor": "x",
         "type": "t1"},
        {"ts": "2026-04-29T14:30:00", "source": "b", "actor": "x",
         "type": "t2"},
    ]
    r = dart_corr.correlate_timeline(events, window_seconds=60)
    # 30 min apart, 60s window → no correlation
    assert r["correlations"] == []
    assert r["contradictions"] == []


# ─── correlate_download_to_execution ──────────────────────────────────────

def test_correlate_download_to_execution_corroborates_match():
    downloads = [{"ts": "2026-04-29T10:00:00",
                  "path": "C:/Users/alice/Downloads/invoice.exe"}]
    executions = [{"ts": "2026-04-29T10:05:00",
                   "image": "C:/Users/alice/Downloads/invoice.exe"}]
    r = dart_corr.correlate_download_to_execution(downloads, executions)
    assert r["execution_count"] == 1
    assert len(r["corroborated"]) == 1
    assert r["corroborated"][0]["status"] == "CORROBORATED"
    assert r["corroborated"][0]["delta_seconds"] == 300
    assert r["revision_required"] is False


def test_correlate_download_to_execution_flags_uncorroborated():
    downloads = []  # no download record
    executions = [{"ts": "2026-04-29T10:05:00",
                   "image": "C:/Windows/System32/cmd.exe"}]
    r = dart_corr.correlate_download_to_execution(downloads, executions)
    assert len(r["uncorroborated"]) == 1
    u = r["uncorroborated"][0]
    assert "no matching download" in u["status"]
    # Agent must revise the 'malicious download' hypothesis
    assert r["revision_required"] is True


def test_correlate_download_to_execution_basename_match():
    """When the execution path doesn't exactly equal the download path
    but the basenames match (LOLBin copied/renamed), still corroborate."""
    downloads = [{"ts": "2026-04-29T10:00:00",
                  "path": "C:/Users/alice/Downloads/dropper.exe"}]
    executions = [{"ts": "2026-04-29T10:05:00",
                   "image": "C:/Temp/dropper.exe"}]
    r = dart_corr.correlate_download_to_execution(downloads, executions)
    assert len(r["corroborated"]) == 1


# ─── Rule pack loader ─────────────────────────────────────────────────────

def test_load_rules_returns_built_in_pack():
    r = dart_corr.load_rules()
    # correlation-rules.yaml is shipped alongside the package
    assert "rules" in r
    assert isinstance(r["rules"], list)
    # Must have at least the ip_kvm_precedes_logon rule
    names = [rule.get("name") for rule in r["rules"]]
    assert "ip_kvm_precedes_logon" in names


def test_load_rules_handles_missing_file():
    r = dart_corr.load_rules(Path("/nonexistent/path/rules.yaml"))
    assert r["rules"] == []


# ─── Module-level invariants ──────────────────────────────────────────────

def test_dart_corr_version_matches_repo():
    # Package version is the same as the repo release (v0.7.1)
    assert dart_corr.__version__ == "0.7.1"


def test_public_api_surface_is_complete():
    expected = {
        "correlate_events",
        "correlate_timeline",
        "correlate_download_to_execution",
        "load_rules",
        "__version__",
    }
    assert expected.issubset(set(dart_corr.__all__))


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
