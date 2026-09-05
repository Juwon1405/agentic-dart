"""Tests for match_sigma_rules — the consolidated Sigma pack matcher (v0.7).

These run against the real dfir_sigma/ pack and a small synthetic event log, so
they exercise rule loading, the condition evaluator, and the |contains modifier
without depending on any case's evidence.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dfir_mcp" / "src"))

import dfir_mcp  # noqa: E402


def _run(tmp_path, events, monkeypatch):
    """Write events to a JSONL under a temp evidence root and run the matcher.

    Patch EVIDENCE_ROOT in place (no module reload — reload would un-register
    the @tool decorators from the submodules).
    """
    log = tmp_path / "events.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in events))
    monkeypatch.setattr(dfir_mcp, "EVIDENCE_ROOT", tmp_path)
    return dfir_mcp.call_tool("match_sigma_rules",
                              {"event_log_path": "events.jsonl"})


def test_pack_loads_and_reports_version(tmp_path, monkeypatch):
    r = _run(tmp_path, [{"event_type": "noop"}], monkeypatch)
    # Read the expected version from the manifest so a pack bump (v1 -> v2 -> …)
    # never breaks this test: assert the matcher reports what pack.yml declares.
    _manifest = (REPO / "dfir_sigma" / "pack.yml").read_text()
    _expected = next((l.split(":", 1)[1].strip()
                      for l in _manifest.splitlines() if l.startswith("version:")), None)
    assert r.get("pack_version") == _expected, r
    assert r.get("rule_count", 0) >= 4, f"pack rules not loaded: {r}"


def test_hid_keyboard_insertion_fires_t1200(tmp_path, monkeypatch):
    # A keyboard-class USB insertion (IP-KVM / BadUSB presents as HID keyboard).
    events = [
        {"event_type": "usb_insert",
         "device_class_guid": "{4d36e96b-e325-11ce-bfc1-08002be10318}",
         "device_description": "Generic USB Keyboard"},
    ]
    r = _run(tmp_path, events, monkeypatch)
    titles = {m["rule_title"] for m in r.get("matches", [])}
    assert any("HID" in t for t in titles), f"HID rule did not fire: {r}"
    tags = [t for m in r["matches"] for t in m["mitre"]]
    assert "attack.t1200" in tags, f"T1200 not tagged: {tags}"


def test_storage_usb_does_not_fire_hid_rule(tmp_path, monkeypatch):
    # A mass-storage USB insertion is NOT a keyboard — HID rule must stay silent.
    events = [
        {"event_type": "usb_insert",
         "device_class_guid": "{36fc9e60-c465-11cf-8056-444553540000}",
         "device_description": "SanDisk Cruzer USB Device"},
    ]
    r = _run(tmp_path, events, monkeypatch)
    titles = {m["rule_title"] for m in r.get("matches", [])}
    assert not any("HID" in t for t in titles), \
        f"HID rule fired on storage device (false positive): {titles}"


def test_suspicious_scheduled_task_fires(tmp_path, monkeypatch):
    events = [
        {"event_type": "task_registration",
         "task_command": "powershell.exe",
         "task_arguments": "-enc SQBFAFgA"},
    ]
    r = _run(tmp_path, events, monkeypatch)
    tags = [t for m in r.get("matches", []) for t in m["mitre"]]
    assert "attack.t1053.005" in tags, f"scheduled-task rule did not fire: {r}"


def test_kerberoasting_rc4_tgs_fires(tmp_path, monkeypatch):
    events = [
        {"EventID": 4769, "TicketEncryptionType": "0x17",
         "ServiceName": "MSSQLSvc/SQL01.corp.local"},
    ]
    r = _run(tmp_path, events, monkeypatch)
    tags = [t for m in r.get("matches", []) for t in m["mitre"]]
    assert "attack.t1558.003" in tags, f"kerberoasting rule did not fire: {r}"


def test_missing_log_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(dfir_mcp, "EVIDENCE_ROOT", tmp_path)
    r = dfir_mcp.call_tool("match_sigma_rules",
                           {"event_log_path": "nope.jsonl"})
    assert r.get("error") == "file_not_found", r
