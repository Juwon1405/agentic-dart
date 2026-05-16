"""Unit tests for the v0.7.0 Linux DFIR triplet:
- parse_linux_text_log
- parse_linux_shell_history
(parse_linux_cron_jobs is the v0.6.1 implementation and has its own coverage.)
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dart_mcp" / "src"))
os.environ["DART_EVIDENCE_ROOT"] = str(ROOT / "examples" / "sample-evidence-realistic")

from dart_mcp import call_tool  # noqa: E402
import dart_mcp as _dm  # noqa: E402

# Monkey-patch EVIDENCE_ROOT in case another test imported dart_mcp first
# with a different DART_EVIDENCE_ROOT (the module reads env at line 45 of
# __init__.py only once, so a later test cannot override via env alone).
# Affects only this test module's call_tool invocations.
_dm.EVIDENCE_ROOT = Path(os.environ["DART_EVIDENCE_ROOT"])


# ─── parse_linux_text_log ─────────────────────────────────────────

def test_parse_linux_text_log_auditd_fixture():
    """Auditd dispatcher text mode — sample evidence ships with the right shape."""
    r = call_tool("parse_linux_text_log", {"log_path": "linux/auditd_sample.txt"})
    assert "error" not in r, r
    assert r["lines_examined"] >= 12
    assert r["records_parsed"] >= 12
    assert r["formats"].get("auditd", 0) >= 12
    # /etc/shadow read should fire sensitive_file_access
    rules = {h["rule"] for h in r["suspicious_hits"]}
    assert "sensitive_file_access" in rules
    assert r["max_severity"] in ("high", "critical")


def test_parse_linux_text_log_missing_file():
    r = call_tool("parse_linux_text_log", {"log_path": "linux/this-does-not-exist.log"})
    assert r.get("error") == "file_not_found"


def test_parse_linux_text_log_http_access_format(tmp_path, monkeypatch):
    """Apache combined log shape — must parse src/method/uri/status."""
    log = ROOT / "examples" / "sample-evidence-realistic" / "linux" / "_pytest_http.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        '10.0.0.1 - - [15/Mar/2026:14:15:08 +0900] "GET /admin/../../etc/passwd HTTP/1.1" 200 4096 "-" "Nikto/2.1.6"\n'
        '10.0.0.2 - alice [15/Mar/2026:14:16:30 +0900] "POST /login HTTP/1.1" 401 234 "https://example.com" "Mozilla/5.0"\n'
    )
    try:
        r = call_tool("parse_linux_text_log", {"log_path": "linux/_pytest_http.log"})
        assert "error" not in r
        assert r["records_parsed"] == 2
        assert r["formats"].get("http_access") == 2
        rules = {h["rule"] for h in r["suspicious_hits"]}
        # 1st line has both ../etc/passwd traversal + Nikto UA + /etc/passwd
        assert "path_traversal_attempt" in rules
        assert "sensitive_file_access" in rules
        assert "scanner_user_agent" in rules
    finally:
        log.unlink(missing_ok=True)


# ─── parse_linux_shell_history ────────────────────────────────────

def test_parse_linux_shell_history_with_timestamps():
    """Bundled bash_history uses HISTTIMEFORMAT — timestamps must surface."""
    r = call_tool("parse_linux_shell_history", {"history_path": "linux/bash_history"})
    assert "error" not in r, r
    assert r["total_commands"] >= 10
    assert r["has_timestamps"] is True
    # Suspicious patterns we deliberately seeded
    rules = {h["rule"] for h in r["suspicious_hits"]}
    assert "sensitive_file_read" in rules
    assert "background_exec_from_world_writable" in rules
    assert "ssh_key_persistence" in rules
    assert "shell_history_cleared" in rules
    assert r["max_severity"] in ("high", "critical")


def test_parse_linux_shell_history_missing_file():
    r = call_tool("parse_linux_shell_history",
                  {"history_path": "linux/nonexistent_history"})
    assert r.get("error") == "file_not_found"


def test_parse_linux_shell_history_each_entry_has_required_keys():
    r = call_tool("parse_linux_shell_history", {"history_path": "linux/bash_history"})
    for h in r["suspicious_hits"][:5]:
        for key in ("rule", "technique", "severity", "command", "line"):
            assert key in h, f"hit missing {key}: {h}"


# ─── path safety (the v0.6.1 wall must still hold) ────────────────

def test_parse_linux_text_log_path_traversal_rejected():
    """Should refuse paths that escape DART_EVIDENCE_ROOT."""
    os.environ["DART_EVIDENCE_ROOT"] = str(ROOT / "examples" / "sample-evidence-realistic")
    from dart_mcp import PathTraversalAttempt, call_tool as _ct
    try:
        _ct("parse_linux_text_log", {"log_path": "../../../../../etc/passwd"})
    except PathTraversalAttempt:
        return
    except Exception as exc:
        # Some pipelines wrap traversal in a generic error result
        if isinstance(exc, Exception) and "escapes evidence root" in str(exc):
            return
        raise
    raise AssertionError("path traversal should have been rejected")
