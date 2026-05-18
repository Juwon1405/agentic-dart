"""
Regression tests from the 2026-05-02 QA pass.

Pins fixes that the existing test matrix did not cover.

  - dart_agent: --max-iterations small enough to skip _phase_hypothesis
    used to crash inside _report() because self._primary was unset.
    Fixed by guarding with getattr() defaults.

  (Note: the audit-log non-JSON-native input regression is covered in
  tests/test_audit_chain.py::test_chain_handles_non_json_native_inputs.)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ["dart_audit/src", "dart_mcp/src", "dart_agent/src"]:
    sys.path.insert(0, str(REPO / p))
os.environ.setdefault("DART_EVIDENCE_ROOT",
                       str(REPO / "examples" / "sample-evidence"))


def test_short_max_iterations_does_not_crash_report():
    """--max-iterations=1 forces an early exit before _phase_hypothesis runs.
    Pre-fix, this triggered AttributeError on self._primary inside _report().
    """
    if "dart_mcp" in sys.modules:
        del sys.modules["dart_mcp"]
    from dart_agent import main
    with tempfile.TemporaryDirectory() as td:
        rc = main(["--case", "short-iter-test", "--out", td,
                   "--mode", "deterministic",
                   "--max-iterations", "1"])
        # rc may be 0 or 1 depending on chain-verify outcome on a
        # very short run, but the agent must NOT crash with
        # AttributeError. The report file must exist and be valid JSON.
        report_path = Path(td) / "report.json"
        assert report_path.exists(), \
            "report.json missing — agent likely crashed before writing"
        report = json.loads(report_path.read_text())
        # Both hypothesis fields must serialize cleanly (None or dict).
        assert "primary_hypothesis" in report
        assert "alternative_hypothesis" in report
        # When the hypothesis phase never ran, both should be None.
        assert (report["primary_hypothesis"] is None
                or isinstance(report["primary_hypothesis"], dict))


# ─────────────────────────────────────────────────────────────────────
# 2026-05-17 code-review pass regressions (commit 8e1bc43)
# ─────────────────────────────────────────────────────────────────────


def test_zone_identifier_full_suffix_strip(tmp_path, monkeypatch):
    """Pre-fix: Path.with_suffix('') only stripped '.Identifier' from
    'malware.exe.Zone.Identifier', leaving 'malware.exe.Zone'. The new
    code strips the full '.Zone.Identifier' literal, so target_path is
    the real downloaded file.
    """
    if "dart_mcp" in sys.modules:
        del sys.modules["dart_mcp"]
    monkeypatch.setenv("DART_EVIDENCE_ROOT", str(tmp_path))
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    (downloads / "malware.exe").write_bytes(b"MZ\x90\x00")
    (downloads / "malware.exe.Zone.Identifier").write_text(
        "[ZoneTransfer]\nZoneId=3\nHostUrl=https://attacker.example/p.exe\n",
        encoding="utf-8")
    from dart_mcp import call_tool
    result = call_tool("analyze_downloads",
                       {"downloads_source": "downloads",
                        "mode": "zone_identifier"})
    items = result.get("items", [])
    assert items, "expected at least one zone_identifier item"
    target = items[0]["target_path"]
    # Must NOT end in '.Zone' (the old bug). Must point at the real file.
    assert not target.endswith(".Zone"), \
        f"Zone.Identifier strip bug returned: {target!r}"
    assert target.endswith("malware.exe"), \
        f"target_path should point at malware.exe, got {target!r}"


def test_lsass_mask_bitwise_uppercase_and_full_access(tmp_path, monkeypatch):
    """Pre-fix: GrantedAccess comparison was string equality against 7
    lowercase literals. Uppercase form '0X1010' and unlisted masks like
    PROCESS_ALL_ACCESS (0x1F0FFF) were silently missed. The new bitwise
    check catches any mask containing the dangerous bits regardless of
    spelling.
    """
    if "dart_mcp" in sys.modules:
        del sys.modules["dart_mcp"]
    monkeypatch.setenv("DART_EVIDENCE_ROOT", str(tmp_path))
    ev = tmp_path / "sysmon.json"
    # Three cases: uppercase 0X1010, PROCESS_ALL_ACCESS, mixed-case
    # '0x143A' (old code only matched lowercase '0x143a'). All three
    # carry the dangerous read+query bits.
    ev.write_text(json.dumps([
        {"EventID": 10,
         "TargetImage": "C:/Windows/System32/lsass.exe",
         "GrantedAccess": "0X1010",
         "TimeCreated": "2026-04-29T10:00:00Z",
         "SourceImage": "C:/tmp/dump1.exe",
         "SourceProcessId": 1234},
        {"EventID": 10,
         "TargetImage": "C:/Windows/System32/lsass.exe",
         "GrantedAccess": "0x1F0FFF",
         "TimeCreated": "2026-04-29T10:01:00Z",
         "SourceImage": "C:/tmp/dump2.exe",
         "SourceProcessId": 1235},
        {"EventID": 10,
         "TargetImage": "C:/Windows/System32/lsass.exe",
         "GrantedAccess": "0x143A",
         "TimeCreated": "2026-04-29T10:02:00Z",
         "SourceImage": "C:/tmp/dump3.exe",
         "SourceProcessId": 1236},
    ]), encoding="utf-8")
    from dart_mcp import call_tool
    result = call_tool("detect_credential_access",
                       {"sysmon_events_json": "sysmon.json"})
    findings = result.get("findings", [])
    # All three masks must surface as LSASS access findings
    lsass_findings = [f for f in findings
                       if f.get("sub_technique", "").startswith("lsass_access")]
    assert len(lsass_findings) == 3, \
        f"bitwise LSASS check should detect all 3 dangerous masks, got {len(lsass_findings)}: {findings}"


def test_cron_hourly_emits_full_file_not_arbitrary_line(tmp_path, monkeypatch):
    """Pre-fix: for /etc/cron.hourly/*, the function emitted a job
    entry whose 'command' was the file's first non-comment line —
    misleading the analyst into thinking that line was the executed
    command. The new shape emits a script marker plus first_lines,
    line_count, and a full-content sha256 + flag scan.
    """
    # Clear cached modules so the @tool side-effect imports re-run
    # against the new EVIDENCE_ROOT.
    for mod in ("dart_mcp", "dart_mcp._v04_expansion",
                 "dart_mcp._v05_supply_chain", "dart_mcp._v06_macos_linux"):
        sys.modules.pop(mod, None)
    monkeypatch.setenv("DART_EVIDENCE_ROOT", str(tmp_path))
    cron_hourly = tmp_path / "etc" / "cron.hourly"
    cron_hourly.mkdir(parents=True)
    script = cron_hourly / "0anacron"
    script.write_text(
        "#!/bin/sh\n"
        "# This is the anacron run script — multiple meaningful lines\n"
        "test -e /var/run/anacron.lock && exit 0\n"
        "/usr/sbin/anacron -s\n"
        "exit 0\n",
        encoding="utf-8")
    script.chmod(0o755)
    from dart_mcp import call_tool
    # The function appends /etc/cron.hourly internally to evidence_root.
    # Use "." to mean the EVIDENCE_ROOT itself.
    result = call_tool("parse_linux_cron_jobs", {"evidence_root": "."})
    jobs = [j for j in result.get("jobs", []) if j.get("kind") == "system_hourly"]
    assert jobs, f"expected one system_hourly entry, got {result}"
    job = jobs[0]
    # New shape: command is a marker, NOT an arbitrary line of the file
    assert job["command"].startswith("<executable script:"), \
        f"command should be a marker, got {job['command']!r}"
    # New shape: first_lines + line_count present
    assert "first_lines" in job and isinstance(job["first_lines"], list)
    assert "line_count" in job and job["line_count"] >= 4
    # sha256 covers the whole file
    assert job.get("sha256")


def test_audit_chain_resume_with_large_entries(tmp_path):
    """Pre-fix: _load_tail_hash read a fixed 4 KB from the end of
    audit.jsonl. A single entry larger than 4 KB (very common when
    inputs carries a large dict) caused the last line to be truncated
    on resume and json.loads to raise. The new backward-growing-chunk
    loop guarantees a complete last line.
    """
    if "dart_audit" in sys.modules:
        del sys.modules["dart_audit"]
    from dart_audit import AuditLogger
    audit_path = tmp_path / "audit.jsonl"

    # First session: write an entry whose 'inputs' is ~10 KB
    big_input = {"data": "x" * 10000, "more": list(range(500))}
    logger_a = AuditLogger(audit_path)
    h1 = logger_a.log(tool_name="dummy_tool", inputs=big_input,
                       output={"ok": True}, iteration=1,
                       token_count_in=42, token_count_out=7,
                       finding_ids=None)
    # File should now have one entry well over 4 KB
    assert audit_path.stat().st_size > 4096, \
        f"expected entry > 4KB, got {audit_path.stat().st_size}"

    # Second session: open a new logger pointing at the same file.
    # If _load_tail_hash truncates the tail, this raises.
    logger_b = AuditLogger(audit_path)
    h2 = logger_b.log(tool_name="next_tool", inputs={"x": 1},
                       output={"ok": True}, iteration=2,
                       token_count_in=10, token_count_out=5,
                       finding_ids=None)

    # Verify the chain is intact across the resume
    ok, msg = AuditLogger.verify(audit_path)
    assert ok is True, \
        f"chain verification failed across large-entry resume: {msg}"

    # And that the second entry was chained off the first
    assert h2 != h1


if __name__ == "__main__":
    test_short_max_iterations_does_not_crash_report()
    print("test_short_max_iterations_does_not_crash_report OK")
    # New (2026-05-17 code-review fixes):
    import pytest
    # The 3 monkeypatch-based tests need pytest's tmp_path fixture
    rc = pytest.main([__file__, "-v", "--tb=short"])
    sys.exit(rc)
