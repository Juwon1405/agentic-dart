"""Tests for dart-audit: chain integrity and tamper detection."""
import json
import os
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "dart_audit" / "src"
sys.path.insert(0, str(SRC))

from dart_audit import AuditLogger


def test_chain_verifies_clean():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "audit.jsonl"
        logger = AuditLogger(p)
        for i in range(5):
            logger.log(
                tool_name="get_amcache",
                inputs={"hive_path": "x"},
                output={"n": i},
                iteration=i,
                token_count_in=10,
                token_count_out=20,
            )
        ok, msg = AuditLogger.verify(p)
        assert ok, msg
        assert "5 entries" in msg


def test_chain_detects_tampering():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "audit.jsonl"
        logger = AuditLogger(p)
        for i in range(3):
            logger.log("get_amcache", {"x": i}, {"n": i}, i, 10, 20)

        lines = p.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["inputs"] = {"x": 999}
        lines[1] = json.dumps(obj, sort_keys=True)
        p.write_text("\n".join(lines) + "\n")

        ok, msg = AuditLogger.verify(p)
        assert not ok
        assert "entry_hash mismatch" in msg


def test_resume_preserves_chain():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "audit.jsonl"
        AuditLogger(p).log("a", {}, {"v": 1}, 1, 1, 1)
        AuditLogger(p).log("b", {}, {"v": 2}, 2, 1, 1)
        ok, msg = AuditLogger.verify(p)
        assert ok, msg


def test_chain_handles_non_json_native_inputs():
    """REGRESSION (QA 2026-05-02): Path / datetime in inputs must not crash
    log() and must not desync the chain hash. Earlier version had
    `default=str` only on the output digest; the entry-level json.dumps()
    in log() and the verify() canonical recompute lacked it, so a single
    Path object in inputs raised TypeError on log(), and even when caught
    upstream a datetime in finding_ids would produce a hash that verify()
    could not reproduce. All three sites now share `default=str`."""
    import datetime
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "audit.jsonl"
        logger = AuditLogger(p)
        # Mix of types that aren't JSON-native by default
        logger.log(
            tool_name="get_amcache",
            inputs={
                "hive_path": Path("/evidence/disk/Amcache.hve"),  # Path
                "started_at": datetime.datetime(2026, 5, 2, 12, 0, 0),  # datetime
            },
            output={"items": [], "examined": Path("/evidence/disk")},
            iteration=1,
            token_count_in=10,
            token_count_out=20,
            finding_ids=["F-001"],
        )
        # Second entry to ensure chain advancement
        logger.log("parse_prefetch",
                   {"prefetch_path": Path("/evidence/p.pf")},
                   {"ok": True}, 2, 5, 5)

        ok, msg = AuditLogger.verify(p)
        assert ok, f"chain broken on non-JSON-native inputs: {msg}"
        assert "2 entries" in msg


if __name__ == "__main__":
    test_chain_verifies_clean(); print("test_chain_verifies_clean OK")
    test_chain_detects_tampering(); print("test_chain_detects_tampering OK")
    test_resume_preserves_chain(); print("test_resume_preserves_chain OK")
    test_chain_handles_non_json_native_inputs(); print("test_chain_handles_non_json_native_inputs OK")
