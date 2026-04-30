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


if __name__ == "__main__":
    test_chain_verifies_clean(); print("test_chain_verifies_clean OK")
    test_chain_detects_tampering(); print("test_chain_detects_tampering OK")
    test_resume_preserves_chain(); print("test_resume_preserves_chain OK")
