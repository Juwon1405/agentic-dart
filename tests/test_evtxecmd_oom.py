"""Tests for the OOM-safe bounded streaming read in the evtxecmd adapter.

EvtxECmd output for a busy Security.evtx can be GB-scale. _run_evtxecmd
must stream the CSV and only ever materialize up to max_rows matching
rows, never the whole file. These tests mock the EvtxECmd subprocess so
they run without the .NET binary.
"""
import csv
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from dfir_mcp.sift_adapters import evtxecmd


def _make_csv(path: Path, n_rows: int):
    with path.open("w", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["EventId", "TimeCreated", "Channel"])
        w.writeheader()
        for i in range(n_rows):
            w.writerow({
                "EventId": str(4624 if i % 3 == 0 else 1000),
                "TimeCreated": f"2026-01-01T{i % 24:02d}:00:00",
                "Channel": "Security",
            })


@contextmanager
def _mock_evtxecmd(tmp_path: Path, n_rows: int):
    """Patch the subprocess plumbing so _run_evtxecmd reads our fake CSV."""
    csv_path = tmp_path / "evtx.csv"
    _make_csv(csv_path, n_rows)

    fake_result = MagicMock()
    fake_result.stderr = ""
    fake_result.duration_ms = 10
    fake_result.output_files = {str(csv_path): "deadbeef"}

    @contextmanager
    def fake_tempdir(prefix=""):
        yield tmp_path

    with patch.object(evtxecmd, "safe_evidence_input", return_value=tmp_path), \
         patch.object(evtxecmd, "_sha256", return_value="abc123"), \
         patch.object(evtxecmd, "_tempdir", fake_tempdir), \
         patch.object(evtxecmd, "_evtxecmd_bin", return_value="/bin/true"), \
         patch.object(evtxecmd, "run_tool", return_value=fake_result):
        yield


def test_bounded_read_only_materializes_max_rows(tmp_path):
    """A 10k-row CSV with max_rows=100 must keep exactly 100 rows."""
    with _mock_evtxecmd(tmp_path, 10000):
        r = evtxecmd._run_evtxecmd("dummy", max_rows=100)
    assert len(r["rows"]) == 100, "must not materialize beyond max_rows"
    assert r["truncated"] is True


def test_unfiltered_bounded_read_stops_scanning_early(tmp_path):
    """For an unfiltered read, hitting max_rows stops the scan entirely —
    total_scanned reflects the early stop, not the whole file."""
    with _mock_evtxecmd(tmp_path, 10000):
        r = evtxecmd._run_evtxecmd("dummy", max_rows=100)
    # We stopped right after collecting 100, so we scanned ~100, not 10000.
    assert r["total_scanned"] <= 200, \
        f"unfiltered read should stop early, scanned {r['total_scanned']}"


def test_filtered_read_discards_nonmatching_without_holding_them(tmp_path):
    """row_filter keeps only matching rows; non-matching are counted in
    total_scanned but never materialized."""
    def keep_4624(row):
        return row.get("EventId") == "4624"

    with _mock_evtxecmd(tmp_path, 10000):
        r = evtxecmd._run_evtxecmd("dummy", max_rows=50, row_filter=keep_4624)
    assert len(r["rows"]) == 50
    assert all(row["EventId"] == "4624" for row in r["rows"])
    # A filtered read keeps scanning so the matched-vs-scanned ratio is
    # meaningful — it counts ALL rows, not just the 50 kept.
    assert r["total_scanned"] == 10000


def test_small_input_returns_everything(tmp_path):
    """A small CSV under the cap returns all rows, not truncated."""
    with _mock_evtxecmd(tmp_path, 42):
        r = evtxecmd._run_evtxecmd("dummy", max_rows=10000)
    assert len(r["rows"]) == 42
    assert r["total_scanned"] == 42
    assert r["truncated"] is False


def test_parse_tool_reports_truncation(tmp_path):
    """sift_evtxecmd_parse surfaces total_scanned + truncated in metadata."""
    with _mock_evtxecmd(tmp_path, 5000):
        out = evtxecmd.sift_evtxecmd_parse("dummy", limit=100)
    meta = out["metadata"]
    assert meta["events_returned"] == 100
    assert meta["truncated"] is True
    assert len(out["events"]) == 100


def test_filter_eids_tool_pushes_predicate_down(tmp_path):
    """sift_evtxecmd_filter_eids only materializes matching EIDs."""
    with _mock_evtxecmd(tmp_path, 3000):
        out = evtxecmd.sift_evtxecmd_filter_eids(
            "dummy", event_ids=["4624"], limit=10000)
    meta = out["metadata"]
    # 1/3 of rows are 4624 → ~1000 matches out of 3000 scanned
    assert meta["events_total"] == 3000
    assert all(e["EventId"] == "4624" for e in out["events"])
    assert meta["events_after_filter"] == len(out["events"])


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
