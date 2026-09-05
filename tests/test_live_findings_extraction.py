"""Unit tests for live-mode findings extraction from the final REPORT block.

Caught by a real-Claude run: the model follows the prompt contract (REPORT:
followed by a ```json fenced object with a findings array), but the real path
previously never parsed it back into state.findings, so live_summary.json
always carried an empty list in real-claude mode.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dfir_agent" / "src"))

from dfir_agent.live import _extract_findings  # noqa: E402


FENCED = """Some narrative analysis first.

REPORT:
```json
{
  "findings": [
    {"id": "F-001", "title": "Trojanized PDF", "confidence": 0.98},
    {"id": "F-013", "title": "USB exfil", "confidence": 0.82}
  ],
  "primary_hypothesis": "phishing chain",
  "iterations": 5
}
```
"""

BARE = 'prelude REPORT: {"findings": [{"id": "F-001"}], "iterations": 3} trailing prose'


def test_fenced_report_parses():
    out = _extract_findings(FENCED)
    assert [f["id"] for f in out] == ["F-001", "F-013"]
    assert out[0]["confidence"] == 0.98


def test_bare_report_with_trailing_prose():
    out = _extract_findings(BARE)
    assert [f["id"] for f in out] == ["F-001"]


def test_last_report_marker_wins():
    text = 'REPORT: {"findings": []}\n...revised...\n' + FENCED
    out = _extract_findings(text)
    assert [f["id"] for f in out] == ["F-001", "F-013"]


def test_no_report_returns_empty():
    assert _extract_findings("(max_iterations reached)") == []
    assert _extract_findings("") == []


def test_malformed_json_returns_empty():
    assert _extract_findings("REPORT: {not json") == []


def test_braces_inside_strings_handled():
    text = 'REPORT: {"findings": [{"id": "F-001", "title": "uses { and } in text"}]}'
    out = _extract_findings(text)
    assert out[0]["title"] == "uses { and } in text"


def test_non_dict_entries_dropped():
    text = 'REPORT: {"findings": [{"id": "F-001"}, "stray-string", 42]}'
    out = _extract_findings(text)
    assert [f["id"] for f in out] == ["F-001"]


def test_real_transcript_if_present():
    """Regression against the actual transcript captured from the live run."""
    runs = sorted((REPO / "out").glob("live-full14-*/live_transcript.txt"))
    if not runs:
        return  # transcript not present on this host; covered by fixtures above
    out = _extract_findings(runs[-1].read_text())
    assert out, "real transcript should yield findings"
    assert any(f.get("id") == "F-001" for f in out)
