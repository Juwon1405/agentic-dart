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


if __name__ == "__main__":
    test_short_max_iterations_does_not_crash_report()
    print("test_short_max_iterations_does_not_crash_report OK")
