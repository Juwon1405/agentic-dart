"""End-to-end test: agent runs, self-corrects on USB contradiction."""
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ["yushin_audit/src", "yushin_mcp/src", "yushin_agent/src"]:
    sys.path.insert(0, str(REPO / p))


def test_full_run_produces_self_correction():
    os.environ["YUSHIN_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")
    # Re-import with new env var
    if "yushin_mcp" in sys.modules:
        del sys.modules["yushin_mcp"]
    from yushin_agent import main
    with tempfile.TemporaryDirectory() as td:
        rc = main(["--case", "ci-test", "--out", td, "--mode", "deterministic"])
        assert rc == 0, "agent exited non-zero"

        progress_lines = (Path(td) / "progress.jsonl").read_text().splitlines()
        joined = " ".join(progress_lines).lower()
        assert "contradiction" in joined or "self-correction" in joined, \
            "self-correction trace missing from progress.jsonl"

        report = json.loads((Path(td) / "report.json").read_text())
        finding_ids = [f["finding_id"] for f in report["findings"]]
        assert "F-013" in finding_ids, f"IP-KVM finding missing: {finding_ids}"


if __name__ == "__main__":
    test_full_run_produces_self_correction()
    print("test_full_run_produces_self_correction OK")
