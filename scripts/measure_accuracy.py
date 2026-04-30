#!/usr/bin/env python3
"""Measure Agentic-DART's accuracy against the sample-evidence ground truth.

This script is deterministic: same evidence in → same numbers out. The
output is committed to docs/accuracy-report.md so any reviewer can
re-run and verify.

Ground truth for the sample case (find-evil-ref-01):
  F-001  Unusual binary first-executed shortly after reported login
  F-013  IP-KVM device inserted ~3 min before operator logon
         (remote-hands pattern; VID 0557 / PID 2419 ATEN)

Metrics:
  recall            = TP / (TP + FN)
  false_positive    = FP / total_reported
  hallucination     = findings lacking any audit_id → MCP call chain
  evidence_integrity= SHA-256(evidence) pre vs post
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
os.environ["DART_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")
sys.path.insert(0, str(REPO / "dart_audit" / "src"))
sys.path.insert(0, str(REPO / "dart_mcp"   / "src"))
sys.path.insert(0, str(REPO / "dart_agent" / "src"))

GROUND_TRUTH = {"F-001", "F-013"}


def evidence_sha256_map(root):
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            out[str(p.relative_to(root))] = h.hexdigest()
    return out


def main():
    evidence_root = Path(os.environ["DART_EVIDENCE_ROOT"])

    # 1. Snapshot evidence hashes BEFORE the run
    pre = evidence_sha256_map(evidence_root)

    # 2. Run the agent
    from dart_agent import main as agent_main
    with tempfile.TemporaryDirectory() as td:
        rc = agent_main(["--case", "accuracy-measurement",
                         "--out", td, "--mode", "deterministic"])
        assert rc == 0, f"agent exited {rc}"

        report = json.loads((Path(td) / "report.json").read_text())
        audit  = [json.loads(l) for l in (Path(td) / "audit.jsonl").read_text().splitlines() if l.strip()]
        progress_lines = (Path(td) / "progress.jsonl").read_text().splitlines()

    # 3. Compute metrics
    reported = {f["finding_id"] for f in report["findings"]}
    tp = reported & GROUND_TRUTH
    fp = reported - GROUND_TRUTH
    fn = GROUND_TRUTH - reported
    recall = len(tp) / max(1, len(GROUND_TRUTH))
    fp_rate = len(fp) / max(1, len(reported))

    # Hallucinations: any reported finding whose audit_ids don't exist in audit.jsonl
    audit_ids = {e["audit_id"] for e in audit}
    hallucinated = [
        f["finding_id"] for f in report["findings"]
        if not f.get("audit_ids") or not (set(f["audit_ids"]) & audit_ids)
    ]

    # 4. Snapshot evidence hashes AFTER the run
    post = evidence_sha256_map(evidence_root)
    evidence_integrity = (pre == post)

    # 5. Self-correction check — hard requirement for SANS criterion #1
    joined = " ".join(progress_lines).lower()
    self_correction_observed = (
        "contradiction" in joined or "self-correction" in joined
    )

    summary = {
        "ground_truth_count": len(GROUND_TRUTH),
        "reported_count": len(reported),
        "true_positives": sorted(tp),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "recall": round(recall, 3),
        "false_positive_rate": round(fp_rate, 3),
        "hallucinated_findings": hallucinated,
        "hallucination_count": len(hallucinated),
        "evidence_integrity_preserved": evidence_integrity,
        "evidence_files_measured": len(pre),
        "self_correction_observed": self_correction_observed,
        "iterations": report["iterations"],
        "audit_chain_length": len(audit),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
