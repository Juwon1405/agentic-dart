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

# Venv self-rexec guard (see run_eval.py for full rationale).
import os as _os
import sys as _sys
from pathlib import Path as _Path
if _os.environ.get("DART_VENV_REEXEC") not in ("1", "0"):
    _venv_py = _Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python3"
    # scripts/benchmark/*.py is two levels deep — use parents[2] there.
    if not _venv_py.exists():
        _venv_py = _Path(__file__).resolve().parents[2] / ".venv" / "bin" / "python3"
    if _venv_py.exists() and _Path(_sys.executable).resolve() != _venv_py.resolve():
        _os.environ["DART_VENV_REEXEC"] = "1"
        _os.execv(str(_venv_py), [str(_venv_py), __file__] + _sys.argv[1:])

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Canonical bundled evidence: the realistic, production-volume tree shipped as
# the self-evaluation case-01 evidence_root
# (examples/case-studies/self-evaluation/case-01/evidence_root/). It carries
# security-events (~11k lines), supply-chain, RDP brute, USB setupapi, etc. The
# web-access and unix-auth logs ship IOC-only and are enriched with
# deterministic benign noise (~1:30) at measure time to exercise
# needle-in-haystack recall.
#
# There is no public evidence-set selector any more: this harness always scores
# against the one canonical evidence root. (examples/sample-evidence/ remains
# only as a small, byte-stable CI fixture imported directly by the unit tests;
# it is not an evidence set the user ever selects.)
_evidence_dir = Path("examples") / "case-studies" / "self-evaluation" / "case-01" / "evidence_root"
# Re-derive the two IOC-only logs (web access and unix auth) with deterministic
# benign noise before scoring, so the needle-in-haystack measurement always
# reflects the current reference IOCs. The generator only touches those two
# logs; all other hand-curated evidence is left untouched, and its output is
# byte-identical across runs, so this leaves git clean.
_gen = REPO / "scripts" / "generate_realistic_evidence.py"
_r = subprocess.run(
    [sys.executable, str(_gen)], cwd=str(REPO),
    capture_output=True, text=True,
)
if _r.returncode != 0:
    print(f"generate_realistic_evidence.py failed:\n{_r.stderr}",
          file=sys.stderr)
    sys.exit(2)
os.environ["DART_EVIDENCE_ROOT"] = str(REPO / _evidence_dir)
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
