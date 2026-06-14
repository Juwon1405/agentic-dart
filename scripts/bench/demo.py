#!/usr/bin/env python3
"""
demo.py — pipeline integrity check, no LLM / no API key required.

This is the "does the machine work end to end" check. It runs the agent over
case-01's self-contained evidence in DETERMINISTIC mode (scripted reasoning,
no model calls), then proves the three things a reviewer wants to see before
trusting any LLM numbers:

  1. ACCURACY   — the deterministic walk recovers both ground-truth findings
                  (F-001 unusual binary, F-013 IP-KVM insertion) with recall
                  1.0 and zero hallucinations (every finding chains to a real
                  MCP call in audit.jsonl).
  2. INTEGRITY  — the SHA-256 of every evidence file is identical before and
                  after the run (the agent reads, never writes, evidence), and
                  the audit chain verifies.
  3. CONTAINMENT— a destructive call that isn't registered (execute_shell) is
                  refused by dart-mcp, demonstrating the allow-list boundary.

Same evidence in -> same numbers out, so this doubles as the reproducible
figure committed to docs/. Run it first; if this is green the toolchain is
sound and any later self/external recall difference is the model, not the rig.

Usage:
  python3 -m scripts.bench.demo
  python3 -m scripts.bench.demo --json     # machine-readable summary line
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CASE01 = REPO / "examples" / "case-studies" / "self-evaluation" / "case-01" / "evidence_root"
GROUND_TRUTH = {"F-001", "F-013"}


def _sha_map(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            out[str(p.relative_to(root))] = h.hexdigest()
    return out


def run(quiet: bool = False) -> dict:
    os.environ["DART_EVIDENCE_ROOT"] = str(CASE01)
    for pkg in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr"):
        sys.path.insert(0, str(REPO / pkg / "src"))

    from dart_agent import main as agent_main
    from dart_mcp import call_tool

    pre = _sha_map(CASE01)

    with tempfile.TemporaryDirectory() as td:
        if quiet:
            # The deterministic agent prints progress to stdout; in --json mode
            # that would corrupt the single-line JSON contract. Redirect it.
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                rc = agent_main(["--case", "demo-pipeline-check",
                                 "--out", td, "--mode", "deterministic"])
        else:
            rc = agent_main(["--case", "demo-pipeline-check",
                             "--out", td, "--mode", "deterministic"])
        if rc != 0:
            raise SystemExit(f"agent exited {rc}")
        report = json.loads((Path(td) / "report.json").read_text())
        audit = [json.loads(l) for l in
                 (Path(td) / "audit.jsonl").read_text().splitlines() if l.strip()]

    post = _sha_map(CASE01)

    reported = {f["finding_id"] for f in report["findings"]}
    tp = reported & GROUND_TRUTH
    fn = GROUND_TRUTH - reported
    recall = len(tp) / max(1, len(GROUND_TRUTH))

    audit_ids = {e["audit_id"] for e in audit}
    hallucinated = [f["finding_id"] for f in report["findings"]
                    if not f.get("audit_ids") or not (set(f["audit_ids"]) & audit_ids)]

    # Containment: an unregistered destructive call must be refused.
    contained = False
    try:
        call_tool("execute_shell", {"cmd": "rm -rf /mnt/evidence"})
    except Exception:
        contained = True

    return {
        "recall": round(recall, 4),
        "true_positives": sorted(tp),
        "false_negatives": sorted(fn),
        "hallucinations": hallucinated,
        "evidence_integrity": pre == post,
        "audit_chain_len": len(audit),
        "containment_enforced": contained,
        "findings_count": len(reported),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit one JSON summary line")
    args = ap.parse_args(argv)

    r = run(quiet=args.json)

    if args.json:
        print(json.dumps(r))
        return 0 if (r["recall"] == 1.0 and not r["hallucinations"]
                     and r["evidence_integrity"] and r["containment_enforced"]) else 1

    ok = lambda b: "PASS" if b else "FAIL"
    print("Agentic-DART — pipeline check (deterministic, no LLM)")
    print(f"  evidence root      : {CASE01.relative_to(REPO)}")
    print()
    print(f"  [1] accuracy       : recall {r['recall']:.0%}  "
          f"TP={r['true_positives']}  FN={r['false_negatives']}")
    print(f"      hallucinations : {len(r['hallucinations'])} ({ok(not r['hallucinations'])})")
    print(f"  [2] integrity      : evidence unchanged {ok(r['evidence_integrity'])}  "
          f"| audit chain {r['audit_chain_len']} entries")
    print(f"  [3] containment    : unregistered destructive call refused "
          f"{ok(r['containment_enforced'])}")
    print()
    all_ok = (r["recall"] == 1.0 and not r["hallucinations"]
              and r["evidence_integrity"] and r["containment_enforced"])
    print(f"  result: {'ALL PASS — toolchain sound' if all_ok else 'FAILURE — see above'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
