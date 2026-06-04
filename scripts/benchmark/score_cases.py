#!/usr/bin/env python3
"""Unified scorer - scores every case (internal 01-07,11 + external 08-10) via one interface.

dart_agent output (report.json) carries no evidence_path, so each finding's
audit_ids are joined against audit.jsonl to recover (tool_name, inputs paths),
which are then matched against ground-truth. This content-based match sidesteps
the finding_id scheme mismatch (F-001 vs F-AUTH-xxx).

  strict   : ground-truth (expected_function, evidence_path) <-> finding (tool_name, recovered path)
  lenient  : (artifact_type / host_path prefix)              <-> finding recovered-path prefix
  derived (self_correction / audit_chain / correlation)       : excluded from scoring
  hallucination : findings without any audit_ids (claims lacking a chain)
  FPR           : findings matched by neither / total findings

Usage:
  python3 scripts/benchmark/score_cases.py --case case-05-authentication-lateral --run-dir <out_dir>
  python3 scripts/benchmark/score_cases.py --case <case> --report r.json --audit a.jsonl
"""
import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CS = REPO / "examples" / "case-studies"
DERIVED = {"self_correction_event", "audit_chain", "correlation_finding"}
_PATH_HINT = (".json", ".csv", ".log", ".evtx", ".hve", ".ndjson", ".txt", ".dat", ".db")


def load_audit_map(audit_path):
    """Map audit_id -> {tool, paths:set}. Collect only file-path-like inputs values."""
    amap = {}
    if not audit_path.exists():
        return amap
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        aid = e.get("audit_id")
        if not aid:
            continue
        paths = set()
        for v in (e.get("inputs") or {}).values():
            if isinstance(v, str) and ("/" in v or v.endswith(_PATH_HINT)):
                paths.add(v)
        amap[aid] = {"tool": e.get("tool_name"), "paths": paths}
    return amap


def normalize_findings(report_path, amap):
    """Model finding -> {id, tools:set, paths:set, has_audit:bool} (audit join)."""
    out = []
    d = json.loads(report_path.read_text(encoding="utf-8"))
    for f in d.get("findings", []):
        aids = f.get("audit_ids") or []
        tools, paths = set(), set()
        for a in aids:
            if a in amap:
                if amap[a]["tool"]:
                    tools.add(amap[a]["tool"])
                paths |= amap[a]["paths"]
        out.append({"id": f.get("finding_id"), "tools": tools,
                    "paths": paths, "has_audit": bool(aids)})
    return out


def load_gt(case):
    gt = json.loads((CS / case / "ground-truth.json").read_text(encoding="utf-8"))
    rows = []
    for f in gt.get("ground_truth_findings", []):
        if f.get("artifact_type") in DERIVED:
            continue
        fn = (f.get("expected_dart_mcp_function") or f.get("expected_function") or "")
        rows.append({
            "id": f.get("finding_id"),
            "fn": fn.split("(")[0].strip(),
            "ep": f.get("evidence_path") or "",
            "at": (f.get("artifact_type") or "").lower(),
            "hp": (f.get("host_path") or "").lower(),
        })
    return rows


def match_strict(gt, findings, used):
    """Path match + (function match or gt function unset). One finding consumed once."""
    for f in findings:
        if id(f) in used:
            continue
        if gt["ep"] and gt["ep"] in f["paths"]:
            if not gt["fn"] or gt["fn"] in f["tools"]:
                return f
    return None


def match_lenient(gt, findings, used):
    for f in findings:
        if id(f) in used:
            continue
        if gt["hp"] and any(gt["hp"] in p.lower() for p in f["paths"]):
            return f
        if gt["ep"] and any(gt["ep"] in p for p in f["paths"]):
            return f
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", required=True)
    ap.add_argument("--run-dir", help="dart_agent output dir (report.json + audit.jsonl)")
    ap.add_argument("--report")
    ap.add_argument("--audit")
    ap.add_argument("--json", action="store_true", help="print a single JSON line only")
    a = ap.parse_args()

    if a.run_dir:
        rd = Path(a.run_dir)
        report, audit = rd / "report.json", rd / "audit.jsonl"
    elif a.report and a.audit:
        report, audit = Path(a.report), Path(a.audit)
    else:
        ap.error("requires --run-dir or both --report and --audit")

    amap = load_audit_map(audit)
    findings = normalize_findings(report, amap)
    gts = load_gt(a.case)

    used_s, used_l = set(), set()
    s_tp = l_tp = 0
    for gt in gts:
        s = match_strict(gt, findings, used_s)
        if s:
            s_tp += 1
            used_s.add(id(s))
        l = match_lenient(gt, findings, used_l)
        if l:
            l_tp += 1
            used_l.add(id(l))

    n_gt, n_f = len(gts), len(findings)
    halluc = sum(1 for f in findings if not f["has_audit"])
    fp = n_f - len(used_l)
    res = {
        "case": a.case,
        "strict_recall": round(s_tp / n_gt, 3) if n_gt else 0.0,
        "lenient_recall": round(l_tp / n_gt, 3) if n_gt else 0.0,
        "strict_precision": round(s_tp / n_f, 3) if n_f else 0.0,
        "hallucination": halluc,
        "fpr": round(fp / n_f, 3) if n_f else 0.0,
        "ground_truth": n_gt,
        "findings": n_f,
        "strict_tp": s_tp,
        "lenient_tp": l_tp,
    }
    if a.json:
        print(json.dumps(res))
        return
    print(f"=== {a.case} ===")
    print(f"ground-truth (non-derived) {n_gt}  |  findings {n_f}")
    print(f"strict  recall {res['strict_recall']:.1%} ({s_tp}/{n_gt})  precision {res['strict_precision']:.1%}")
    print(f"lenient recall {res['lenient_recall']:.1%} ({l_tp}/{n_gt})")
    print(f"hallucination {halluc}  |  FPR {res['fpr']:.1%} ({fp}/{n_f})")


if __name__ == "__main__":
    main()
