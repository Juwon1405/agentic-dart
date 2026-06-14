#!/usr/bin/env python3
"""
score_against_truth.py — score a run_eval findings.json against a case's
truth.json, for any self-evaluation case (not just case-01).

run_eval.py produces findings.json but does not score it. measure_accuracy.py
scores, but only the bundled case-01 with its hardcoded harness. This fills the
gap: a model-agnostic, case-agnostic scorer so the same comparison table can be
built across every case and every model.

How scoring works
------------------
Ground-truth findings (truth.json: ground_truth_findings[]) and the model's
findings (findings.json) are matched on **MITRE ATT&CK technique overlap**.
Titles are free text and vary run to run; ATT&CK technique IDs are a controlled
vocabulary both sides use, so they are the stable join key.

A ground-truth finding counts as DETECTED when at least one model finding shares
one of its ATT&CK techniques (sub-technique 'T1059.001' also matches the parent
'T1059', and vice-versa, so granularity differences don't cause misses).

Metrics
-------
  recall                 = detected_gt / total_gt
  gt_total               = number of ground-truth findings
  gt_detected            = ground-truth findings with >=1 technique match
  model_findings         = number of findings the model reported
  unmatched_model        = model findings sharing no technique with any GT
                           (a rough over-reporting signal, NOT proof of a false
                           positive — the synthetic cases are not exhaustively
                           labelled, so treat this as informational)

Usage
-----
  python3 scripts/score_against_truth.py \
      --findings out/self-evaluation/case-02/<ts>/findings.json \
      --truth   examples/case-studies/self-evaluation/case-02/truth.json

  # JSON line for table aggregation:
  python3 scripts/score_against_truth.py --findings ... --truth ... --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


_TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def _techniques(text_or_list) -> set[str]:
    """Pull ATT&CK technique IDs out of any shape (list, dict, string)."""
    out: set[str] = set()
    if text_or_list is None:
        return out
    if isinstance(text_or_list, str):
        for m in _TECH_RE.findall(text_or_list):
            out.add(m.upper())
        return out
    if isinstance(text_or_list, (list, tuple)):
        for item in text_or_list:
            out |= _techniques(item)
        return out
    if isinstance(text_or_list, dict):
        for v in text_or_list.values():
            out |= _techniques(v)
        return out
    return out


def _with_parents(techs: set[str]) -> set[str]:
    """Add the parent technique of every sub-technique so T1059.001 and T1059
    are considered a match in either direction."""
    expanded = set(techs)
    for t in techs:
        if "." in t:
            expanded.add(t.split(".", 1)[0])
    return expanded


def _gt_techniques(finding: dict) -> set[str]:
    # truth.json findings carry 'mitre_attack'; be liberal in case a field
    # name varies.
    for key in ("mitre_attack", "mitre_tactics", "mitre", "attack"):
        if key in finding:
            return _techniques(finding[key])
    # last resort: scan the whole finding text
    return _techniques(json.dumps(finding))


def _model_techniques(finding: dict) -> set[str]:
    for key in ("mitre_tactics", "mitre_attack", "mitre", "attack", "techniques"):
        if key in finding:
            return _techniques(finding[key])
    return _techniques(json.dumps(finding))


def score(findings_path: Path, truth_path: Path) -> dict:
    truth = json.loads(truth_path.read_text())
    gt = truth.get("ground_truth_findings") or truth.get("findings") or []

    try:
        model = json.loads(findings_path.read_text())
    except FileNotFoundError:
        model = []
    if isinstance(model, dict):  # in case a report.json was passed
        model = model.get("findings", [])

    model_tech_sets = [_with_parents(_model_techniques(f)) for f in model]

    detected = 0
    scorable = 0          # GT findings that actually carry a technique
    per_gt = []
    matched_model_idx: set[int] = set()
    for g in gt:
        g_tech = _with_parents(_gt_techniques(g))
        has_tech = bool(g_tech)
        hit = False
        if has_tech:
            scorable += 1
            for i, m_tech in enumerate(model_tech_sets):
                if g_tech & m_tech:
                    hit = True
                    matched_model_idx.add(i)
            detected += 1 if hit else 0
        per_gt.append({
            "finding_id": g.get("finding_id") or g.get("id") or "?",
            "techniques": sorted(g_tech),
            "detected": hit,
            "scorable": has_tech,
        })

    gt_total = len(gt)
    unmatched_model = len(model) - len(matched_model_idx)

    return {
        "case": truth.get("case_metadata", {}).get("case_id")
                or truth_path.parent.name,
        "gt_total": gt_total,
        "gt_scorable": scorable,
        "gt_detected": detected,
        # recall is over the SCORABLE ground truth (findings that carry an
        # ATT&CK technique). Findings with no technique (investigative
        # conclusions, audit-chain notes) can't be matched by technique overlap
        # and are excluded from the denominator rather than counted as misses.
        "recall": round(detected / scorable, 4) if scorable else None,
        "recall_over_all": round(detected / gt_total, 4) if gt_total else None,
        "model_findings": len(model),
        "unmatched_model": unmatched_model,
        "per_gt": per_gt,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True, type=Path,
                    help="path to run_eval findings.json")
    ap.add_argument("--truth", required=True, type=Path,
                    help="path to the case's truth.json")
    ap.add_argument("--json", action="store_true",
                    help="emit a single compact JSON line (for table building)")
    args = ap.parse_args()

    result = score(args.findings, args.truth)

    if args.json:
        # drop the verbose per_gt for the compact line
        compact = {k: v for k, v in result.items() if k != "per_gt"}
        print(json.dumps(compact))
        return 0

    print(f"case            : {result['case']}")
    print(f"ground truth    : {result['gt_total']} findings "
          f"({result['gt_scorable']} scorable by ATT&CK technique, "
          f"{result['gt_total'] - result['gt_scorable']} unscorable)")
    if result['recall'] is not None:
        print(f"detected        : {result['gt_detected']}/{result['gt_scorable']} "
              f"scorable (recall {result['recall']:.0%})")
    else:
        print("detected        : n/a (no scorable ground truth)")
    print(f"model findings  : {result['model_findings']}")
    print(f"unmatched model : {result['unmatched_model']} "
          f"(informational — synthetic cases are not exhaustively labelled)")
    print()
    print("per ground-truth finding:")
    for g in result["per_gt"]:
        if not g["scorable"]:
            mark = "–"  # excluded from scoring (no technique)
        elif g["detected"]:
            mark = "✓"
        else:
            mark = "·"
        techs = ",".join(g["techniques"]) or "(no technique — excluded from recall)"
        print(f"  [{mark}] {g['finding_id']:16s} {techs}")
    print()
    print("  legend: ✓ detected   · missed   – not scorable (no ATT&CK technique)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
