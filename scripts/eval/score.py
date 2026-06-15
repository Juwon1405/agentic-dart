#!/usr/bin/env python3
"""
score.py — score a analyze findings.json against a case's
truth.json, for any self-evaluation case (not just case-01).

analyze.py produces findings.json but does not score it. scripts/eval/demo.py
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
  python3 scripts/eval/score.py \
      --findings out/self-evaluation/case-02/<ts>/findings.json \
      --truth   examples/case-studies/self-evaluation/case-02/truth.json

  # JSON line for table aggregation:
  python3 scripts/eval/score.py --findings ... --truth ... --json
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


# Common words to ignore when matching technique-less external claims by
# keyword. Keeps the match anchored on distinctive nouns (tool names, account
# names, file names) rather than filler.
_STOP = {
    "the", "and", "for", "with", "from", "this", "that", "have", "has", "was",
    "were", "are", "his", "her", "their", "system", "user", "account", "file",
    "files", "found", "shows", "show", "registered", "primary", "installed",
    "evidence", "indicates", "present", "used", "using", "into", "onto",
}


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
    # For external cases the ground truth often carries no ATT&CK technique
    # (NIST CFReDS answers like "registered owner is Greg Schardt" are facts,
    # not techniques). Those cases instead flag which findings are reachable
    # with the current toolset via directly_detectable_v053. We pre-compute a
    # lowercased text blob per model finding so technique-less ground truth can
    # still be matched by claim keywords.
    model_text = [
        " ".join(str(f.get(k, "")) for k in
                 ("title", "claim", "evidence_summary", "summary", "finding")).lower()
        for f in model
    ]

    detected = 0
    scorable = 0          # GT findings we can fairly score against this toolset
    per_gt = []
    matched_model_idx: set[int] = set()
    for g in gt:
        g_tech = _with_parents(_gt_techniques(g))
        has_tech = bool(g_tech)
        # A finding is scorable if it carries a technique OR is explicitly
        # marked reachable by the current tools. External truth uses the flag;
        # self truth uses techniques. When the flag is present and False, the
        # finding needs a tool we haven't built yet -> not scorable (excluded
        # from the denominator, not counted as a miss). When the flag is
        # absent (self cases), fall back to technique presence. A "partial"
        # flag means the artifact is reachable with the current toolset but
        # only some of the claim's facts surface (e.g. CFReDS "web-based email
        # mrevilrulez@yahoo.com" — the agent can recover the account name from
        # disk artifacts even if it can't reconstruct the full webmail session).
        # Partial is scorable: it's fair to expect the agent to surface the
        # detectable part. Anything else stringy/unknown falls back to technique
        # presence rather than silently dropping out of the denominator.
        flag = g.get("directly_detectable_v053")
        if flag is True or flag == "partial":
            is_scorable = True
        elif flag is False:
            is_scorable = False
        else:
            is_scorable = has_tech

        hit = False
        if is_scorable:
            scorable += 1
            if has_tech:
                for i, m_tech in enumerate(model_tech_sets):
                    if g_tech & m_tech:
                        hit = True
                        matched_model_idx.add(i)
            else:
                # technique-less but detectable (external): match by the
                # distinctive nouns in the ground-truth claim.
                claim = (g.get("claim") or g.get("title") or "").lower()
                import re as _re
                keys = [w for w in _re.findall(r"[a-z0-9.\\-]{4,}", claim)
                        if w not in _STOP]
                for i, mt in enumerate(model_text):
                    if keys and sum(1 for k in keys if k in mt) >= max(2, len(keys) // 3):
                        hit = True
                        matched_model_idx.add(i)
            detected += 1 if hit else 0
        per_gt.append({
            "finding_id": g.get("finding_id") or g.get("id") or "?",
            "techniques": sorted(g_tech),
            "detected": hit,
            "scorable": is_scorable,
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
                    help="path to analyze findings.json")
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
          f"({result['gt_scorable']} scorable with current tools, "
          f"{result['gt_total'] - result['gt_scorable']} need unbuilt tools / no technique)")
    if result['recall'] is not None:
        print(f"detected        : {result['gt_detected']}/{result['gt_scorable']} "
              f"scorable (recall {result['recall']:.0%})")
    else:
        print("detected        : n/a (no scorable ground truth for this toolset)")
    print(f"model findings  : {result['model_findings']}")
    print(f"unmatched model : {result['unmatched_model']} "
          f"(informational — synthetic cases are not exhaustively labelled)")
    print()
    print("per ground-truth finding:")
    for g in result["per_gt"]:
        if not g["scorable"]:
            mark = "–"  # excluded: needs an unbuilt tool, or no technique
        elif g["detected"]:
            mark = "✓"
        else:
            mark = "·"
        techs = ",".join(g["techniques"]) or "(matched by claim keywords)"
        print(f"  [{mark}] {g['finding_id']:16s} {techs}")
    print()
    print("  legend: ✓ detected   · missed   – not scorable "
          "(needs unbuilt tool / no ATT&CK technique)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
