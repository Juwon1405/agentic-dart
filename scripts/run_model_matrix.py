#!/usr/bin/env python3
"""
run_model_matrix.py — run every case across multiple models, score each result
against truth, and emit one clean Markdown table for the repo.

This is the driver behind docs/benchmarks/MODEL-COMPARISON.md: it answers
"given that we know the ground truth, how does each model do on each case, and
what did it cost in tokens?" so a future, better model can be dropped in and
re-measured the same way.

What it does, per (case, model):
  1. runs `run_eval.py --case <case> --model <model>` (live; needs API key)
  2. reads the produced findings.json + summary.json (token usage)
  3. scores findings vs the case's truth.json (scripts/score_against_truth.py)
  4. records recall, gt detected/total, model finding count, tokens in/out

Then writes a Markdown matrix grouped by case, one row per model, plus a totals
row. Token counts make the cost/quality trade-off visible.

Self-evaluation cases need their evidence_root present (case-01 is bundled;
case-02..08 use the evidence_root symlinks created by the runbook/bootstrap).
External cases need --download to have been run at least once.

Usage
-----
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 scripts/run_model_matrix.py \
      --models claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8 \
      --cases self-evaluation/case-01 self-evaluation/case-02 ... \
      --out docs/benchmarks/MODEL-COMPARISON.md

  # convenience: --all-self runs every self-evaluation case
  python3 scripts/run_model_matrix.py --all-self \
      --models claude-haiku-4-5-20251001 claude-sonnet-4-6

Re-runs are additive per (case, model): the latest run wins. Use --dry-run to
print the plan without calling the API.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CASE_ROOT = REPO / "examples" / "case-studies"


def discover_self_cases() -> list[str]:
    out = []
    base = CASE_ROOT / "self-evaluation"
    for d in sorted(base.glob("case-*")):
        if (d / "truth.json").is_file():
            out.append(f"self-evaluation/{d.name}")
    return out


def latest_out_dir(case_ref: str) -> Path | None:
    tier, case_id = case_ref.split("/", 1)
    base = REPO / "out" / tier / case_id
    if not base.is_dir():
        return None
    runs = sorted([p for p in base.iterdir() if p.is_dir()],
                  key=lambda p: p.stat().st_mtime, reverse=True)
    return runs[0] if runs else None


def run_one(case_ref: str, model: str, *, download: bool, dry_run: bool) -> dict:
    cmd = [sys.executable, str(REPO / "run_eval.py"),
           "--case", case_ref, "--model", model]
    if download:
        cmd.append("--download")

    row = {"case": case_ref, "model": model, "ok": False,
           "recall": None, "gt_detected": None, "gt_total": None,
           "model_findings": None, "tokens_in": None, "tokens_out": None,
           "error": None}

    if dry_run:
        print("  DRY-RUN:", " ".join(cmd))
        row["error"] = "dry-run"
        return row

    print(f"  → {case_ref}  [{model}]")
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)
    if proc.returncode != 0:
        # keep last line of stderr as the reason
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        row["error"] = tail[-1] if tail else f"exit {proc.returncode}"
        print(f"     FAILED: {row['error']}")
        return row

    out_dir = latest_out_dir(case_ref)
    if not out_dir:
        row["error"] = "no output dir"
        return row

    findings_path = out_dir / "findings.json"
    summary_path = out_dir / "summary.json"
    truth_path = (CASE_ROOT / case_ref / "truth.json")

    # token usage
    try:
        summ = json.loads(summary_path.read_text())
        usage = summ.get("usage", {})
        row["tokens_in"] = usage.get("input_tokens")
        row["tokens_out"] = usage.get("output_tokens")
        row["model_findings"] = summ.get("findings_count")
    except Exception:
        pass

    # score vs truth (self cases only; external have no usable truth here)
    if truth_path.is_file() and case_ref.startswith("self-evaluation/"):
        score_cmd = [sys.executable, str(REPO / "scripts" / "score_against_truth.py"),
                     "--findings", str(findings_path),
                     "--truth", str(truth_path), "--json"]
        sp = subprocess.run(score_cmd, cwd=str(REPO), capture_output=True, text=True)
        if sp.returncode == 0 and sp.stdout.strip():
            try:
                s = json.loads(sp.stdout.strip())
                row["recall"] = s.get("recall")
                row["gt_detected"] = s.get("gt_detected")
                row["gt_total"] = s.get("gt_total")
                if row["model_findings"] is None:
                    row["model_findings"] = s.get("model_findings")
            except Exception:
                pass

    row["ok"] = True
    return row


def _fmt_recall(r) -> str:
    return f"{r:.0%}" if isinstance(r, (int, float)) else "—"


def _fmt_int(n) -> str:
    return f"{n:,}" if isinstance(n, int) else "—"


def build_markdown(rows: list[dict], models: list[str]) -> str:
    today = dt.date.today().isoformat()
    lines = []
    lines.append("# Agentic-DART — Model Comparison Benchmark")
    lines.append("")
    lines.append(f"_Generated {today}. Ground truth is known for every "
                 "self-evaluation case; scoring matches findings to truth.json "
                 "by MITRE ATT&CK technique overlap (parent/sub-technique "
                 "aware). Token counts are the live API usage for that run._")
    lines.append("")
    lines.append("**Models compared:** " + ", ".join(f"`{m}`" for m in models))
    lines.append("")
    lines.append("> `recall` = ground-truth findings detected ÷ total. "
                 "`found` = findings the model reported. `tok in/out` = live "
                 "token usage. `—` = not applicable / run failed. External "
                 "cases have no labelled ground truth here, so their rows show "
                 "findings + tokens only.")
    lines.append("")

    # group rows by case, preserving case order of first appearance
    cases: list[str] = []
    for r in rows:
        if r["case"] not in cases:
            cases.append(r["case"])

    lines.append("| Case | Model | Recall | GT detected | Found | Tok in | Tok out |")
    lines.append("|------|-------|:------:|:-----------:|:-----:|-------:|--------:|")

    sum_in = {m: 0 for m in models}
    sum_out = {m: 0 for m in models}
    for case in cases:
        for m in models:
            r = next((x for x in rows if x["case"] == case and x["model"] == m), None)
            if not r:
                continue
            short_model = m.replace("claude-", "").replace("-20251001", "")
            gt = (f"{r['gt_detected']}/{r['gt_total']}"
                  if r["gt_detected"] is not None else "—")
            recall = _fmt_recall(r["recall"])
            found = _fmt_int(r["model_findings"]) if r["model_findings"] is not None else "—"
            ti = _fmt_int(r["tokens_in"])
            to = _fmt_int(r["tokens_out"])
            if isinstance(r["tokens_in"], int):
                sum_in[m] += r["tokens_in"]
            if isinstance(r["tokens_out"], int):
                sum_out[m] += r["tokens_out"]
            note = "" if r["ok"] else f" _(failed: {r['error']})_"
            lines.append(f"| {case} | {short_model} | {recall} | {gt} | {found} | {ti} | {to} |{note}")

    lines.append("")
    lines.append("## Token totals by model")
    lines.append("")
    lines.append("| Model | Total tok in | Total tok out |")
    lines.append("|-------|-------------:|--------------:|")
    for m in models:
        short_model = m.replace("claude-", "").replace("-20251001", "")
        lines.append(f"| {short_model} | {sum_in[m]:,} | {sum_out[m]:,} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Reproduce: `python3 scripts/run_model_matrix.py --all-self "
                 "--models " + " ".join(models) + "`. "
                 "Each (case, model) cell is one live `run_eval.py` run scored "
                 "by `scripts/score_against_truth.py`._")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", required=True,
                    help="model ids to compare")
    ap.add_argument("--cases", nargs="*", default=None,
                    help="case refs (e.g. self-evaluation/case-01). "
                         "Default: all self cases.")
    ap.add_argument("--all-self", action="store_true",
                    help="run every self-evaluation case")
    ap.add_argument("--download", action="store_true",
                    help="pass --download to run_eval (for external cases)")
    ap.add_argument("--out", type=Path,
                    default=REPO / "docs" / "benchmarks" / "MODEL-COMPARISON.md")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.all_self or not args.cases:
        cases = discover_self_cases()
    else:
        cases = args.cases

    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set (required for live runs).",
              file=sys.stderr)
        return 2

    print(f"Matrix: {len(cases)} cases x {len(args.models)} models = "
          f"{len(cases) * len(args.models)} runs")
    rows = []
    for case in cases:
        for model in args.models:
            rows.append(run_one(case, model,
                                download=args.download, dry_run=args.dry_run))

    if args.dry_run:
        print("\n(dry-run: no table written)")
        return 0

    md = build_markdown(rows, args.models)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md)
    print(f"\nWrote {args.out}")

    # also drop the raw rows next to it for re-aggregation
    raw = args.out.with_suffix(".rows.json")
    raw.write_text(json.dumps(rows, indent=2))
    print(f"Wrote {raw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
