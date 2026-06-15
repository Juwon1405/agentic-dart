#!/usr/bin/env python3
"""
self.py — measure the LLM on the self-evaluation cases (needs an API key).

This is where the real model numbers come from. Each self case now has its own
self-contained evidence_root (only that scenario's artifacts plus benign noise),
so a clean recall falls out per case without any prompt hint: the agent has to
discover the incident from the evidence itself.

For every (case, model) it runs the live agent, scores the findings against the
case's truth.json over the tool-reachable subset, and records recall + token
cost. With one model it reads as a simple per-case list; with several it writes
the comparison matrix to docs/benchmarks/MODEL-COMPARISON.md so a future model
can be dropped in and re-measured identically.

Run `python3 -m scripts.eval.demo` first to confirm the toolchain — if demo is
green, any low recall here is the model, not the rig.

Usage
-----
  export ANTHROPIC_API_KEY=sk-ant-...

  # all 8 self cases, one model (quick)
  python3 -m scripts.eval.self

  # one case
  python3 -m scripts.eval.self --case self-evaluation/case-01

  # full model comparison -> docs/benchmarks/MODEL-COMPARISON.md
  python3 -m scripts.eval.self \\
      --models claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8

  --dry-run prints the plan without calling the API.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CASE_ROOT = REPO / "examples" / "case-studies"
SELF = CASE_ROOT / "self-evaluation"
DEFAULT_MODEL = os.environ.get("DART_MODEL", "claude-haiku-4-5-20251001")
MATRIX_MD = REPO / "docs" / "benchmarks" / "MODEL-COMPARISON.md"
SUMMARY_MD = REPO / "docs" / "benchmarks" / "SUMMARY.md"


def discover_self_cases() -> list[str]:
    cases = []
    for d in sorted(SELF.iterdir()):
        if d.is_dir() and (d / "truth.json").is_file():
            cases.append(f"self-evaluation/{d.name}")
    return cases


def latest_out_dir(case_ref: str) -> Path | None:
    base = REPO / "out" / case_ref
    if not base.is_dir():
        return None
    runs = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
    return runs[0] if runs else None


def run_one(case_ref: str, model: str, *, dry_run: bool) -> dict:
    cmd = [sys.executable, str(REPO / "analyze.py"), "--case", case_ref, "--model", model]
    row = {"case": case_ref, "model": model, "ok": False, "recall": None,
           "gt_detected": None, "gt_scorable": None, "model_findings": None,
           "tokens_in": None, "tokens_out": None, "error": None}

    if dry_run:
        print("  DRY-RUN:", " ".join(cmd))
        row["error"] = "dry-run"
        return row

    print(f"  → {case_ref}  [{model}]")
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        row["error"] = tail[-1] if tail else f"exit {proc.returncode}"
        print(f"     FAILED: {row['error']}")
        return row

    out_dir = latest_out_dir(case_ref)
    if not out_dir:
        row["error"] = "no output dir"
        return row

    findings_path = out_dir / "findings.json"
    truth_path = CASE_ROOT / case_ref / "truth.json"

    try:
        summ = json.loads((out_dir / "summary.json").read_text())
        usage = summ.get("usage", {})
        row["tokens_in"] = usage.get("input_tokens")
        row["tokens_out"] = usage.get("output_tokens")
        row["model_findings"] = summ.get("findings_count")
    except Exception:
        pass

    if truth_path.is_file():
        score_cmd = [sys.executable, str(REPO / "scripts" / "eval" / "score.py"),
                     "--findings", str(findings_path), "--truth", str(truth_path), "--json"]
        sp = subprocess.run(score_cmd, cwd=str(REPO), capture_output=True, text=True)
        if sp.returncode == 0 and sp.stdout.strip():
            try:
                s = json.loads(sp.stdout.strip())
                row["recall"] = s.get("recall")
                row["gt_detected"] = s.get("gt_detected")
                row["gt_scorable"] = s.get("gt_scorable")
                if row["model_findings"] is None:
                    row["model_findings"] = s.get("model_findings")
            except Exception:
                pass

    row["ok"] = True
    print(f"     recall={_fmt_recall(row['recall'])} "
          f"({row['gt_detected']}/{row['gt_scorable']} scorable)  "
          f"findings={row['model_findings']}  "
          f"tok={row['tokens_in']}/{row['tokens_out']}")
    return row


def _fmt_recall(r) -> str:
    return "—" if r is None else f"{r*100:.0f}%"


def _fmt_int(n) -> str:
    return "—" if n is None else f"{n:,}"


def build_markdown(rows: list[dict], models: list[str]) -> str:
    today = dt.date.today().isoformat()
    by_case: dict[str, list[dict]] = {}
    for r in rows:
        by_case.setdefault(r["case"], []).append(r)

    out = [
        "# Model comparison — self-evaluation",
        "",
        f"_Generated {today}. Each (case, model) cell is one live `analyze.py` "
        "run scored by `scripts/eval/score.py` over the tool-reachable "
        "ground truth. Recall is detected / scorable findings._",
        "",
    ]
    for case in sorted(by_case):
        out.append(f"## {case}")
        out.append("")
        out.append("| Model | Recall | Detected/Scorable | Model findings | Tokens in | Tokens out |")
        out.append("|---|---|---|---|---|---|")
        for model in models:
            r = next((x for x in by_case[case] if x["model"] == model), None)
            if not r:
                continue
            if r.get("error") and r["error"] != "dry-run":
                out.append(f"| `{model}` | _err_ | — | — | — | — |")
                continue
            det = "—" if r["gt_detected"] is None else f"{r['gt_detected']}/{r['gt_scorable']}"
            out.append(f"| `{model}` | {_fmt_recall(r['recall'])} | {det} | "
                       f"{_fmt_int(r['model_findings'])} | {_fmt_int(r['tokens_in'])} | "
                       f"{_fmt_int(r['tokens_out'])} |")
        out.append("")
    return "\n".join(out) + "\n"


def _write_summary(rows: list[dict], models: list[str]) -> None:
    """Write a compact, human-readable digest to SUMMARY.md.

    The matrix file is the full table; this is the at-a-glance view: per-model
    average recall plus a per-case recall column for each model. Rewritten every
    run so it always reflects the latest measurement."""
    today = dt.date.today().isoformat()
    cases = sorted({r["case"] for r in rows})

    def cell(case: str, model: str) -> str:
        r = next((x for x in rows if x["case"] == case and x["model"] == model), None)
        if not r or r.get("recall") is None:
            return "—"
        return f"{r['recall']*100:.0f}%"

    def model_avg(model: str) -> str:
        vals = [r["recall"] for r in rows
                if r["model"] == model and r.get("recall") is not None]
        return f"{sum(vals)/len(vals)*100:.0f}%" if vals else "—"

    out = [
        "# Benchmark summary — self-evaluation",
        "",
        f"_Last run {today}. Recall is detected / scorable ground-truth findings "
        "per case (see `MODEL-COMPARISON.md` for the full table with token "
        "counts). Regenerated every `python3 -m scripts.eval.self` run._",
        "",
        "## Average recall",
        "",
        "| Model | Mean recall (self cases) |",
        "|---|---|",
    ]
    for m in models:
        out.append(f"| `{m}` | {model_avg(m)} |")
    out += ["", "## Per-case recall", "",
            "| Case | " + " | ".join(f"`{m}`" for m in models) + " |",
            "|---|" + "|".join("---" for _ in models) + "|"]
    for case in cases:
        out.append(f"| {case} | " + " | ".join(cell(case, m) for m in models) + " |")
    out.append("")
    SUMMARY_MD.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_MD.write_text("\n".join(out) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case", help="one case ref, e.g. self-evaluation/case-01 "
                                   "(default: all 8 self cases)")
    ap.add_argument("--models", nargs="+", default=[DEFAULT_MODEL],
                    help=f"models to run (default: {DEFAULT_MODEL})")
    ap.add_argument("--out", type=Path, default=MATRIX_MD,
                    help="matrix markdown path (written when >1 model)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2

    cases = [args.case] if args.case else discover_self_cases()
    print(f"self-evaluation: {len(cases)} case(s) × {len(args.models)} model(s)\n")

    rows = []
    for case in cases:
        for model in args.models:
            rows.append(run_one(case, model, dry_run=args.dry_run))

    if args.dry_run:
        return 0

    # Always persist results — single model or several. The matrix file holds
    # the full per-case x per-model table; SUMMARY.md holds a compact
    # human-readable digest. Both are rewritten every run so they reflect the
    # latest measurement rather than going stale.
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Per-case ledger (record of record): updates only this run's cases/models,
    # stamps each with the current time, and renders SUMMARY.md +
    # MODEL-COMPARISON.md covering self AND external together.
    _eval_dir = str(REPO / "scripts" / "eval")
    if _eval_dir not in sys.path:
        sys.path.insert(0, _eval_dir)
    import _ledger
    _ledger.upsert_run(rows, "self")
    # Append-only run log (separate from the ledger; accumulates over time).
    from _history import append_run as _append_run
    _append_run("self", rows, args.models)
    print(f"\nResults written:")
    print(f"  docs/benchmarks/SUMMARY.md            (per-case ledger, self+external)")
    print(f"  docs/benchmarks/MODEL-COMPARISON.md   (per-case detail)")
    print(f"  docs/benchmarks/HISTORY.md            (append-only run log)")

    ok = sum(1 for r in rows if r["ok"])
    print(f"\nDone: {ok}/{len(rows)} runs succeeded.")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
