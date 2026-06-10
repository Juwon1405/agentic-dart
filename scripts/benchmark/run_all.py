#!/usr/bin/env python3
"""
run_all.py — single-command benchmark runner for measured benchmark layers.

Splits work into two layers:

  LAYER 1 BASELINE (case-01)
    Evaluated against examples/sample-evidence-realistic/ — bundled with
    the repository, no external download needed. Uses the existing
    scripts/measure_accuracy.py harness and records only that measured case.

  LAYER 2 (case-08 to case-10)
    Evaluated against externally-hosted third-party datasets (NIST CFReDS,
    Ali Hadi, Digital Corpora M57). Requires one-time ~13 GB download
    via benchmark/download.py.

Both layers emit measured results into docs/benchmarks/SUMMARY.md. The runner
does not fabricate rows for case studies that were not executed.

Usage:

    # Layer 1 only (fast, no download needed, ~10 seconds)
    python3 -m scripts.benchmark.run_all --layer 1

    # Layer 2 only (slow, requires ./datasets/ to be populated)
    python3 -m scripts.benchmark.run_all --layer 2

    # Both layers (the SANS-submission default)
    python3 -m scripts.benchmark.run_all

    # Auto-fetch missing Layer-2 datasets before running
    python3 -m scripts.benchmark.run_all --download

Exit codes:
    0   all configured cases evaluated successfully
    1   one or more cases failed (script continues past per-case failure
        so a partial summary is still produced)
    2   no cases ran at all (configuration error)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

try:
    from .datasets import DATASETS
    from .download import download as fetch_dataset
    from .run_benchmark import run as run_external_benchmark
    from .run_benchmark import _emit_json, _append_summary, _print_summary
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from datasets import DATASETS
    from download import download as fetch_dataset
    from run_benchmark import run as run_external_benchmark
    from run_benchmark import _emit_json, _append_summary, _print_summary

REPO = Path(__file__).resolve().parents[2]


# ─── Layer 1: measured bundled baseline ─────────────────────────────────────
LAYER_1_BASELINE_CASE = "case-01-ipkvm-insider"


def run_layer_1(variant: str = "realistic") -> int:
    """
    Run measure_accuracy.py against the bundled evidence tree. Returns 0 on
    success, non-zero on harness failure.
    """
    print("\n" + "=" * 72)
    print("  LAYER 1 — measured bundled baseline (case-01)")
    print(f"  evidence: examples/sample-evidence-{variant}/")
    print("=" * 72)

    if not (REPO / f"examples/sample-evidence-{variant}").exists():
        print(f"\n[FAIL] examples/sample-evidence-{variant}/ not found.")
        print(f"       Either you are in the wrong directory or the")
        print(f"       repository was cloned incompletely.")
        return 1

    cmd = [
        sys.executable, "scripts/measure_accuracy.py",
        "--variant", variant,
    ]
    print(f"  $ {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="" if proc.stderr.endswith("\n") else "\n")
    if proc.returncode != 0:
        print(f"\n[FAIL] measure_accuracy.py returned {proc.returncode}")
        return proc.returncode

    try:
        measurement = _extract_json_summary(proc.stdout)
    except Exception as e:
        print(f"\n[FAIL] could not parse measure_accuracy.py JSON: {e}")
        return 1

    _append_layer_1_summary(variant, measurement)
    return 0


def _extract_json_summary(stdout: str) -> dict:
    start = stdout.find("{")
    if start < 0:
        raise ValueError("no JSON object found")
    return json.loads(stdout[start:])


def _append_layer_1_summary(variant: str, measurement: dict) -> None:
    """
    Append the measured case-01 baseline row to docs/benchmarks/SUMMARY.md.
    """
    summary_path = REPO / "docs" / "benchmarks" / "SUMMARY.md"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if not summary_path.exists():
        summary_path.write_text(
            "# Benchmark Summary\n\n"
            "Accuracy of Agentic-DART against measured bundled and external DFIR datasets.\n\n"
            "| Date | Case | Findings | GT | Strict Recall | Lenient Recall | Hallucinations | Audit |\n"
            "|------|------|---------:|---:|--------------:|---------------:|---------------:|:-----:|\n"
        )

    today = dt.date.today().isoformat()
    case_name = f"{LAYER_1_BASELINE_CASE} ({variant})"

    existing_keys = set()
    if summary_path.exists():
        for line in summary_path.read_text().split("\n"):
            if line.startswith("| ") and "%" in line:
                cells = [c.strip() for c in line.split("|")]
                if len(cells) >= 3:
                    existing_keys.add((cells[1], cells[2]))

    if (today, case_name) in existing_keys:
        print(f"  → summary row already present for {case_name} on {today}")
        return

    recall_pct = float(measurement.get("recall", 0.0)) * 100
    hallucinations = int(measurement.get("hallucination_count", 0))
    findings = int(measurement.get("reported_count", 0))
    gt = int(measurement.get("ground_truth_count", 0))
    halluc_rate = (hallucinations / findings * 100) if findings else 0.0
    audit_ok = "✓" if measurement.get("evidence_integrity_preserved") else "!"

    with summary_path.open("a") as f:
        f.write(
            f"| {today} "
            f"| {case_name} "
            f"| {findings} "
            f"| {gt} "
            f"| {recall_pct:.2f}% "
            f"| {recall_pct:.2f}% "
            f"| {hallucinations} ({halluc_rate:.1f}%) "
            f"| {audit_ok} "
            f"|\n"
        )
    print(f"  → appended measured layer-1 row to {summary_path}")


# ─── Layer 2: external cases (08-10) ─────────────────────────────────────────
LAYER_2_DATASETS = ["cfreds_hacking_case", "hadi_challenge_1", "m57_jo"]


def run_layer_2(*, auto_download: bool, skip_hash: bool) -> int:
    """
    Run run_benchmark.py against each registered external dataset.
    Returns 0 if all succeeded, non-zero if any failed.
    """
    print("\n" + "=" * 72)
    print("  LAYER 2 — external cases (case-08 to case-10)")
    print(f"  datasets: {', '.join(LAYER_2_DATASETS)}")
    print("=" * 72)

    failures = 0
    for short in LAYER_2_DATASETS:
        spec = DATASETS[short]
        image_path = REPO / "datasets" / short / spec["joined_name"]
        if not image_path.exists():
            if auto_download:
                print(f"\n[fetch] {short} → ./datasets/{short}/")
                try:
                    fetch_dataset(short, REPO / "datasets")
                except Exception as e:
                    print(f"[FAIL] download failed for {short}: {e}")
                    failures += 1
                    continue
            else:
                print(
                    f"\n[SKIP] {short}: image not found at {image_path}\n"
                    f"       Run with --download to fetch automatically, or:\n"
                    f"           python3 -m scripts.benchmark.download {short} ./datasets"
                )
                failures += 1
                continue

        try:
            result = run_external_benchmark(short, str(image_path), skip_hash=skip_hash)
            _print_summary(result)
            json_out = _emit_json(result)
            _append_summary(result)
            print(f"  full report: {json_out}")
        except Exception as e:
            print(f"\n[FAIL] {short}: {e}")
            failures += 1

    return 0 if failures == 0 else 1


# ─── Orchestrator ────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--layer", choices=["1", "2", "both"], default="both",
        help="which layer to run (default: both)"
    )
    p.add_argument(
        "--variant", choices=["reference", "realistic"], default="realistic",
        help="layer-1 evidence variant (default: realistic — production noise ratio)"
    )
    p.add_argument(
        "--download", action="store_true",
        help="auto-fetch layer-2 datasets if missing (~13 GB on first run)"
    )
    p.add_argument(
        "--skip-hash", action="store_true",
        help="skip layer-2 image SHA-256 (faster, less safe)"
    )
    args = p.parse_args()

    start = dt.datetime.now(dt.timezone.utc).isoformat()
    print(f"\nstart: {start}")
    print(f"repo:  {REPO}")
    print(f"layer: {args.layer}")

    rc_total = 0
    ran_any = False

    if args.layer in ("1", "both"):
        rc = run_layer_1(args.variant)
        rc_total |= rc
        ran_any = True

    if args.layer in ("2", "both"):
        rc = run_layer_2(auto_download=args.download, skip_hash=args.skip_hash)
        rc_total |= rc
        ran_any = True

    if not ran_any:
        print("\n[FAIL] no layer selected — nothing to do", file=sys.stderr)
        return 2

    print("\n" + "=" * 72)
    summary_path = REPO / "docs" / "benchmarks" / "SUMMARY.md"
    if summary_path.exists():
        print(f"  unified summary: {summary_path}")
    else:
        print(f"  unified summary: (not yet written)")
    print(f"  layer-1 detail : {REPO / 'docs' / 'accuracy-report.md'}")
    print(f"  layer-2 detail : {REPO / 'docs' / 'benchmarks'}/")
    print("=" * 72)
    print(f"\nend: {dt.datetime.now(dt.timezone.utc).isoformat()}")
    print(f"exit code: {rc_total}")
    return rc_total


if __name__ == "__main__":
    sys.exit(main())
