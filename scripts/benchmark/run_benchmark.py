#!/usr/bin/env python3
"""
run_benchmark.py — measure Agentic-DART against a registered public dataset.

Pipeline (per dataset):

    1. Locate the dataset image on disk (or fail with a clear pointer to
       benchmark/download.py).
    2. Optionally mount / extract to an evidence_root layout the dart-agent
       expects. Uses agentic-dart-collector-adapter if installed; falls
       back to a thin internal extraction otherwise.
    3. Run dart_agent against evidence_root with the senior-analyst-v3
       playbook.
    4. Diff dart_agent's findings.json against the dataset's ground-truth.json:
         - true positive  (TP): finding matches a ground-truth entry
         - false negative (FN): ground-truth entry not raised by the agent
         - false positive (FP): finding with no ground-truth match
         - hallucination     : finding lacking any audit_id reference
    5. Verify the audit chain is internally consistent (SHA-256 linkage).
    6. Emit a JSON report under docs/benchmarks/<dataset>_<timestamp>.json
       and append a Markdown row to docs/benchmarks/SUMMARY.md.

Two scoring modes:

    strict   exact-string match on the 'evidence_id' field. Equivalent to
             "did the agent surface the same artefact?"
    lenient  fuzzy match on (artifact_type, host_path) tuple. Equivalent to
             "did the agent surface the same TYPE of evidence from the
             same area of the filesystem, even if it phrased it differently?"

Usage:
    python3 -m benchmark.run_benchmark cfreds --image /data/SCHARDT.dd
    python3 -m benchmark.run_benchmark hadi1  --image /data/Challenge1.dd
    python3 -m benchmark.run_benchmark m57    --image /data/jean.aff

If --image is omitted, the script looks under ./datasets/<short>/<joined_name>.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Make this importable as benchmark.run_benchmark or runnable directly
try:
    from .datasets import DATASETS
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from datasets import DATASETS

REPO = Path(__file__).resolve().parents[2]


# ─── Result types ────────────────────────────────────────────────────────────
@dataclass
class FindingMatch:
    ground_truth_id: str
    agent_finding_id: str | None
    mode: str  # "strict" | "lenient" | "missed"
    confidence: float | None = None


@dataclass
class BenchmarkResult:
    dataset: str
    timestamp: str
    image_path: str
    image_sha256: str | None
    agent_runtime_sec: float
    total_findings: int
    total_ground_truth: int
    # strict
    strict_tp: int = 0
    strict_fn: int = 0
    strict_fp: int = 0
    strict_recall: float = 0.0
    strict_precision: float = 0.0
    # lenient
    lenient_tp: int = 0
    lenient_fn: int = 0
    lenient_fp: int = 0
    lenient_recall: float = 0.0
    lenient_precision: float = 0.0
    # hallucination check
    hallucinations: int = 0
    hallucination_rate: float = 0.0
    # audit chain
    audit_chain_intact: bool = True
    audit_entries: int = 0
    # detail
    matches: list[dict] = field(default_factory=list)


# ─── Locate / verify the image ───────────────────────────────────────────────
def _locate_image(short: str, image_arg: str | None) -> Path:
    spec = DATASETS[short]
    if image_arg:
        p = Path(image_arg)
    else:
        p = REPO / "datasets" / short / spec["joined_name"]
    if not p.exists():
        sys.exit(
            f"image not found at {p}\n"
            f"download with:\n"
            f"    python3 -m benchmark.download {short} ./datasets\n"
            f"or pass --image /path/to/{spec['joined_name']}"
        )
    return p


def _image_sha256(path: Path) -> str:
    """Compute SHA-256 of the image, with progress logging."""
    h = hashlib.sha256()
    total = path.stat().st_size
    seen = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(64 * 1024 * 1024)  # 64 MB
            if not chunk:
                break
            h.update(chunk)
            seen += len(chunk)
            if total:
                pct = 100 * seen / total
                print(f"  hashing image: {pct:5.1f}%", end="\r")
    print()
    return h.hexdigest()


# ─── Evidence prep (adapter or fallback) ─────────────────────────────────────
def _prepare_evidence_root(image: Path, short: str, out_dir: Path) -> Path:
    """
    Convert the dataset image into the evidence_root layout dart_agent reads.

    Preferred: agentic-dart-collector-adapter (if installed alongside).
    Fallback : thin internal extraction (uses sleuthkit if available,
               otherwise reports skipped artefacts).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[evidence-prep] image={image}  → evidence_root={out_dir}")

    adapter = REPO.parent / "agentic-dart-collector-adapter"
    if (adapter / "src" / "dart_collector_adapter" / "__init__.py").exists():
        print(f"  using local agentic-dart-collector-adapter")
        # Invoke its CLI; adapter handles classification + manifest + SHA-256
        env = os.environ.copy()
        env["PYTHONPATH"] = str(adapter / "src") + ":" + env.get("PYTHONPATH", "")
        subprocess.run(
            ["python3", "-m", "dart_collector_adapter",
             "--source", "image", "--input", str(image),
             "--output", str(out_dir),
             "--case-id", short],
            check=True, env=env,
        )
    else:
        # Fallback: write a minimal manifest so dart_agent can still iterate.
        # Production deployment should always have the adapter installed.
        print("  collector-adapter not found; writing minimal manifest only")
        manifest = {
            "case_id": short,
            "source": str(image),
            "adapter_version": "fallback-0",
            "artefacts": [],
            "note": "minimal manifest — full classification requires "
                    "agentic-dart-collector-adapter to be installed",
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    return out_dir


# ─── Run dart_agent ──────────────────────────────────────────────────────────
def _run_agent(evidence_root: Path, output_dir: Path) -> tuple[Path, Path, float]:
    """Invoke dart_agent end-to-end. Returns (findings.json, audit.jsonl, seconds)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[dart_agent] running on evidence_root={evidence_root}")

    cmd = [
        sys.executable, "-m", "dart_agent",
        "--evidence-root", str(evidence_root),
        "--playbook", str(REPO / "dart_playbook" / "senior-analyst-v3.yaml"),
        "--output", str(output_dir),
    ]
    t0 = time.time()
    subprocess.run(cmd, check=True, cwd=REPO)
    dt_sec = time.time() - t0
    print(f"  agent completed in {dt_sec:.1f}s")
    return output_dir / "findings.json", output_dir / "audit.jsonl", dt_sec


# ─── Scoring ─────────────────────────────────────────────────────────────────
def _load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return data


def _load_ground_truth(short: str) -> list[dict]:
    spec = DATASETS[short]
    gt_path = REPO / spec["ground_truth_path"]
    if not gt_path.exists():
        sys.exit(
            f"ground truth not found at {gt_path}\n"
            f"create it from the dataset's published answer key before running."
        )
    data = json.loads(gt_path.read_text())
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return data


def _match_strict(gt: dict, findings: list[dict]) -> dict | None:
    """A finding matches strictly when its evidence_id == gt['evidence_id']."""
    target = gt.get("evidence_id")
    if not target:
        return None
    for f in findings:
        if f.get("evidence_id") == target:
            return f
    return None


def _match_lenient(gt: dict, findings: list[dict]) -> dict | None:
    """
    Lenient: (artifact_type, host_path_prefix) tuple matches, regardless of
    whether the agent assigned the same evidence_id string.
    """
    gt_type = (gt.get("artifact_type") or "").lower()
    gt_path = (gt.get("host_path") or "").lower()
    if not gt_type and not gt_path:
        return None
    for f in findings:
        f_type = (f.get("artifact_type") or "").lower()
        f_path = (f.get("host_path") or "").lower()
        if gt_type and f_type and gt_type == f_type:
            if not gt_path or (gt_path and gt_path in f_path):
                return f
        elif gt_path and f_path and gt_path in f_path:
            return f
    return None


def _verify_audit_chain(audit_path: Path) -> tuple[bool, int]:
    """Verify SHA-256 chain linkage in audit.jsonl. Returns (intact, count)."""
    if not audit_path.exists():
        return False, 0
    entries = []
    with audit_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    if not entries:
        return False, 0

    prev_hash = None
    for i, e in enumerate(entries):
        if i > 0 and e.get("prev_hash") != prev_hash:
            return False, len(entries)
        prev_hash = e.get("entry_hash") or e.get("hash")
    return True, len(entries)


def _detect_hallucinations(findings: list[dict]) -> int:
    """Any finding lacking an audit_id reference is treated as a hallucination."""
    return sum(1 for f in findings if not f.get("audit_id"))


# ─── Orchestrator ────────────────────────────────────────────────────────────
def run(short: str, image_arg: str | None, *, skip_hash: bool = False) -> BenchmarkResult:
    spec = DATASETS[short]
    print(f"\n{'=' * 72}")
    print(f"  benchmark: {spec['title']}")
    print(f"{'=' * 72}")

    image = _locate_image(short, image_arg)
    image_hash = None if skip_hash else _image_sha256(image)
    print(f"image SHA-256: {image_hash or '(skipped)'}")

    workdir = REPO / "datasets" / "_runs" / short
    workdir.mkdir(parents=True, exist_ok=True)
    evidence_root = workdir / "evidence_root"
    output_dir = workdir / "out"

    _prepare_evidence_root(image, short, evidence_root)
    findings_path, audit_path, agent_sec = _run_agent(evidence_root, output_dir)

    findings = _load_findings(findings_path)
    ground_truth = _load_ground_truth(short)
    print(f"\nfindings: {len(findings)}  |  ground truth entries: {len(ground_truth)}")

    # Score
    result = BenchmarkResult(
        dataset=short,
        timestamp=dt.datetime.utcnow().isoformat() + "Z",
        image_path=str(image),
        image_sha256=image_hash,
        agent_runtime_sec=agent_sec,
        total_findings=len(findings),
        total_ground_truth=len(ground_truth),
    )

    matched_strict_finding_ids = set()
    matched_lenient_finding_ids = set()
    for gt in ground_truth:
        s = _match_strict(gt, findings)
        if s:
            result.strict_tp += 1
            matched_strict_finding_ids.add(id(s))
            result.matches.append({"gt": gt.get("id"), "mode": "strict",
                                    "finding": s.get("id")})
        else:
            result.strict_fn += 1

        l = _match_lenient(gt, findings)
        if l:
            result.lenient_tp += 1
            matched_lenient_finding_ids.add(id(l))
        else:
            result.lenient_fn += 1

    # False positives: findings not matching any ground-truth lenient match
    result.strict_fp = len(findings) - len(matched_strict_finding_ids)
    result.lenient_fp = len(findings) - len(matched_lenient_finding_ids)

    # Recall / precision
    if result.total_ground_truth:
        result.strict_recall = result.strict_tp / result.total_ground_truth
        result.lenient_recall = result.lenient_tp / result.total_ground_truth
    if result.total_findings:
        result.strict_precision = result.strict_tp / result.total_findings
        result.lenient_precision = result.lenient_tp / result.total_findings

    # Hallucinations
    result.hallucinations = _detect_hallucinations(findings)
    if result.total_findings:
        result.hallucination_rate = result.hallucinations / result.total_findings

    # Audit chain
    intact, count = _verify_audit_chain(audit_path)
    result.audit_chain_intact = intact
    result.audit_entries = count

    return result


# ─── Reporting ───────────────────────────────────────────────────────────────
def _emit_json(result: BenchmarkResult) -> Path:
    out_dir = REPO / "docs" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result.timestamp.replace(":", "-").split(".")[0]
    out = out_dir / f"{result.dataset}_{stamp}.json"
    out.write_text(json.dumps(asdict(result), indent=2))
    return out


def _append_summary(result: BenchmarkResult) -> None:
    out = REPO / "docs" / "benchmarks" / "SUMMARY.md"
    if not out.exists():
        out.write_text(
            "# Benchmark Summary\n\n"
            "Accuracy of Agentic-DART against public DFIR datasets.\n\n"
            "| Date | Dataset | Findings | GT | Strict Recall | Lenient Recall | Hallucinations | Audit |\n"
            "|------|---------|---------:|---:|--------------:|---------------:|---------------:|:-----:|\n"
        )
    row = (
        f"| {result.timestamp[:10]} "
        f"| {result.dataset} "
        f"| {result.total_findings} "
        f"| {result.total_ground_truth} "
        f"| {result.strict_recall:.2%} "
        f"| {result.lenient_recall:.2%} "
        f"| {result.hallucinations} ({result.hallucination_rate:.1%}) "
        f"| {'✓' if result.audit_chain_intact else '✗'} "
        f"|\n"
    )
    with out.open("a") as f:
        f.write(row)


def _print_summary(r: BenchmarkResult) -> None:
    print("\n" + "=" * 72)
    print(f"  RESULT — {r.dataset}")
    print("=" * 72)
    print(f"  total findings        : {r.total_findings}")
    print(f"  total ground truth    : {r.total_ground_truth}")
    print(f"  agent runtime         : {r.agent_runtime_sec:.1f}s")
    print(f"  image SHA-256         : {r.image_sha256 or '(skipped)'}")
    print()
    print(f"  STRICT  recall {r.strict_recall:.2%} ({r.strict_tp} TP, {r.strict_fn} FN)"
          f"  precision {r.strict_precision:.2%} ({r.strict_fp} FP)")
    print(f"  LENIENT recall {r.lenient_recall:.2%} ({r.lenient_tp} TP, {r.lenient_fn} FN)"
          f"  precision {r.lenient_precision:.2%} ({r.lenient_fp} FP)")
    print()
    print(f"  hallucinations        : {r.hallucinations} ({r.hallucination_rate:.1%})")
    print(f"  audit chain intact    : {'YES' if r.audit_chain_intact else 'NO'}"
          f"  ({r.audit_entries} entries)")
    print()


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", choices=list(DATASETS.keys()) + ["all"])
    p.add_argument("--image", help="path to the dataset image (default: ./datasets/<short>/<joined_name>)")
    p.add_argument("--skip-hash", action="store_true", help="skip image SHA-256 (faster)")
    args = p.parse_args()

    targets = list(DATASETS.keys()) if args.dataset == "all" else [args.dataset]

    for t in targets:
        try:
            r = run(t, args.image, skip_hash=args.skip_hash)
            _print_summary(r)
            json_out = _emit_json(r)
            _append_summary(r)
            print(f"\n  full report: {json_out}")
            print(f"  summary    : {REPO / 'docs' / 'benchmarks' / 'SUMMARY.md'}")
        except SystemExit:
            raise
        except Exception as e:
            print(f"\n[FAIL] {t}: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
