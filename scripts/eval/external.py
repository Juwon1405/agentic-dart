#!/usr/bin/env python3
"""
external.py — measure the LLM on public third-party DFIR images (needs a key).

This proves Agentic-DART runs on real, externally-authored evidence, not just
our own synthetic cases. It drives the external-evaluation cases, which map to
public datasets:

  external-evaluation/case-01  ->  NIST CFReDS Hacking Case   (cfreds)
  external-evaluation/case-02  ->  Ali Hadi Web-Server #1     (hadi1)
  external-evaluation/case-03  ->  Digital Corpora M57 / Jo   (m57)

Per case it follows the flow you'd run by hand:

  1. IMAGE      — if the dataset image is already under ./datasets/<short>/,
                  use it; otherwise download it (resumable).
  2. EVIDENCE   — if the case's evidence_root already exists, run on it as-is.
                  Otherwise, once the image hash checks out, adapt the image
                  into the evidence_root tree (collector adapter if installed,
                  thin sleuthkit extraction otherwise) and STOP at a sorted tree
                  unless we're also analysing this pass.
  3. ANALYSE    — run the live agent over the evidence_root and score against
                  truth.json over the tool-reachable subset (most external
                  answers need tools that are still on the roadmap, so recall is
                  reported over what the current toolset can actually reach).

Heads-up: these images are large (CFReDS ~5 GB, M57 ~10 GB) and the adapt step
is I/O heavy. Use --prepare-only to fetch + hash + materialise the tree without
calling the API.

Usage
-----
  export ANTHROPIC_API_KEY=sk-ant-...

  # one external case, one model (download/adapt if needed, then analyse)
  python3 -m scripts.eval.external --case external-evaluation/case-01

  # all three, comparison matrix
  python3 -m scripts.eval.external \\
      --models claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8

  # just stage the data (no API calls)
  python3 -m scripts.eval.external --prepare-only
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# resolve_auth_mode lets us label each model line with its credential source
# (oauth = cheap subscription, api = metered) before the run starts.
sys.path.insert(0, str(REPO / "dart_agent" / "src"))
try:
    from dart_agent.auth import resolve_auth_mode
except Exception:  # pragma: no cover
    def resolve_auth_mode(_model=None):
        return None
CASE_ROOT = REPO / "examples" / "case-studies"
EXT = CASE_ROOT / "external-evaluation"
DATASETS_DIR = REPO / "datasets"
DEFAULT_MODEL = os.environ.get("DART_MODEL", "claude-haiku-4-5-20251001")
MATRIX_MD = REPO / "docs" / "benchmarks" / "EXTERNAL-COMPARISON.md"

# external case ref -> dataset short key (from scripts/eval/datasets.py)
CASE_TO_SHORT = {
    "external-evaluation/case-01": "cfreds",
    "external-evaluation/case-02": "hadi1",
    "external-evaluation/case-03": "m57",
}


def discover_external_cases() -> list[str]:
    cases = []
    for d in sorted(EXT.iterdir()):
        if d.is_dir() and (d / "truth.json").is_file():
            cases.append(f"external-evaluation/{d.name}")
    return cases


def latest_out_dir(case_ref: str) -> Path | None:
    base = REPO / "out" / case_ref
    if not base.is_dir():
        return None
    runs = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
    return runs[0] if runs else None


def _fmt_recall(r) -> str:
    return "—" if r is None else f"{r*100:.0f}%"


def _fmt_int(n) -> str:
    return "—" if n is None else f"{n:,}"


def _adapt_image_to_evidence_root(image: Path, evidence_root: Path, case_id: str) -> bool:
    """Turn a raw disk image into the evidence_root tree dart_mcp reads.

    Preferred path is the collector adapter (agentic-dart-collector-adapter),
    which knows how to carve the registry hives, browser history, prefetch,
    etc. into the layout the tools expect. If it isn't installed we fall back
    to a thin sleuthkit extraction. Either way the result is a sorted tree
    under evidence_root.
    """
    evidence_root.mkdir(parents=True, exist_ok=True)

    # 1) collector adapter, if importable
    try:
        import dart_collector_adapter  # noqa: F401
        print(f"    adapting via collector adapter → {evidence_root}")
        proc = subprocess.run(
            [sys.executable, "-m", "dart_collector_adapter",
             "--source", "image", "--input", str(image),
             "--output", str(evidence_root), "--case-id", case_id.upper()],
            cwd=str(REPO), capture_output=True, text=True)
        if proc.returncode == 0 and any(evidence_root.iterdir()):
            return True
        print(f"    collector adapter did not populate the tree: "
              f"{(proc.stderr or proc.stdout or '').strip()[:200]}")
    except ImportError:
        pass

    # 2) thin sleuthkit fallback (tsk_recover) — best-effort.
    #
    # A whole-disk image (SCHARDT.dd, an .E01) has a PARTITION TABLE, so calling
    # tsk_recover on the raw image fails with "Cannot determine file system
    # type": there's no filesystem at offset 0, there's an MBR/GPT. The real
    # forensic flow is: (a) if it's an E01, expose it as raw via ewfmount;
    # (b) read the partition table with mmls; (c) run tsk_recover at each
    # filesystem partition's offset. We do exactly that, and also try offset-0
    # directly in case the image happens to be a bare filesystem.
    from shutil import which
    if not which("tsk_recover"):
        print("    no image adapter available (install agentic-dart-collector-"
              "adapter or sleuthkit); evidence_root not built.")
        return False

    print(f"    adapting via sleuthkit tsk_recover → {evidence_root}")

    # (a) If this is an EWF/E01, mount it to a raw image first (ewfmount).
    raw_image = image
    ewf_mnt = None
    if image.suffix.lower() in (".e01", ".ex01", ".s01") and which("ewfmount"):
        ewf_mnt = Path(tempfile.mkdtemp(prefix="dart-ewf-"))
        m = subprocess.run(["ewfmount", str(image), str(ewf_mnt)],
                           capture_output=True, text=True)
        cand = ewf_mnt / "ewf1"
        if m.returncode == 0 and cand.exists():
            raw_image = cand
        else:
            print(f"    ewfmount failed ({(m.stderr or '').strip()[:120]}); "
                  f"trying the .E01 directly")

    def _tsk_recover_at(off_arg: list[str]) -> bool:
        proc = subprocess.run(
            ["tsk_recover", "-a", *off_arg, str(raw_image), str(evidence_root)],
            capture_output=True, text=True)
        return proc.returncode == 0 and any(evidence_root.iterdir())

    built = False
    try:
        # (b) Read the partition table; collect filesystem partition offsets.
        offsets: list[int] = []
        if which("mmls"):
            mm = subprocess.run(["mmls", str(raw_image)],
                               capture_output=True, text=True)
            for line in (mm.stdout or "").splitlines():
                # mmls rows look like: "002:  000:000  0000002048  ...  NTFS / exFAT (0x07)"
                parts = line.split()
                if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
                    low = line.lower()
                    if any(fs in low for fs in
                           ("ntfs", "fat", "ext", "exfat", "hfs", "apfs", "0x07", "0x83")):
                        try:
                            offsets.append(int(parts[2]))  # starting sector
                        except ValueError:
                            continue

        # (c) Try each partition offset (sectors -> tsk -o takes sectors).
        for off in offsets:
            if _tsk_recover_at(["-o", str(off)]):
                built = True
                break

        # Fallback: try the image with no offset (bare filesystem case).
        if not built and _tsk_recover_at([]):
            built = True

        if not built:
            hint = "no filesystem partitions recovered"
            if offsets:
                hint = f"tried offsets {offsets} but recovered nothing"
            print(f"    tsk_recover failed: {hint}")
    finally:
        if ewf_mnt is not None:
            subprocess.run(["fusermount", "-u", str(ewf_mnt)],
                           capture_output=True, text=True)
            try:
                ewf_mnt.rmdir()
            except OSError:
                pass

    if built:
        return True

    print("    no image adapter available (install agentic-dart-collector-"
          "adapter or sleuthkit); evidence_root not built.")
    return False


def prepare(case_ref: str, *, dry_run: bool) -> bool:
    """One-shot: make this case's evidence_root exist, end to end.

    Idempotent and self-contained — no detour through analyze.py:
      1. evidence_root already populated   -> reuse, done.
      2. image already under datasets/      -> skip download.
         image missing                      -> download it (resumable).
      4. adapt the image into evidence_root (collector adapter / sleuthkit).
    Returns True iff evidence_root ends up populated.
    """
    evidence_root = CASE_ROOT / case_ref / "evidence_root"
    if evidence_root.is_dir() and any(evidence_root.iterdir()):
        print(f"  [{case_ref}] evidence_root present — reusing")
        return True

    short = CASE_TO_SHORT.get(case_ref)
    if not short:
        print(f"  [{case_ref}] no dataset mapping", file=sys.stderr)
        return False

    sys.path.insert(0, str(REPO / "scripts"))
    from eval.datasets import DATASETS
    spec = next((v for v in DATASETS.values() if v.get("short") == short), None)
    # download.py stores under the REGISTRY KEY directory (it runs short ->
    # key via _resolve_key), not the friendly short. Compute the same path here
    # so prepare() looks where download() actually wrote, instead of a sibling
    # directory that never gets created. (This was the 'expected image not found
    # after download' skip: file landed in datasets/<key>/, we looked in
    # datasets/<short>/.)
    from eval.download import _resolve_key
    key = _resolve_key(short)
    image = DATASETS_DIR / key / (spec or {}).get("joined_name", f"{short}.img")

    if dry_run:
        action = "reuse" if image.exists() else "download"
        print(f"  DRY-RUN [{case_ref}]: image {action} ({image.name}), "
              f"adapt → {evidence_root}")
        return False

    # download (skips if already present and non-empty).
    if image.exists():
        print(f"  [{case_ref}] image present ({image.name}) — skipping download")
    else:
        print(f"  [{case_ref}] downloading '{short}' …")
    from eval.download import download as fetch
    try:
        fetch(short, DATASETS_DIR)
    except Exception as e:  # noqa: BLE001
        print(f"  [{case_ref}] download failed: {e}", file=sys.stderr)
        return False

    if not image.exists():
        print(f"  [{case_ref}] expected image not found after download: {image}",
              file=sys.stderr)
        return False

    # 4: adapt image -> evidence_root.
    print(f"  [{case_ref}] building evidence_root …")
    ok = _adapt_image_to_evidence_root(image, evidence_root,
                                       case_ref.split("/")[-1])
    if not ok:
        return False
    return evidence_root.is_dir() and any(evidence_root.iterdir())


def run_one(case_ref: str, model: str, *, dry_run: bool) -> dict:
    row = {"case": case_ref, "model": model, "ok": False, "recall": None,
           "gt_detected": None, "gt_scorable": None, "model_findings": None,
           "tokens_in": None, "tokens_out": None, "error": None}

    # Unified prep: ensure evidence_root exists (download + adapt as needed)
    # before any analysis. analyze.py then just reads the prepared tree.
    if not dry_run and not prepare(case_ref, dry_run=False):
        row["error"] = "evidence_root unavailable (prepare failed)"
        print(f"     SKIP: {row['error']}")
        return row

    cmd = [sys.executable, str(REPO / "analyze.py"),
           "--case", case_ref, "--model", model]
    if dry_run:
        print("  DRY-RUN:", " ".join(cmd))
        row["error"] = "dry-run"
        return row

    _auth_mode = resolve_auth_mode(model)
    print(f"  → {case_ref}  [{model} · {_auth_mode}]")
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
          f"findings={row['model_findings']}  tok={row['tokens_in']}/{row['tokens_out']}")
    return row


def build_markdown(rows: list[dict], models: list[str]) -> str:
    today = dt.date.today().isoformat()
    by_case: dict[str, list[dict]] = {}
    for r in rows:
        by_case.setdefault(r["case"], []).append(r)

    out = [
        "# Model comparison — external datasets",
        "",
        f"_Generated {today}. Public third-party images (NIST CFReDS, Ali Hadi, "
        "Digital Corpora M57). Recall is over the tool-reachable subset of each "
        "dataset's ground truth — many external answers require tools still on "
        "the roadmap, so a low number reflects tool coverage, not model skill._",
        "",
    ]
    for case in sorted(by_case):
        short = CASE_TO_SHORT.get(case, "?")
        out.append(f"## {case}  (`{short}`)")
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case", help="one case ref, e.g. external-evaluation/case-01 "
                                   "(default: all 3 external cases)")
    ap.add_argument("--models", nargs="+", default=[DEFAULT_MODEL])
    ap.add_argument("--out", type=Path, default=MATRIX_MD)
    ap.add_argument("--prepare-only", action="store_true",
                    help="fetch + materialise evidence_root, no API calls")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    cases = [args.case] if args.case else discover_external_cases()

    if args.prepare_only:
        print(f"prepare-only: staging {len(cases)} external case(s)\n")
        ok = sum(1 for c in cases if prepare(c, dry_run=args.dry_run))
        print(f"\nStaged {ok}/{len(cases)} evidence trees.")
        return 0 if ok == len(cases) else 1

    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2

    print(f"external-evaluation: {len(cases)} case(s) × {len(args.models)} model(s)\n")
    rows = []
    for case in cases:
        for model in args.models:
            rows.append(run_one(case, model, dry_run=args.dry_run))

    if args.dry_run:
        return 0

    # external feeds the SAME per-case ledger as self — no separate
    # EXTERNAL-COMPARISON file. Updates only this run's cases/models in
    # ledger.json, stamps each, and re-renders SUMMARY.md + MODEL-COMPARISON.md
    # (self + external in one place). Robust import (derived from REPO, not cwd).
    _eval_dir = str(REPO / "scripts" / "eval")
    if _eval_dir not in sys.path:
        sys.path.insert(0, _eval_dir)
    import _ledger
    _ledger.upsert_run(rows, "external")
    # Append-only run log (accumulates over time, separate from the ledger).
    from _history import append_run as _append_run
    _append_run("external", rows, args.models)
    print(f"\nLedger updated: docs/benchmarks/SUMMARY.md (external rows + timestamps)")

    ok = sum(1 for r in rows if r["ok"])
    print(f"\nDone: {ok}/{len(rows)} runs succeeded.")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
