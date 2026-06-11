#!/usr/bin/env python3
"""
run_eval.py — the primary, user-facing Agentic-DART evaluation command.

    python3 run_eval.py                                  # all bundled self-eval cases
    python3 run_eval.py --case self-evaluation/case-01
    python3 run_eval.py --case external-evaluation/case-01 --download
    python3 run_eval.py --model claude-sonnet-4-6

This is **live mode only**: it drives the real Claude reasoning loop over the
read-only MCP forensic tools. It authenticates with either an ANTHROPIC_API_KEY
or a local Claude Code login (`claude login`); if neither is present it fails
fast, before any expensive work, with an actionable message. There is no public
deterministic / dry-run / fake mode here — those remain low-level developer
commands (`python3 -m dart_agent ...`, `scripts/measure_accuracy.py`).

Cases are discovered dynamically from examples/case-studies/<tier>/case-*/.
Each case is self-contained: README.md + truth.json + (bundled or downloaded)
evidence_root/. Output for each run is written to:

    out/<tier>/<case-id>/<timestamp>/
        findings.json  report.json  summary.json
        audit.jsonl    progress.jsonl   (+ live_* transcripts)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent
CASE_ROOT = REPO / "examples" / "case-studies"
TIERS = ("self-evaluation", "external-evaluation")

# The single source of truth for the default model. Kept in sync with the
# dart_agent default; override per run with --model or the DART_MODEL env var.
DEFAULT_MODEL = "claude-haiku-4-5-20251001"

# Map a case directory to the external dataset short-name used by the
# downloader, so --download and the remediation hint print the exact command.
EXTERNAL_DATASET_BY_CASE = {
    "external-evaluation/case-01": "cfreds",
    "external-evaluation/case-02": "hadi1",
    "external-evaluation/case-03": "m57",
}

NO_CREDS_MESSAGE = (
    "Error: no Claude credentials found. Do one of:\n"
    "  export ANTHROPIC_API_KEY='sk-...'   # an Anthropic API key, or\n"
    "  claude login                        # sign in with Claude Code"
)


def _have_credentials() -> bool:
    """True when live mode can authenticate: an ANTHROPIC_API_KEY env var, or a
    local Claude Code login (`claude login` -> ~/.claude/.credentials.json)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    for pkg in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr"):
        p = str(REPO / pkg / "src")
        if p not in sys.path:
            sys.path.insert(0, p)
    try:
        from dart_agent.auth import has_any_credentials
        return bool(has_any_credentials())
    except Exception:  # noqa: BLE001 — any import/lookup failure => treat as no creds
        return False


@dataclass
class Case:
    tier: str
    case_id: str           # e.g. "case-01"
    ref: str               # e.g. "self-evaluation/case-01"
    path: Path
    truth_path: Path
    evidence_root: Path

    @property
    def has_evidence(self) -> bool:
        return self.evidence_root.is_dir() and any(self.evidence_root.iterdir())


def discover_cases(root: Path = CASE_ROOT) -> list[Case]:
    """Dynamically discover every case-*/ under each tier. No case numbers are
    special-cased."""
    cases: list[Case] = []
    for tier in TIERS:
        tier_dir = root / tier
        if not tier_dir.is_dir():
            continue
        for case_dir in sorted(tier_dir.glob("case-*")):
            if not case_dir.is_dir():
                continue
            cases.append(Case(
                tier=tier,
                case_id=case_dir.name,
                ref=f"{tier}/{case_dir.name}",
                path=case_dir,
                truth_path=case_dir / "truth.json",
                evidence_root=case_dir / "evidence_root",
            ))
    return cases


def get_case(ref: str, root: Path = CASE_ROOT) -> Case:
    ref = ref.strip().strip("/")
    for c in discover_cases(root):
        if c.ref == ref or c.case_id == ref:
            return c
    known = ", ".join(c.ref for c in discover_cases(root))
    raise SystemExit(f"Error: unknown case '{ref}'. Known cases:\n  " +
                     "\n  ".join(known.split(", ")))


def _download_hint(case: Case) -> str:
    short = EXTERNAL_DATASET_BY_CASE.get(case.ref)
    if short:
        return (f"    python3 -m scripts.benchmark.download {short} "
                f"{case.evidence_root.parent}")
    return f"    (populate {case.evidence_root}/ with the case evidence)"


def _resolve_evidence(case: Case, *, allow_download: bool) -> int:
    """Validate a case is runnable. Returns 0 if ready, non-zero otherwise,
    printing fail-fast diagnostics with clear remediation."""
    if not case.truth_path.is_file():
        print(f"Error: {case.ref} is missing truth.json at {case.truth_path}. "
              f"This is a configuration error.", file=sys.stderr)
        return 2

    if case.has_evidence:
        return 0

    # No evidence yet.
    if case.tier == "external-evaluation":
        if allow_download:
            return _run_download(case)
        print(f"Error: {case.ref} has no evidence_root yet (external dataset is "
              f"not bundled).\nDownload it first, or re-run with --download:\n"
              f"{_download_hint(case)}", file=sys.stderr)
        return 3

    print(f"Error: {case.ref} has no bundled evidence_root at "
          f"{case.evidence_root}.\nOnly self-evaluation/case-01 ships bundled "
          f"evidence; the other self-evaluation cases are scenario "
          f"specifications (README.md + truth.json) without a packaged "
          f"evidence tree.", file=sys.stderr)
    return 3


def _run_download(case: Case) -> int:
    short = EXTERNAL_DATASET_BY_CASE.get(case.ref)
    if not short:
        print(f"Error: no downloader mapping for {case.ref}.", file=sys.stderr)
        return 3
    sys.path.insert(0, str(REPO / "scripts"))
    from benchmark.download import download as fetch  # noqa: WPS433
    print(f"[download] fetching {short} into {case.evidence_root.parent}/ ...")
    try:
        fetch(short, case.evidence_root.parent)
    except Exception as e:  # noqa: BLE001
        print(f"Error: download failed for {case.ref}: {e}", file=sys.stderr)
        return 3
    if not case.has_evidence:
        print(f"Error: download completed but {case.evidence_root} is still "
              f"empty; the raw image must be adapted into an evidence_root "
              f"(see the collector adapter --source image).", file=sys.stderr)
        return 3
    return 0


def _timestamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%dT%H%M%S")


def run_case(case: Case, *, model: str, max_iter: int, allow_download: bool) -> int:
    rc = _resolve_evidence(case, allow_download=allow_download)
    if rc != 0:
        return rc

    out_dir = REPO / "out" / case.tier / case.case_id / _timestamp()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Wire the agent to this case's own evidence_root.
    os.environ["DART_EVIDENCE_ROOT"] = str(case.evidence_root)
    for pkg in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr"):
        p = str(REPO / pkg / "src")
        if p not in sys.path:
            sys.path.insert(0, p)

    print(f"[run_eval] case={case.ref} model={model}")
    print(f"[run_eval] evidence_root={case.evidence_root}")
    print(f"[run_eval] out={out_dir}")

    from dart_agent import main as agent_main
    rc = agent_main([
        "--case", case.ref,
        "--out", str(out_dir),
        "--mode", "live",
        "--model", model,
        "--max-iterations", str(max_iter),
    ])

    _normalize_outputs(case, out_dir, model)
    print(f"[run_eval] done: {out_dir}")
    return rc


def _normalize_outputs(case: Case, out_dir: Path, model: str) -> None:
    """Map the agent's native live outputs into the canonical filenames the
    eval layout promises (findings.json / report.json / summary.json)."""
    live_summary = out_dir / "live_summary.json"
    findings, usage, iters = [], {}, None
    if live_summary.is_file():
        data = json.loads(live_summary.read_text())
        findings = data.get("findings", [])
        usage = data.get("usage", {})
        iters = data.get("iterations")
        (out_dir / "report.json").write_text(json.dumps(data, indent=2))
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2))
    (out_dir / "summary.json").write_text(json.dumps({
        "case": case.ref,
        "model": model,
        "evidence_root": str(case.evidence_root),
        "findings_count": len(findings),
        "iterations": iters,
        "usage": usage,
        "out_dir": str(out_dir),
    }, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_eval.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Agentic-DART evaluation runner (live mode only).",
        epilog="examples:\n"
               "  python3 run_eval.py\n"
               "  python3 run_eval.py --case self-evaluation/case-01\n"
               "  python3 run_eval.py --case external-evaluation/case-01 --download\n",
    )
    p.add_argument("--case", default=None,
                   help="Case to run, e.g. self-evaluation/case-01. "
                        "Omit to run all bundled self-evaluation cases.")
    p.add_argument("--model", default=os.environ.get("DART_MODEL", DEFAULT_MODEL),
                   help=f"Anthropic model id (default: {DEFAULT_MODEL}).")
    p.add_argument("--download", action="store_true",
                   help="Fetch the external dataset first if its evidence_root "
                        "is not present.")
    p.add_argument("--max-iterations", type=int, default=8,
                   help="Max agent iterations per case (default: 8).")
    p.add_argument("--list", action="store_true",
                   help="List discovered cases and exit (no API key required).")
    return p


def _print_case_list() -> int:
    for c in discover_cases():
        evid = "bundled" if c.has_evidence else "download"
        print(f"  {c.ref:32s} evidence={evid}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        return _print_case_list()

    # Fail fast BEFORE any expensive work if no credentials are present.
    if not _have_credentials():
        print(NO_CREDS_MESSAGE, file=sys.stderr)
        return 1

    if args.case:
        targets = [get_case(args.case)]
    else:
        # Default: every self-evaluation case that has bundled evidence.
        targets = [c for c in discover_cases()
                   if c.tier == "self-evaluation" and c.has_evidence]
        if not targets:
            print("Error: no bundled self-evaluation cases found.", file=sys.stderr)
            return 2
        skipped = [c.ref for c in discover_cases()
                   if c.tier == "self-evaluation" and not c.has_evidence]
        if skipped:
            print(f"[run_eval] skipping {len(skipped)} self-eval scenario "
                  f"spec(s) without bundled evidence: {', '.join(skipped)}")

    rc_total = 0
    for case in targets:
        rc_total |= run_case(case, model=args.model,
                             max_iter=args.max_iterations,
                             allow_download=args.download)
    return rc_total


if __name__ == "__main__":
    raise SystemExit(main())
