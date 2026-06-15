"""Run the whole benchmark in one shot: demo -> self -> external.

This is the "just show me everything" entry point. It runs all three tiers in
sequence so you don't have to invoke them one by one:

    python3 -m scripts.eval.all --models claude-haiku-4-5-20251001

  1. demo     — the deterministic, no-LLM pipeline check, printed up front as a
                quick sanity taste (does the toolchain even stand up?). No API
                key needed for this part.
  2. self     — the 8 bundled self-evaluation cases (ready evidence_root each).
  3. external — the full-disk public-image cases (NIST CFReDS, Ali Hadi, M57).
                If an image or its adapted evidence_root is missing, external's
                own prepare() downloads the image and runs the collector/
                sleuthkit adapter first, THEN analyzes — all in this one run.

self and external each append a timestamped row to docs/benchmarks/HISTORY.md
(and write their snapshot tables), so a single `all` run records the full
picture in one place. The demo is just a printed taster; it isn't scored into
the ledger.

API key: demo runs without one; self/external need ANTHROPIC_API_KEY. If it's
absent we still run the demo, then stop before the LLM tiers with a clear note.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

DEFAULT_MODEL = "claude-haiku-4-5-20251001"


def _rule(title: str) -> None:
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Run demo + self + external benchmarks in one pass.")
    ap.add_argument("--models", nargs="+", default=[DEFAULT_MODEL],
                    help=f"Models for self/external (default: {DEFAULT_MODEL}). "
                         "The demo is deterministic and ignores this.")
    ap.add_argument("--skip-demo", action="store_true",
                    help="Skip the up-front deterministic demo taster.")
    ap.add_argument("--skip-external", action="store_true",
                    help="Run demo + self only (external needs the disk images).")
    args = ap.parse_args(argv)

    from eval import self as self_mod  # noqa: WPS433
    from eval import external as external_mod  # noqa: WPS433

    # 1) Demo taster — deterministic, no key, just prove the rig stands up.
    #    Run in a SUBPROCESS so the demo's evidence_root can't be polluted by
    #    self/external having already imported dart_mcp in this process —
    #    dart_mcp freezes EVIDENCE_ROOT at import time, so an in-process demo
    #    would inherit the wrong root. self/external are already
    #    subprocess-isolated; this brings the demo in line with them.
    if not args.skip_demo:
        _rule("1/3  demo — deterministic pipeline taster (no LLM, no key)")
        subprocess.run([sys.executable, "-m", "scripts.eval.demo"],
                       cwd=str(REPO))

    # self/external need a key. Check once; if missing, stop cleanly after demo.
    if not os.environ.get("ANTHROPIC_API_KEY"):
        _rule("self + external need ANTHROPIC_API_KEY")
        print("  The demo above ran without a key. To run the scored tiers:")
        print("    export ANTHROPIC_API_KEY='sk-ant-...'")
        print("    python3 -m scripts.eval.all")
        return 0

    rc = 0

    # 2) Self — 8 bundled cases.
    _rule(f"2/3  self-evaluation — 8 cases × {len(args.models)} model(s)")
    try:
        rc |= self_mod.main(["--models", *args.models])
    except SystemExit as e:
        rc |= int(e.code or 0)

    # 3) External — full-disk public images. prepare() handles download+adapt
    #    for any case whose image/evidence_root is missing, then analyzes.
    if args.skip_external:
        print("\n(--skip-external set; external tier skipped.)")
        return rc

    _rule(f"3/3  external — full-disk public images × {len(args.models)} model(s)")
    print("  Missing images/evidence are downloaded and adapted first, then "
          "analyzed — all in this run.\n")
    try:
        rc |= external_mod.main(["--models", *args.models])
    except SystemExit as e:
        rc |= int(e.code or 0)

    _rule("done — demo + self + external complete")
    print("  Snapshots : docs/benchmarks/MODEL-COMPARISON.md, SUMMARY.md")
    print("  Trend     : docs/benchmarks/HISTORY.md  (one row per tier, appended)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
