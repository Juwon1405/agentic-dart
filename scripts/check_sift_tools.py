#!/usr/bin/env python3
"""
check_sift_tools.py — report which SIFT adapter tools are actually runnable.

The 25 SIFT adapters each shell out to an external binary (yara, vol,
MFTECmd, ...). When a binary is missing the adapter raises
SiftToolNotFoundError at call time; the native dart_mcp tools still work.
healthcheck.py only confirms the adapters are *registered* (73 tools), not
that their backing binaries are *installed*. This script closes that gap: it
runs the adapters' own resolver (`_which`, honoring the DART_*_BIN env
overrides) for every tool and prints a clear available / missing table, so
you know before a run which adapters will actually execute.

It does not just check PATH — it calls the exact same resolution each adapter
uses, so an env override like DART_YARA_BIN=/opt/yara is reflected correctly.

Usage
-----
  python3 scripts/check_sift_tools.py            # table + summary
  python3 scripts/check_sift_tools.py --json     # machine-readable
  python3 scripts/check_sift_tools.py --strict   # exit 1 if any tool missing

Exit code is 0 by default (missing tools are informational, since native
tools cover those analyses). With --strict, exit 1 when anything is missing.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for pkg in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr"):
    p = str(REPO / pkg / "src")
    if p not in sys.path:
        sys.path.insert(0, p)

# (display name, binary, env override var, adapter module, which-tools it powers)
# Mirrors the _which(...) calls in each adapter; keep in sync if adapters change.
TOOLS = [
    ("YARA",          "yara",            "DART_YARA_BIN",          "yara",
     "sift_yara_scan_file, sift_yara_scan_dir"),
    ("Volatility 3",  "vol",             "DART_VOLATILITY3_BIN",   "volatility3",
     "sift_vol3_* (12 memory tools)"),
    ("Plaso log2timeline", "log2timeline.py", "DART_LOG2TIMELINE_BIN", "plaso",
     "sift_plaso_log2timeline"),
    ("Plaso psort",   "psort.py",        "DART_PSORT_BIN",         "plaso",
     "sift_plaso_psort"),
    ("MFTECmd",       "MFTECmd",         "DART_MFTECMD_BIN",       "mftecmd",
     "sift_mftecmd_parse, sift_mftecmd_timestomp"),
    ("EvtxECmd",      "EvtxECmd",        "DART_EVTXECMD_BIN",      "evtxecmd",
     "sift_evtxecmd_parse, sift_evtxecmd_filter_eids"),
    ("PECmd",         "PECmd",           "DART_PECMD_BIN",         "pecmd",
     "sift_pecmd_parse, sift_pecmd_run_history"),
    ("RECmd",         "RECmd",           "DART_RECMD_BIN",         "recmd",
     "sift_recmd_run_batch, sift_recmd_query_key"),
    ("AmcacheParser", "AmcacheParser",   "DART_AMCACHEPARSER_BIN", "amcacheparser",
     "sift_amcacheparser_parse"),
]


def _resolve(binary: str, env_var: str):
    """Use the adapters' own resolver so env overrides are honored. Falls back
    to a plain PATH lookup if _common can't be imported for any reason."""
    try:
        from dart_mcp.sift_adapters._common import _which, SiftToolNotFoundError
        try:
            return _which(binary, env_var=env_var), None
        except SiftToolNotFoundError as e:
            return None, str(e)
    except Exception:
        found = shutil.which(binary)
        return (found, None) if found else (None, f"{binary} not on PATH")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any tool is missing")
    args = ap.parse_args()

    results = []
    for disp, binary, env_var, module, powers in TOOLS:
        path, err = _resolve(binary, env_var)
        results.append({
            "tool": disp, "binary": binary, "env_var": env_var,
            "adapter": module, "powers": powers,
            "available": path is not None, "path": path,
        })

    available = sum(1 for r in results if r["available"])
    total = len(results)

    if args.json:
        print(json.dumps({
            "available": available, "total": total,
            "all_available": available == total, "tools": results,
        }, indent=2))
    else:
        print(f"SIFT adapter tool availability ({available}/{total} runnable)\n")
        print(f"{'TOOL':<22} {'STATUS':<12} BACKING BINARY / PATH")
        print("-" * 78)
        for r in results:
            if r["available"]:
                status = "available"
                detail = r["path"]
            else:
                status = "MISSING"
                detail = f"{r['binary']} (set {r['env_var']} or add to PATH)"
            print(f"{r['tool']:<22} {status:<12} {detail}")
        print()
        missing = [r for r in results if not r["available"]]
        if missing:
            print("Missing tools — the adapters below raise SiftToolNotFoundError")
            print("until installed. Native dart_mcp tools cover the same analyses,")
            print("so the agent keeps working; these only add SIFT-toolchain parity.\n")
            for r in missing:
                print(f"  • {r['tool']:<18} powers: {r['powers']}")
            print()
            print("Install on a SANS SIFT Workstation:")
            print("  - Just re-run: bash scripts/install.sh")
            print("    (idempotent — installs only what's missing: yara/vol/")
            print("     plaso via apt+pip, EZ Tools staged into bin/zimmerman/")
            print("     which the adapters auto-discover, no env vars needed)")
            print("  - Or point an env var at an existing binary, e.g.")
            print("    export DART_YARA_BIN=/usr/local/bin/yara")
        else:
            print("All SIFT adapter tools are runnable. Every sift_* tool will execute.")

    return 1 if (args.strict and available < total) else 0


if __name__ == "__main__":
    raise SystemExit(main())
