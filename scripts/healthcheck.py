#!/usr/bin/env python3
"""
healthcheck.py — API-free readiness check for Agentic-DART.

Validates that a clone is correctly installed and wired without needing an
Anthropic API key and without running any live model call or producing any
fabricated findings:

  1. Python version (>= 3.10)
  2. Local package imports (dart_audit / dart_mcp / dart_agent / dart_corr)
  3. Third-party dependency versions (anthropic / mcp / duckdb / yaml ...)
  4. MCP tool surface count (native + SIFT split, > 0)
  5. Collector-adapter CLI (`python3 -m dart_collector_adapter --help`)
  6. Tiered case-study layout (both tiers discoverable; case-01 evidence bundled)
  7. run_eval.py is live-only and fails fast without a key (no fake mode)

Exit code 0 and the success banner only when every check passes.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC_DIRS = [REPO / pkg / "src" for pkg in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr")]
for _p in SRC_DIRS:
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
sys.path.insert(0, str(REPO))

_failures: list[str] = []
_ok: list[str] = []


def _check(name: str, fn) -> None:
    try:
        detail = fn()
        _ok.append(f"[ok]   {name}: {detail}")
    except Exception as e:  # noqa: BLE001
        _failures.append(f"[FAIL] {name}: {type(e).__name__}: {e}")


# 1. Python version
def _py_version():
    v = sys.version_info
    assert v >= (3, 10), f"Python 3.10+ required, found {v.major}.{v.minor}"
    return f"{v.major}.{v.minor}.{v.micro}"


# 2. local package imports
def _imports():
    for mod in ("dart_audit", "dart_mcp", "dart_agent", "dart_corr"):
        importlib.import_module(mod)
    return "dart_audit, dart_mcp, dart_agent, dart_corr importable"


# 3. third-party deps + versions
def _deps():
    from importlib.metadata import version
    seen = []
    for dist in ("anthropic", "mcp", "duckdb", "PyYAML", "python-registry", "requests"):
        try:
            seen.append(f"{dist}=={version(dist)}")
        except Exception:  # noqa: BLE001 — optional ones may be absent
            seen.append(f"{dist}=<missing>")
    missing = [s for s in seen if s.endswith("<missing>")]
    assert not missing, f"missing dependencies: {missing} (pip install -r requirements.txt)"
    return ", ".join(seen)


# 4. MCP tool surface
def _mcp_surface():
    os.environ.setdefault("DART_EVIDENCE_ROOT", "/tmp/dart-healthcheck-evidence")
    Path(os.environ["DART_EVIDENCE_ROOT"]).mkdir(parents=True, exist_ok=True)
    import dart_mcp
    reg = dart_mcp._REGISTRY
    sift = [k for k in reg if k.startswith("sift_")]
    total, native = len(reg), len(reg) - len(sift)
    assert total > 0 and native > 0 and len(sift) > 0, \
        f"tool surface looks wrong: total={total} native={native} sift={len(sift)}"
    return f"{total} tools ({native} native + {len(sift)} SIFT adapters)"


# 5. adapter CLI
def _adapter_cli():
    # Resolve the adapter: importable -> DART_ADAPTER_DIR -> sibling checkout.
    env = dict(os.environ)
    candidates = []
    if os.environ.get("DART_ADAPTER_DIR"):
        candidates.append(Path(os.environ["DART_ADAPTER_DIR"]) / "src")
    candidates.append(REPO.parent / "agentic-dart-collector-adapter" / "src")
    try:
        import dart_collector_adapter  # noqa: F401
        py_path = env.get("PYTHONPATH", "")
    except Exception:  # noqa: BLE001
        src = next((c for c in candidates if (c / "dart_collector_adapter").is_dir()), None)
        assert src is not None, (
            "collector adapter not importable and not found at DART_ADAPTER_DIR "
            "or ../agentic-dart-collector-adapter/src "
            "(install it: pip install -e ../agentic-dart-collector-adapter)"
        )
        py_path = (str(src) + os.pathsep + env.get("PYTHONPATH", "")).rstrip(os.pathsep)
    env["PYTHONPATH"] = py_path
    r = subprocess.run([sys.executable, "-m", "dart_collector_adapter", "--help"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, f"adapter --help exit {r.returncode}: {r.stderr[-200:]}"
    assert "--source" in r.stdout, "adapter CLI missing --source contract"
    return "python3 -m dart_collector_adapter --help OK (--source zip|image)"


# 6. case-study layout
def _layout():
    import run_eval
    cases = run_eval.discover_cases()
    tiers = {c.tier for c in cases}
    assert tiers == {"self-evaluation", "external-evaluation"}, f"tiers={tiers}"
    for c in cases:
        assert c.truth_path.is_file(), f"{c.ref} missing truth.json"
    c01 = run_eval.get_case("self-evaluation/case-01")
    assert c01.has_evidence, "self-evaluation/case-01 evidence_root not bundled"
    return f"{len(cases)} cases across both tiers; case-01 evidence bundled"


# 7. run_eval is live-only and fails fast without a key
def _fail_fast():
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    r = subprocess.run([sys.executable, "run_eval.py", "--case", "self-evaluation/case-01"],
                       cwd=REPO, capture_output=True, text=True, env=env)
    assert r.returncode != 0, "run_eval did not fail fast without ANTHROPIC_API_KEY"
    assert "ANTHROPIC_API_KEY is not set" in r.stderr, "missing fail-fast message"
    import run_eval
    opts = {a.option_strings[0] for a in run_eval.build_parser()._actions
            if a.option_strings}
    forbidden = {"--mode", "--dry-run", "--deterministic", "--fake"}
    leaked = forbidden & opts
    assert not leaked, f"run_eval exposes a non-live public flag: {leaked}"
    return "live-only; fails fast without a key; no fake-findings mode"


# 8. SIFT adapter tool availability (informational — native tools cover gaps)
def _sift_tools():
    """Report how many SIFT adapter backing binaries are runnable. Never fails:
    a missing tool just means that adapter raises SiftToolNotFoundError and the
    native dart_mcp equivalent is used instead. Run scripts/check_sift_tools.py
    for the full per-tool table."""
    try:
        from dart_mcp.sift_adapters._common import _which, SiftToolNotFoundError
    except Exception as e:  # noqa: BLE001
        return f"could not import SIFT adapter resolver ({e})"
    tools = [
        ("yara", "DART_YARA_BIN"),
        ("vol", "DART_VOLATILITY3_BIN"),
        ("log2timeline.py", "DART_LOG2TIMELINE_BIN"),
        ("psort.py", "DART_PSORT_BIN"),
        ("MFTECmd", "DART_MFTECMD_BIN"),
        ("EvtxECmd", "DART_EVTXECMD_BIN"),
        ("PECmd", "DART_PECMD_BIN"),
        ("RECmd", "DART_RECMD_BIN"),
        ("AmcacheParser", "DART_AMCACHEPARSER_BIN"),
    ]
    avail = 0
    missing = []
    for binary, env_var in tools:
        try:
            _which(binary, env_var=env_var)
            avail += 1
        except SiftToolNotFoundError:
            missing.append(binary)
    total = len(tools)
    if avail == total:
        return f"{avail}/{total} SIFT tool binaries runnable (all sift_* adapters live)"
    return (f"{avail}/{total} SIFT tool binaries runnable; missing: "
            f"{', '.join(missing)} (native tools cover these; see "
            f"scripts/check_sift_tools.py)")


def main() -> int:
    print("Agentic-DART healthcheck (API-free)\n")
    _check("python version", _py_version)
    _check("local imports", _imports)
    _check("dependencies", _deps)
    _check("MCP tool surface", _mcp_surface)
    _check("collector adapter CLI", _adapter_cli)
    _check("case-study layout", _layout)
    _check("run_eval fail-fast", _fail_fast)
    _check("SIFT tool binaries", _sift_tools)

    for line in _ok:
        print(line)
    for line in _failures:
        print(line, file=sys.stderr)

    if _failures:
        print(f"\n[FAIL] Healthcheck failed: {len(_failures)} check(s) did not pass.",
              file=sys.stderr)
        return 1

    print("\n[OK] Healthcheck completed. The system is ready.")
    print("Next steps:")
    print("1. export ANTHROPIC_API_KEY='sk-...'")
    print("2. python3 run_eval.py --case self-evaluation/case-01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
