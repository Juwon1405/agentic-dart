#!/usr/bin/env python3
"""Validate ground-truth integrity (CI / pre-commit gate).

Prevents drift between the ground-truth files and the actual analysis code.
Checks the following and exits non-zero (blocking commit / CI) on any failure:

  1. expected_function is registered in the live MCP registry (dart_mcp._REGISTRY)
  2. evidence_path exists in the evidence pool (non-derived findings, internal cases)
  3. host_path and evidence_path are consistent
  4. Derived findings (self_correction / audit_chain / correlation) are exempt
     from path checks

External download cases (08-10) keep evidence off-repo and some functions are
roadmap items, so missing paths / unimplemented functions are WARN only
(structural errors remain FAIL).

Usage:
  python3 scripts/eval/validate_ground_truth.py            # FAIL blocks; WARN allowed
  python3 scripts/eval/validate_ground_truth.py --strict   # WARN also blocks (CI)
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CS = REPO / "examples" / "case-studies"
REALISTIC = (REPO / "examples" / "case-studies" / "self-evaluation"
             / "case-01" / "evidence_root")

EXTERNAL_TIER = "external-evaluation"
DERIVED = {"self_correction_event", "audit_chain", "correlation_finding"}


def mcp_tools():
    """Return the set of registered MCP tool names (single source of truth)."""
    src = str(REPO / "dart_mcp" / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    import dart_mcp
    return set(dart_mcp._REGISTRY.keys())


def is_external(tier):
    return tier == EXTERNAL_TIER


def path_exists(rel):
    full = REALISTIC / rel
    return full.exists() or Path(str(full).rstrip("/")).exists()


def check_function(fn, tools):
    """Validate expected_function. Returns (state, reason); state is True/False/None."""
    if not fn:
        return (False, "expected_function missing")
    fn = fn.strip()
    if fn.startswith("("):
        return (None, "unimplemented description")
    # Split "a + b", "a, b", and "name (comment)" forms.
    parts = [re.split(r"\s*\(", p)[0].strip() for p in re.split(r"[+,]", fn)]
    parts = [p for p in parts if p]
    missing = [p for p in parts if p not in tools]
    if missing:
        return (False, f"unregistered function: {missing}")
    return (True, "")


def main():
    strict = "--strict" in sys.argv
    tools = mcp_tools()
    print(f"Validating against {len(tools)} registered MCP tools\n")

    total_fail = total_warn = 0
    for gt in sorted(CS.glob("*/case-*/truth.json")):
        tier = gt.parent.parent.name
        case = f"{tier}/{gt.parent.name}"
        ext = is_external(tier)
        d = json.loads(gt.read_text(encoding="utf-8"))
        findings = d.get("ground_truth_findings", [])

        case_fail, case_warn = [], []
        for f in findings:
            fid = f.get("finding_id", "?")
            at = f.get("artifact_type")
            fn = f.get("expected_dart_mcp_function") or f.get("expected_function")
            derived = at in DERIVED

            # (1) Function check. Derived findings (e.g. audit_chain) are not the
            #     output of a specific tool, so a missing function is allowed
            #     (if present, it is still validated).
            state, reason = check_function(fn, tools)
            if state is False and reason == "expected_function missing" and derived:
                pass
            elif state is False:
                (case_warn if ext else case_fail).append(f"{fid}: {reason}")
            elif state is None and not ext:
                case_fail.append(f"{fid}: unimplemented-description function in internal case ({fn[:40]})")

            # (2)(3) Path check - non-derived & internal cases only.
            if derived or ext:
                continue
            ep = f.get("evidence_path")
            hp = f.get("host_path")
            if not ep:
                case_fail.append(f"{fid}: evidence_path missing")
            elif not path_exists(ep):
                case_fail.append(f"{fid}: evidence_path does not exist ({ep})")
            if hp and ep and hp != ep:
                if path_exists(hp) and path_exists(ep):
                    case_warn.append(f"{fid}: host != evidence (both exist: {hp} vs {ep})")
                else:
                    case_fail.append(f"{fid}: host != evidence mismatch ({hp} vs {ep})")

        tag = " [external]" if ext else ""
        if case_fail:
            print(f"  FAIL {case}{tag} - {len(case_fail)}")
            for x in case_fail[:12]:
                print(f"      {x}")
            total_fail += len(case_fail)
        elif case_warn:
            print(f"  WARN {case}{tag} - {len(case_warn)}")
            for x in case_warn[:12]:
                print(f"      {x}")
            total_warn += len(case_warn)
        else:
            print(f"  OK   {case}{tag}")

    print(f"\nTotal FAIL {total_fail} / WARN {total_warn}")
    if total_fail or (strict and total_warn):
        print(">>> validation failed - blocking commit / CI")
        sys.exit(1)
    print(">>> validation passed")


if __name__ == "__main__":
    main()
