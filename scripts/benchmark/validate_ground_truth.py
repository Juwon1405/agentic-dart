#!/usr/bin/env python3
"""
Ground-truth 정합성 검증 (CI / pre-commit 게이트).

정답지(ground-truth.json)와 실제 분석 코드가 표류하지 못하도록 막는다.
다음을 검증하고, 하나라도 어기면 exit 1 → commit / CI 차단:

  1. expected_function 이 실제 MCP 레지스트리(dart_mcp._REGISTRY)에 존재
  2. evidence_path 가 증거 풀에 실존 (비파생 finding, 내부 케이스)
  3. host_path ↔ evidence_path 정합
  4. 파생 finding(self_correction / audit_chain / correlation)은 경로 검증 면제

외부 다운로드 케이스(08~10)는 증거가 로컬에 없고 일부 기능이 로드맵이므로
경로/미구현 함수는 WARN 으로만 처리한다(구조 오류는 FAIL).

사용:
  python3 scripts/benchmark/validate_ground_truth.py            # WARN 허용, FAIL만 차단
  python3 scripts/benchmark/validate_ground_truth.py --strict   # WARN도 차단(CI 권장)
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CS = REPO / "examples" / "case-studies"
REALISTIC = REPO / "examples" / "sample-evidence-realistic"

EXTERNAL = {"case-08", "case-09", "case-10"}
DERIVED = {"self_correction_event", "audit_chain", "correlation_finding"}


def mcp_tools():
    """실제 등록된 MCP 도구 이름 집합 (단일 진실원천)."""
    src = str(REPO / "dart_mcp" / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    import dart_mcp
    return set(dart_mcp._REGISTRY.keys())


def is_external(case):
    return any(case.startswith(e) for e in EXTERNAL)


def path_exists(rel):
    full = REALISTIC / rel
    return full.exists() or Path(str(full).rstrip("/")).exists()


def check_function(fn, tools):
    """expected_function 유효성. 반환: (state, reason) — state True/False/None(미구현 설명)."""
    if not fn:
        return (False, "expected_function 누락")
    fn = fn.strip()
    if fn.startswith("("):
        return (None, "미구현 설명 표기")
    # "a + b", "a, b", 그리고 "name (주석)" 형태를 분해
    parts = [re.split(r"\s*\(", p)[0].strip() for p in re.split(r"[+,]", fn)]
    parts = [p for p in parts if p]
    missing = [p for p in parts if p not in tools]
    if missing:
        return (False, f"미등록 함수: {missing}")
    return (True, "")


def main():
    strict = "--strict" in sys.argv
    tools = mcp_tools()
    print(f"MCP 등록 도구 {len(tools)}개 기준 검증\n")

    total_fail = total_warn = 0
    for gt in sorted(CS.glob("case-*/ground-truth.json")):
        case = gt.parent.name
        ext = is_external(case)
        d = json.loads(gt.read_text(encoding="utf-8"))
        findings = d.get("ground_truth_findings", [])

        case_fail, case_warn = [], []
        for f in findings:
            fid = f.get("finding_id", "?")
            at = f.get("artifact_type")
            fn = f.get("expected_dart_mcp_function") or f.get("expected_function")
            derived = at in DERIVED

            # (1) 함수 검증 — 파생 finding(audit_chain 등)은 특정 도구 산출이 아니므로
            #     함수 누락을 허용한다(단, 함수가 있으면 유효성은 검증).
            state, reason = check_function(fn, tools)
            if state is False and reason == "expected_function 누락" and derived:
                pass
            elif state is False:
                (case_warn if ext else case_fail).append(f"{fid}: {reason}")
            elif state is None and not ext:
                case_fail.append(f"{fid}: 내부 케이스에 미구현 설명 함수 ({fn[:40]})")

            # (2)(3) 경로 검증 — 비파생 & 내부 케이스만
            if derived or ext:
                continue
            ep = f.get("evidence_path")
            hp = f.get("host_path")
            if not ep:
                case_fail.append(f"{fid}: evidence_path 누락")
            elif not path_exists(ep):
                case_fail.append(f"{fid}: evidence_path 실존하지 않음 ({ep})")
            if hp and ep and hp != ep:
                if path_exists(hp) and path_exists(ep):
                    case_warn.append(f"{fid}: host≠evidence (둘 다 존재: {hp} vs {ep})")
                else:
                    case_fail.append(f"{fid}: host≠evidence 불일치 ({hp} vs {ep})")

        tag = " [외부]" if ext else ""
        if case_fail:
            print(f"  \u2717 {case}{tag} — FAIL {len(case_fail)}")
            for x in case_fail[:12]:
                print(f"      {x}")
            total_fail += len(case_fail)
        elif case_warn:
            print(f"  \u26a0 {case}{tag} — WARN {len(case_warn)}")
            for x in case_warn[:12]:
                print(f"      {x}")
            total_warn += len(case_warn)
        else:
            print(f"  \u2713 {case}{tag}")

    print(f"\n총 FAIL {total_fail} / WARN {total_warn}")
    if total_fail or (strict and total_warn):
        print(">>> 검증 실패 — commit / CI 차단")
        sys.exit(1)
    print(">>> 검증 통과")


if __name__ == "__main__":
    main()
