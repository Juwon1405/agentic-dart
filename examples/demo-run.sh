#!/usr/bin/env bash
# Agentic-DFIR — reproducible demo run.
#
# Produces, from a clean checkout:
#   out/demo/audit.jsonl        (chain-verifiable)
#   out/demo/progress.jsonl     (iteration-by-iteration)
#   out/demo/report.json        (final findings)
#
# examples/out/ref-01/ is the committed reference run and is left untouched.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"

export DFIR_EVIDENCE_ROOT="${REPO}/examples/case-studies/self-evaluation/case-01/evidence_root"
export PYTHONPATH="${REPO}/dfir_audit/src:${REPO}/dfir_mcp/src:${REPO}/dfir_agent/src:${REPO}/dfir_corr/src"

OUT="${REPO}/examples/out/demo"
rm -rf "${OUT}"
mkdir -p "${OUT}"

echo "[demo] evidence root : ${DFIR_EVIDENCE_ROOT}"
echo "[demo] output dir    : ${OUT}"
echo ""

python3 -m dfir_agent \
  --case demo \
  --out "${OUT}" \
  --max-iterations 10 \
  --mode deterministic

echo ""
echo "[demo] verifying audit chain..."
python3 -m dfir_audit.verify "${OUT}/audit.jsonl"

echo ""
echo "[demo] bypass test — attempting to call an unregistered destructive function:"
python3 - << 'PY'
from dfir_mcp import call_tool
try:
    call_tool("execute_shell", {"cmd": "rm -rf /mnt/evidence"})
except KeyError as e:
    print(f"[demo] PASS — {e}")
except Exception as e:
    print(f"[demo] UNEXPECTED — {type(e).__name__}: {e}")
PY
