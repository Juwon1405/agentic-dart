#!/usr/bin/env bash
# YuShin — reproducible demo run.
#
# Produces, from a clean checkout:
#   out/find-evil-ref-01/audit.jsonl      (chain-verifiable)
#   out/find-evil-ref-01/progress.jsonl   (iteration-by-iteration)
#   out/find-evil-ref-01/report.json      (final findings)
#
# This is the exact command the demo video records.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"

export YUSHIN_EVIDENCE_ROOT="${HERE}/sample-evidence"
export PYTHONPATH="${REPO}/yushin_audit/src:${REPO}/yushin_mcp/src:${REPO}/yushin_agent/src"

OUT="${REPO}/examples/out/find-evil-ref-01"
rm -rf "${OUT}"
mkdir -p "${OUT}"

echo "[demo] evidence root : ${YUSHIN_EVIDENCE_ROOT}"
echo "[demo] output dir    : ${OUT}"
echo ""

python3 -m yushin_agent \
  --case find-evil-ref-01 \
  --out "${OUT}" \
  --max-iterations 10 \
  --mode deterministic

echo ""
echo "[demo] verifying audit chain..."
python3 -m yushin_audit.verify "${OUT}/audit.jsonl"

echo ""
echo "[demo] bypass test — attempting to call an unregistered destructive function:"
python3 - << 'PY'
from yushin_mcp import call_tool
try:
    call_tool("execute_shell", {"cmd": "rm -rf /mnt/evidence"})
except KeyError as e:
    print(f"[demo] PASS — {e}")
except Exception as e:
    print(f"[demo] UNEXPECTED — {type(e).__name__}: {e}")
PY
