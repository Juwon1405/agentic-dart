#!/usr/bin/env bash
# Full benchmark as THREE SEPARATE PROCESSES (demo -> self -> external).
#
# Each tier runs in its OWN interpreter on purpose: a rate-limit or usage-limit
# hit in one tier cannot bleed into another, every tier is independently
# debuggable, and a failed run in any tier surfaces as a non-zero exit (the
# self/external runners already exit non-zero when a run gets no LLM response).
# This replaces the old in-process `python3 -m scripts.eval.all`.
#
# Usage:
#   ./scripts/bench_full.sh                                  # default 3 models
#   ./scripts/bench_full.sh claude-sonnet-4-6                # one model
#   ./scripts/bench_full.sh claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8
#
# self/external need ANTHROPIC_API_KEY; demo does not.
set -u

cd "$(dirname "$0")/.." || exit 1

if [ "$#" -gt 0 ]; then
    MODELS=("$@")
else
    MODELS=(claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8)
fi

rule() {
    printf '\n%s\n  %s\n%s\n' \
        "================================================================" \
        "$1" \
        "================================================================"
}

rc=0

# 1) demo — deterministic taster, no key. Never gates the benchmark.
rule "1/3  demo — deterministic pipeline taster (no LLM, no key)"
python3 -m scripts.eval.demo || true

# self/external need a key. Stop cleanly after demo if it is missing.
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    rule "self + external need ANTHROPIC_API_KEY — stopping after demo"
    echo "  export ANTHROPIC_API_KEY='sk-ant-...' then re-run."
    exit 0
fi

# 2) self — 8 bundled cases, its own process.
rule "2/3  self-evaluation (separate process)"
python3 -m scripts.eval.self --models "${MODELS[@]}"
rc=$(( rc | $? ))

# 3) external — full-disk public images, its own process.
rule "3/3  external-evaluation (separate process)"
python3 -m scripts.eval.external --models "${MODELS[@]}"
rc=$(( rc | $? ))

rule "done — demo + self + external complete (each ran as its own process)"
echo "  Snapshots : docs/benchmarks/MODEL-COMPARISON.md, SUMMARY.md"
echo "  Trend     : docs/benchmarks/HISTORY.md"
echo "  (non-zero exit means at least one run failed — check the tier output above)"
exit "$rc"
