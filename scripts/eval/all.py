"""DEPRECATED — the one-shot `all` runner has been removed.

Running demo + self + external inside a SINGLE Python process caused real
reliability problems: self and external shared one interpreter, so a rate-limit
or usage-limit hit during the self tier could silently bleed into external,
failures were hard to attribute to a tier, and the combined run was awkward to
debug. The benchmark is more trustworthy — and live demos are clearer — when
each tier runs as its OWN process.

Use the individual runners instead (each is independently debuggable and exits
non-zero if any run fails to get an LLM response):

    python3 -m scripts.eval.demo                          # deterministic, no key
    python3 -m scripts.eval.self      --models <models>   # 8 bundled cases
    python3 -m scripts.eval.external  --models <models>   # public disk images

Or run all three as SEPARATE processes in one command:

    ./scripts/bench_full.sh <models>

This module no longer runs anything; it prints this guidance and exits non-zero.
"""
from __future__ import annotations

import sys

_MSG = """\
`python3 -m scripts.eval.all` is DEPRECATED and no longer runs the benchmark.

Running demo + self + external in one Python process let failures bleed across
tiers (a rate-limit during self could corrupt external) and was hard to debug.
Run each tier as its own process instead:

    python3 -m scripts.eval.demo                          # deterministic, no key
    python3 -m scripts.eval.self      --models <models>   # 8 bundled cases
    python3 -m scripts.eval.external  --models <models>   # public disk images

Or all three as separate processes in one command:

    ./scripts/bench_full.sh <models>
"""


def main(argv=None) -> int:
    print(_MSG, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
