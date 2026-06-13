# Quick start

Three ways to run Agentic-DART, simplest first. Pick the one you need.

```
A. Test mode      — no API key, deterministic, < 1 min   (start here)
B. Live mode      — real Claude API + external datasets
C. Real evidence  — your own disk image / host collection
```

## 0. Install (once)

```bash
git clone https://github.com/Juwon1405/agentic-dart.git
cd agentic-dart
bash scripts/install.sh                 # minimal: agent + adapter (deterministic works)
#   bash scripts/install.sh --full      # also installs the SIFT toolchain + EZ Tools
python3 scripts/healthcheck.py          # sanity check — no API key needed
```

`install.sh` also clones and installs the collector adapter into the same venv,
so `dart-collector-adapter` (path C) is ready too.

---

## A. Test mode (no API key)

Everything here is deterministic — same input, same output, no network.

```bash
# 1) Run the bundled IP-KVM case end to end (≈ 5 s).
#    Reconstructs the timeline, self-corrects on a contradiction, writes a
#    SHA-256-chained audit log, and proves a destructive call is refused.
bash examples/demo-run.sh

# 2) Score it: recall / false-positive / hallucination on bundled evidence.
python3 scripts/measure_accuracy.py

# 3) Trace any finding back to the exact tool call that produced it.
python3 -m dart_audit verify examples/out/find-evil-ref-01/audit.jsonl
python3 -m dart_audit trace  examples/out/find-evil-ref-01/audit.jsonl F-013

# 4) Smoke-test the live path WITHOUT a key. The real MCP wire + tool-use loop
#    run end to end, but a SCRIPTED stand-in plays Claude (no network, no real
#    reasoning). Proves the live pipeline is wired correctly; real analysis
#    needs an API key — see section B.
python3 -m dart_agent --case self-evaluation/case-01 --out /tmp/out --mode live --dry-run

# 5) Full test suite, and the SIFT-adapter demo (degrades gracefully if a
#    SIFT tool isn't installed).
python3 -m pytest tests/ dart_corr/tests/ -q
bash examples/sift-adapter-demo.sh
```

---

## B. Live mode (real key + external datasets)

```bash
export ANTHROPIC_API_KEY='sk-...'

python3 run_eval.py --list                              # see all cases
python3 run_eval.py --case self-evaluation/case-01      # live run, bundled evidence

# Download a real public dataset, then analyze it:
python3 run_eval.py --case external-evaluation/case-01 --download   # NIST CFReDS
#   external-evaluation/case-02 = Ali Hadi · case-03 = Digital Corpora M57
```

Each run writes to `out/<tier>/<case>/<timestamp>/`
(`findings.json`, `report.json`, `summary.json`, `audit.jsonl`, `progress.jsonl`).

---

## C. Real evidence — your own host or disk image

Three steps: **collect → adapt → analyze.**

### 1. Collect

On the incident host, run a Velociraptor offline collector (no agent install)
to produce an `evidence.zip` — or just start from a raw disk image you already
have (`.dd` / `.raw` / `.E01`). Full collector recipe:
[collector-adapter README](https://github.com/Juwon1405/agentic-dart-collector-adapter#1-on-the-incident-host--collect).

### 2. Adapt — normalize into an `evidence_root/`

```bash
# from a Velociraptor offline-collector ZIP
python3 -m dart_collector_adapter --input evidence.zip \
    --output ./evidence_root --case-id CASE-001

# OR from a raw disk image (dead-disk via Velociraptor remapping)
python3 -m dart_collector_adapter --source image --input disk.E01 \
    --output ./evidence_root --case-id CASE-001
```

This writes a flat, categorized `evidence_root/` plus a `manifest.json`
(SHA-256 chain of custody).

### 3. Analyze

```bash
export ANTHROPIC_API_KEY='sk-...'
python3 run_eval.py --evidence ./evidence_root --case-id CASE-001
```

Output lands in `out/custom/CASE-001/<timestamp>/`, same shape as above.

---

**More:** architecture → [`docs/architecture.md`](architecture.md) ·
accuracy method → [`docs/accuracy-report.md`](accuracy-report.md) ·
case library → [`examples/case-studies/`](../examples/case-studies/).
