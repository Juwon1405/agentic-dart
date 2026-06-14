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

`install.sh` also clones the collector adapter into the same interpreter **and**
chains into the adapter's installer to stage a SHA-256-verified Velociraptor
binary, so `dart-collector-adapter` (path C) is ready end-to-end — including
`--source image` analysis. Pass `--skip-velociraptor` to opt out (e.g. when
you only ever use `--source zip`).

---

## A. Test mode (no API key)

Everything here is deterministic — same input, same output, no network.

```bash
# 1) Run the bundled IP-KVM case end to end (≈ 5 s).
#    Reconstructs the timeline, self-corrects on a contradiction, writes a
#    SHA-256-chained audit log, and proves a destructive call is refused.
bash examples/demo-run.sh

# 2) Score it: recall / false-positive / hallucination on bundled evidence.
#    Deterministic regression baseline: a scripted analyst, not LLM reasoning;
#    detection-skill numbers come from live runs on the external datasets.
python3 scripts/scripts/eval/demo.py

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

python3 analyze.py --list                              # see all cases
python3 analyze.py --case self-evaluation/case-01      # live run, bundled evidence

# External datasets ship as raw disk images — three steps (--download does NOT analyze):
#
# 1) Download the raw image only (large — can take a while; downloads, no analysis).
python3 analyze.py --case external-evaluation/case-01 --download   # NIST CFReDS
#    → prints the downloaded image path under
#      examples/case-studies/external-evaluation/case-01/<dataset>/
#
# 2) Adapt that raw image into an evidence_root (same adapter as path C):
python3 -m dart_collector_adapter --source image \
    --input <image path printed in step 1> \
    --output examples/case-studies/external-evaluation/case-01/evidence_root \
    --case-id CFREDS-01
#
# 3) Analyze the adapted evidence_root:
python3 analyze.py --case external-evaluation/case-01
#   external-evaluation/case-02 = Ali Hadi · case-03 = Digital Corpora M57
```

Each run writes to `out/<tier>/<case>/<timestamp>/`
(`findings.json`, `report.json`, `summary.json`, `audit.jsonl`, `progress.jsonl`).

---

## C. Real evidence — your own host or disk image

Two machines: **collect on the incident host → adapt + analyze on the analysis
server.** The adapter and Agentic-DART install once on the analysis server
(`scripts/install.sh` clones the adapter into the same interpreter and chains into
the adapter's installer to stage a SHA-256-verified Velociraptor binary; pass
`--skip-velociraptor` to opt out, e.g. when only `--source zip` is needed);
the incident host gets **only** a Velociraptor collector binary — nothing is
installed on it.

### 1. Collect — on the incident host

Copy the standalone Velociraptor binary to the host and run it once as an
offline collector (no install, no agent, no Python) to produce `evidence.zip`;
copy the ZIP back to the analysis server. Velociraptor makes the ZIP — the
adapter is not involved here. (Or skip this and start from a raw disk image you
already have: `.dd` / `.raw` / `.E01`.) Full collector recipe:
[collector-adapter README](https://github.com/Juwon1405/agentic-dart-collector-adapter#1-on-the-incident-host--collect).

### 2. Adapt — on the analysis server (normalize into an `evidence_root/`)

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

### 3. Analyze — on the analysis server

```bash
export ANTHROPIC_API_KEY='sk-...'
python3 analyze.py --evidence ./evidence_root --case-id CASE-001
```

Output lands in `out/custom/CASE-001/<timestamp>/`, same shape as above.

---

**More:** architecture → [`docs/architecture.md`](architecture.md) ·
accuracy method → [`docs/accuracy-report.md`](accuracy-report.md) ·
case library → [`examples/case-studies/`](../examples/case-studies/).
