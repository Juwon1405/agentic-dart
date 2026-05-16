# Benchmark Suite

Reproducible accuracy measurement for Agentic-DART across **11 case
studies** (99 ground-truth findings) spanning two evidence tiers.

> The goal of this suite is not to advertise a single number. It is to
> let any third-party reviewer (SANS judge, customer security team,
> auditor) run **one command** and produce **the same accuracy table**
> we publish. If the numbers ever differ, the audit chain SHA-256s pin
> down exactly which input or which agent version drifted.

---

## Quick start (one command)

```bash
cd ~/agentic-dart

# Run everything — both layers, auto-download missing datasets
python3 -m scripts.benchmark.run_all --download

# Just the fast internal cases (no download, ~10 seconds)
python3 -m scripts.benchmark.run_all --layer 1

# Just the external datasets (requires ./datasets/ already populated)
python3 -m scripts.benchmark.run_all --layer 2
```

Output goes to:
- `docs/benchmarks/SUMMARY.md` — unified score sheet (all 11 cases)
- `docs/benchmarks/<dataset>_<timestamp>.json` — per-run external detail
- `docs/accuracy-report.md` — Layer-1 detailed breakdown

---

## Two-layer methodology

The 11 cases are evaluated in two distinct layers because the evidence
provenance is fundamentally different.

| Layer | Cases | Evidence | Size | Where it comes from |
|:---:|---|---|---:|---|
| **1** | case-01 to case-07, case-11 | `examples/sample-evidence-realistic/` | 748 KB + supply-chain evidence | Bundled with the repository |
| **2** | case-08 to case-10 | `./datasets/` (gitignored) | 13 GB | Downloaded from external mirrors |

Splitting them this way lets us be **honest about what each layer
proves**.

### Layer 1 — internal evidence (case-01 to case-07)

**What it is:** synthetic-but-realistic DFIR evidence authored
alongside this project. Two sub-variants ship in the repository:

- **`examples/sample-evidence/`** (the *reference* set, 408 KB) — small,
  deterministic, fully IOC-loaded. Used by the CI to detect detection
  regressions: any change in numbers immediately flags a code change
  that affected detection logic.

- **`examples/sample-evidence-realistic/`** (the *realistic* variant,
  748 KB) — same ground-truth signal, but mixed with synthetic benign
  noise at production-realistic ratios:

  ```
  Web access log     27 attack lines   + 1000 benign lines    1 : 37
  Security events    18 IOC events     +  500 benign events   1 : 28
  Process tree CSV   11 IOC procs      +  200 benign procs    1 : 18
  Unix auth.log      17 IOC lines      +  500 benign lines    1 : 29
  ```

  The benign-noise generator (`scripts/generate_realistic_evidence.py`)
  is seeded (`seed = 20260508`) so the output is byte-identical on every
  run. CI re-derives the realistic tree on every build.

**What this layer proves:**
- The detection functions discriminate IOC from benign at production
  signal-to-noise ratios (not just on toy single-line inputs).
- Recall and false-positive numbers hold across both the small
  reference set and the noise-injected variant — both score
  Recall 1.000 / FPR 0.000 / Hallucination 0.

**What this layer does NOT prove:**
- That dart-mcp solves real-world cases collected from production
  incidents. To claim that, we use Layer 2.

This is documented in detail at `../../docs/accuracy-report.md`.

### Layer 2 — external public datasets (case-08 to case-10)

**What it is:** three peer-reviewed, community-verified, public DFIR
datasets that none of this project's authors created or had any
influence over. They are widely used in DFIR education and tool
benchmarking, and their answer keys are independently published.

| short | Case | Authoring body | Year | Era |
|---|---|---|---:|---|
| `cfreds_hacking_case` | case-08 | **U.S. NIST** (federal standards body) | 2004 | Windows XP |
| `hadi_challenge_1` | case-09 | **Dr. Ali Hadi**, Champlain College | 2014 | Windows Server 2008 |
| `m57_jo` | case-10 | **Naval Postgraduate School + NIST** | 2009 | Windows XP |

**Why these three specifically:**

1. **Authority diversity:** US federal standards body (NIST), academic
   institution (Champlain), and government research lab (NPS). No
   single source of bias.
2. **Threat-model diversity:** WiFi-sniffing toolkit case, web-server
   compromise, corporate IP-theft. Three different attack patterns.
3. **Era diversity:** 2004 / 2009 / 2014 — covers decade of Windows
   evolution and forensic artefact format changes.
4. **Public ground truth:** all three have peer-reviewed answer keys,
   making "did the agent get it right?" mechanically scoreable.
5. **Stable hosting:** NIST archive, Internet Archive, AWS S3 — none
   require captcha, account, or interactive download.

**What this layer proves:**
- The agent can process raw disk images it has never seen, from
  authoring bodies that have no relationship to this project.
- Recall numbers on these three datasets are not the product of
  in-distribution training because **the datasets predate dart-mcp by
  10-20 years**.

**What this layer does NOT prove:**
- 100% recall — we expect numbers below Layer 1 because the agent's
  MCP surface does not yet cover every artefact every dataset uses
  (see Phase 2 roadmap in each case-NN/README.md).

---

## Data sources — full provenance

Every Layer-2 dataset URL is HEAD-checked live on 2026-05-15. Reviewers
can independently verify each source.

### case-08 — NIST CFReDS Hacking Case (Greg Schardt / "Mr. Evil")

- **Homepage:** https://cfreds-archive.nist.gov/all/NIST/HackingCase
- **Download base:** https://cfreds-archive.nist.gov/images/hacking-dd/
- **Files:** `SCHARDT.001` through `SCHARDT.008` (split DD, ~635 MB each)
- **Joined image:** `SCHARDT.dd` (~5 GB, MD5 `aee4fcd9301c03b3b054623ca261959a` per `SCHARDT.LOG`)
- **License:** Public Domain (U.S. Government work)
- **Authoring body:** U.S. National Institute of Standards and Technology
- **Original briefing + answer key:** ships with the dataset under
  `examples/case-studies/case-08-cfreds-hacking-case/SCHARDT.LOG`
- **Citation context:** referenced in SANS GCFE / GCFA prep materials
  and in hundreds of academic forensics courses

### case-09 — Ali Hadi DFIR Challenge #1 (Web Server Case)

- **Homepage:** https://www.ashemery.com/dfir.html
- **Primary mirror:** https://archive.org/details/dfir-case1 (Internet Archive — stable, resumable, no captcha)
- **Download URL:** https://archive.org/download/dfir-case1/Case1-Webserver.E01
- **File:** `Case1-Webserver.E01` (2.91 GB single E01)
- **Memory dump (optional):** `memdump.7z` (0.11 GB, same mirror)
- **License:** CC-BY-4.0
- **Authoring body:** Dr. Ali Hadi, Champlain College Computer & Digital Forensics Program
- **OS:** Windows Server 2008 running XAMPP (Apache + MySQL + PHP)
- **Citation context:** used in Champlain College DFIR coursework;
  community write-ups on aboutdfir.com, forensicfocus.com, and
  betweentwodfirns.blogspot.com

### case-10 — Digital Corpora M57-Patents (Jo's PC, 2009-12-10)

- **Homepage:** https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
- **S3 bucket (canonical):** https://digitalcorpora.s3.amazonaws.com/
- **Download URL:** https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted/jo-2009-12-10.E01
- **File:** `jo-2009-12-10.E01` (5.16 GB single E01)
- **License:** CC-BY-3.0
- **Authoring body:** Naval Postgraduate School (Simson L. Garfinkel et al.)
  with NIST funding
- **Citation context:** Garfinkel, Farrell, Roussev, "Bringing Science
  to Digital Forensics with Standardized Forensic Corpora", DFRWS 2009
- **Note on the name:** the M57 scenario's actual employees are
  `charlie, jo, pat, terry`. Earlier documentation in this repo
  incorrectly referred to "jean" — `case-10-m57-jean` directory
  name is preserved for git history continuity but the dataset
  is officially `m57_jo`.

---

## What `run_all.py` actually does (step-by-step)

When you run `python3 -m scripts.benchmark.run_all --download`:

```
┌─ Layer 1 (~10 seconds) ────────────────────────────────────────┐
│                                                                │
│  1. measure_accuracy.py --variant realistic                    │
│     ↓                                                          │
│  2. Iterates case-01 through case-07                           │
│  3. Calls each detection function on bundled evidence          │
│  4. Diffs findings against ground-truth.json per case          │
│  5. Writes docs/accuracy-report.md                             │
│  6. Mirrors per-case rows into docs/benchmarks/SUMMARY.md      │
│                                                                │
└────────────────────────────────────────────────────────────────┘

┌─ Layer 2 (~30-60 minutes if download needed, ~5 min if cached) ┐
│                                                                │
│  For each of cfreds / hadi1 / m57:                             │
│                                                                │
│  1. Check ./datasets/<short>/<image_name>                      │
│  2. If missing AND --download:                                 │
│       - download.py fetches from authoritative mirror          │
│       - verifies SHA-256 / MD5 where published                 │
│       - joins split parts (CFReDS SCHARDT.001-008)             │
│  3. SHA-256 hash the image (proof of identity)                 │
│  4. Convert image → evidence_root via collector-adapter        │
│  5. Run dart_agent with senior-analyst-v3 playbook             │
│  6. Score findings.json vs case-NN/ground-truth.json           │
│       - strict mode  : exact evidence_id match                 │
│       - lenient mode : artifact_type + host_path prefix match  │
│  7. Detect hallucinations (findings without audit_id)          │
│  8. Verify SHA-256 audit chain linkage                         │
│  9. Emit docs/benchmarks/<dataset>_<timestamp>.json            │
│ 10. Append row to docs/benchmarks/SUMMARY.md                   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Scoring — what the numbers mean

For each ground-truth finding the suite reports two TP/FN counts:

| Mode | Match criterion | Question answered |
|---|---|---|
| **strict** | `evidence_id` exact match | "Did the agent surface the same artefact under the canonical name?" |
| **lenient** | `(artifact_type, host_path_prefix)` tuple match | "Did the agent surface the same TYPE of evidence from the same area, even if it phrased it differently?" |

Reported metrics per case:

- `recall` = TP / total ground truth (how many of the right things the agent found)
- `precision` = TP / total findings (of the things the agent found, how many were right)
- `hallucinations` = count of findings with no `audit_id` reference
  (a finding the agent cannot trace back to an MCP call is, by
  definition, not reproducible — we treat that as hallucination)
- `audit_chain_intact` = `True` only when every `audit.jsonl` entry's
  `prev_hash` field matches the preceding entry's `entry_hash`
  (tamper-evident chain verification)

**Strict mode is the headline number.** Lenient mode is the "would a
human analyst find this useful?" floor. Real-world numbers usually fall
between them.

---

## Why this design is honest

Three deliberate choices that distinguish this benchmark from
marketing-driven accuracy claims:

1. **External datasets cannot be cherry-picked.** Layer 2 sources were
   selected before any measurement was performed. The script is
   committed to the repository with the URLs baked in. A reviewer can
   inspect `datasets.py` to see exactly which images we evaluate
   against — no hidden hold-out or in-distribution training data.

2. **Hallucinations are counted, not suppressed.** Most LLM-based DFIR
   tools either don't measure hallucinations or define them so
   narrowly that everything passes. We define a hallucination as
   "finding with no traceable MCP audit_id" — a mechanical, harsh
   criterion. Score better by being more disciplined, not by changing
   the definition.

3. **The audit chain is verified, not just produced.** Many agentic
   systems emit "audit logs" that nobody actually checks. The
   benchmark recomputes the SHA-256 chain on every run and reports
   `audit_chain_intact` as a boolean column in the summary. If it ever
   reads `✗` for a row, that case's results cannot be trusted and
   should be discarded.

---

## Adding a fourth external dataset

```python
# scripts/benchmark/datasets.py
DATASETS["dfrws_2022"] = {
    "title":           "DFRWS 2022 Forensic Challenge",
    "short":           "dfrws22",
    "year":            2022,
    "filesystem":      "...",
    "size_gb":         8.5,
    "license":         "...",
    "homepage":        "https://dfrws.org/challenges/",
    "download_base":   "https://...",
    "parts":           [("file.E01", "sha1", None)],
    "joined_name":     "file.E01",
    "ground_truth_path": "examples/case-studies/case-12-dfrws-2022/ground-truth.json",
    "scenario":        "...",
    "key_artifacts":   [...],
}
```

Then create `examples/case-studies/case-12-dfrws-2022/` with a `README.md`
and `ground-truth.json` (schema: see `case-08-cfreds-hacking-case/ground-truth.json`).

> Note: case-11 is already occupied by `case-11-supplychain-ad-zeroday`
> (Layer 1). The next available external-benchmark slot is case-12.

That's all. `run_all.py --layer 2` will pick it up automatically.

---

## File index for this directory

```
scripts/benchmark/
├── README.md           this file
├── datasets.py         registry of 3 external datasets with URLs, checksums, scenarios
├── download.py         streaming downloader with resume + verify + auto-join
├── run_benchmark.py    per-dataset evaluator (Layer 2 single-case runner)
└── run_all.py          unified entry point — runs both layers, one command
```

## Related files elsewhere in the repo

- `scripts/measure_accuracy.py` — Layer 1 evaluator (case-01 to case-07)
- `scripts/generate_realistic_evidence.py` — seeded noise generator for the realistic variant
- `examples/sample-evidence/` — Layer 1 reference (deterministic) evidence
- `examples/sample-evidence-realistic/` — Layer 1 noise-injected evidence
- `examples/case-studies/case-NN/ground-truth.json` — per-case answer key (all 11 cases)
- `docs/accuracy-report.md` — Layer 1 detailed report
- `docs/benchmarks/SUMMARY.md` — unified Layer 1 + Layer 2 score sheet
- `docs/benchmarks/*.json` — per-run Layer 2 detail
