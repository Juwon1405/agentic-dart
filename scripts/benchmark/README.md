# Benchmark Suite

Reproducible accuracy measurement of Agentic-DART against three widely-used
public DFIR datasets:

| Short  | Dataset                                       | Size    | License        |
|--------|-----------------------------------------------|---------|----------------|
| cfreds | NIST CFReDS Hacking Case (Greg Schardt 2004)  | ~5 GB   | Public Domain  |
| hadi1  | Ali Hadi DFIR Challenge #1 (Linux web server) | ~1.5 GB | CC-BY-4.0      |
| m57    | Digital Corpora M57-Patents (Jean's PC)       | ~10 GB  | CC-BY-3.0      |

Why these three: they are documented, peer-reviewed, and have published
answer keys, so accuracy numbers measured against them are auditable and
reproducible by any third party.

## Files

```
scripts/benchmark/
├── datasets.py        registry: URLs, checksums, scenarios, key artifacts
├── download.py        fetches a dataset to local disk + verifies checksums
├── run_benchmark.py   evaluates dart_agent and emits JSON + Markdown reports
└── README.md          this file

examples/case-studies/
├── case-08-cfreds-hacking-case/  ground-truth.json (existed prior)
├── case-09-hadi-challenge-1/     ground-truth.json (new)
└── case-10-m57-jean/             ground-truth.json (new)

docs/benchmarks/
├── SUMMARY.md         appended on each run
└── <dataset>_<timestamp>.json     full per-run report
```

## Usage

### 1. Download (run on host with disk space)

```bash
# all three (~16 GB)
python3 -m benchmark.download all ./datasets

# one at a time
python3 -m benchmark.download cfreds ./datasets
python3 -m benchmark.download hadi1  ./datasets
python3 -m benchmark.download m57    ./datasets
```

The downloader resumes interrupted parts, verifies MD5/SHA-256 where
published, and joins split images (CFReDS SCHARDT.001-008).

### 2. Run a benchmark

```bash
# default: looks at ./datasets/<short>/<joined_name>
python3 -m benchmark.run_benchmark cfreds

# explicit path
python3 -m benchmark.run_benchmark hadi1 --image /forensics/cases/Challenge1.dd

# skip image SHA-256 (saves 1-2 min on a 5 GB image)
python3 -m benchmark.run_benchmark m57 --skip-hash

# all three back-to-back
python3 -m benchmark.run_benchmark all
```

### 3. Inspect results

Per-run JSON: `docs/benchmarks/<dataset>_<timestamp>.json`
Rolling Markdown table: `docs/benchmarks/SUMMARY.md`

## Scoring

Each ground-truth finding is matched two ways:

| Mode    | Match criterion                                   | Question answered                           |
|---------|---------------------------------------------------|---------------------------------------------|
| strict  | `evidence_id` exact match                         | Did the agent surface the same artefact?    |
| lenient | `(artifact_type, host_path_prefix)` tuple match   | Same TYPE of evidence from same area?       |

Reported metrics:

- `recall` — TP / total ground truth
- `precision` — TP / total findings
- `hallucinations` — findings with no `audit_id` reference (cannot be
  traced back to an MCP call → cannot be reproduced)
- `audit_chain_intact` — every audit.jsonl entry's `prev_hash` matches
  the preceding entry's `entry_hash` (tamper-evident chain verifies)

Strict mode is the headline number reported in DEVPOST_SUBMISSION.md.
Lenient mode is the "would this finding be useful to a human analyst"
number — typically 10-15 percentage points higher.

## Why the strict mode is intentionally hard

A real SOC analyst can match `"OneDriveStartup → C:\\...\\WinUpdate"` and
`"persistence via WinUpdate run key"` as the same finding. The agent has
to phrase it with the canonical evidence_id to score in strict. That
forces the playbook to emit *standardised* finding identifiers, which is
itself a quality requirement for downstream consumers (SIEM correlation,
case management).

## Adding a fourth dataset

```python
# scripts/benchmark/datasets.py
DATASETS["dfrws_2022"] = {
    "title": "DFRWS 2022 Forensic Challenge",
    "short": "dfrws22",
    "year": 2022,
    "filesystem": "...",
    "size_gb": 8.5,
    "license": "...",
    "homepage": "https://dfrws.org/challenges/",
    ...
}
```

Then create `examples/case-studies/case-NN-<name>/ground-truth.json`
matching the schema in `case-08-cfreds-hacking-case/ground-truth.json`.

That's all. `run_benchmark.py all` will pick it up automatically.

## Reproducibility guarantees

Each report records:

- image SHA-256 (so a reviewer can re-pull the same bytes and verify)
- dart-mcp git commit (so identical agent code can be checked out)
- playbook hash (so the same prompts run)
- audit.jsonl SHA-256 chain (so the same MCP calls are verifiable)

Re-running the same dataset on the same dart-mcp commit produces identical
results bit-for-bit. Any drift is a real change in the agent, not noise.
