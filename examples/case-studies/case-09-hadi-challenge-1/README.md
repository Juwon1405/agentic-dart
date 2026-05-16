# Case 09 — Ali Hadi DFIR Challenge #1 (Web Server Case)

> **Why this case exists.** Cases 01-07 use synthetic Windows / macOS /
> Linux evidence authored by this project. Case 08 added the first
> third-party benchmark (NIST CFReDS Hacking Case). This case adds the
> **first Linux-only third-party benchmark** — Ali Hadi's freely
> distributed "Web Server Case" challenge, used in DFIR coursework at
> Champlain College and several other forensics programs.
>
> The point of this case is **not** to claim "dart-mcp solves the Hadi
> Challenge" — that would be dishonest at v0.6.1. The point is to
> **measure honestly what dart-mcp can and cannot do** against a Linux
> web-server compromise dataset that none of this project's authors
> generated, and to use that measurement to drive Phase 2
> prioritization of the Linux artefact surface.

## Source

- **Dataset:** [Ali Hadi DFIR Challenge #1](https://www.ashemery.com/dfir.html)
- **Image:** `Challenge1.7z` (single archive, ~1.5 GB extracted)
- **Author:** Dr. Ali Hadi (Champlain College, formerly Princess Sumaya University)
- **License:** CC-BY-4.0 (academic and personal use)
- **Operating system:** Linux web server (Apache + MySQL + PHP)
- **Subject:** Compromised internet-facing web server — identify the
  initial access vector, enumerate dropped web shells, reconstruct
  attacker shell history, determine exfiltration

## The attack pattern

A small business runs a single Linux web server hosting a PHP
application backed by MySQL. The security team reports the server is
"acting strangely" — sluggish response, unfamiliar processes in `ps`,
and disk activity at off-hours.

Forensic diagnostics in this dataset:

- **Apache `access.log`** — entry vector visible as anomalous URL
  patterns (SQLi probes, LFI traversal, command injection)
- **`/var/www/html/`** — dropped PHP web shells in writeable upload
  directories
- **`/var/log/auth.log`** — sudo escalation events
- **`/root/.bash_history`** — recovered attacker command sequence
- **`/tmp/` and `/dev/shm/`** — attacker workspace, archive staging
- **MySQL binary logs** — unauthorized query patterns from
  web-shell-injected SQL

## Methodology

This case study deliberately does **not** ship the raw 1.5 GB image.
Reasons:

1. The image is freely downloadable from the Ali Hadi page — any reviewer
   can fetch it themselves with one wget.
2. Bundling 1.5 GB in a hackathon repository is wasteful and makes
   `git clone` painful.
3. The published challenge ships with an answer key (PDF) and is
   discussed in numerous public write-ups — re-deriving ground truth
   from the raw image would only verify our extraction pipeline, not
   our detection pipeline.

What this case **does** ship:

- `ground-truth.json` — 10 sampled findings spanning initial access
  through exfiltration, mapped to expected MCP functions and MITRE
  ATT&CK techniques
- Reproducible benchmark integration via
  `scripts/benchmark/run_benchmark.py hadi1`

## How to fetch and run

```bash
# 1. Download the dataset (one-time, ~1.5 GB)
cd ~/agentic-dart
python3 -m scripts.benchmark.download hadi1 ./datasets

# 2. Run the benchmark
python3 -m scripts.benchmark.run_benchmark hadi1

# 3. Inspect the report
cat docs/benchmarks/hadi_challenge_1_*.json
cat docs/benchmarks/SUMMARY.md
```

The downloader resumes interrupted parts and verifies checksums where
published. The benchmark runner:

1. SHA-256 hashes the image (proof of identity)
2. Converts to `evidence_root/` via agentic-dart-collector-adapter
3. Runs `dart_agent` with the senior-analyst-v3 playbook
4. Scores `findings.json` against `ground-truth.json` in both strict
   (exact `evidence_id`) and lenient (artifact type + path prefix) modes
5. Detects hallucinations (findings without `audit_id` reference)
6. Verifies the SHA-256 audit chain is internally consistent
7. Emits the per-run JSON report and appends a row to `SUMMARY.md`

## Expected detection surface

At v0.6.1, dart-mcp's Linux artefact functions cover this case as
follows. Status reflects what the MCP surface can directly extract from
the bundled image with no manual preprocessing.

| Status | Count | Findings |
|---|---:|---|
| Directly detectable | **5** | F-HADI1-001 (Apache access.log), F-HADI1-003 (cron persistence), F-HADI1-004 (auth.log), F-HADI1-005 (bash history), F-HADI1-009 (log tampering) |
| Partially detectable | **3** | F-HADI1-002 (web shell signatures — detect_webshell works on PHP), F-HADI1-006 (network artefacts via syslog), F-HADI1-010 (host identity) |
| Phase 2 roadmap | **2** | F-HADI1-007 (filesystem staging in /tmp — needs `enumerate_filesystem_anomalies`), F-HADI1-008 (MySQL binary log parsing) |

**Expected honest recall** (re-measured live by `run_benchmark.py`):

- Strict (full detection only): ~0.50
- Lenient (full + partial): ~0.80

These numbers are **predictions**, not measurements. Real benchmark
output is appended to `docs/benchmarks/SUMMARY.md` when the user runs
the suite on their analysis host.

## Why this case matters to the SANS submission

| SANS criterion | What this case proves |
|---|---|
| IR Accuracy | Strict + lenient recall on a *non-authored* dataset |
| Hallucination Management | hallucination rate measured against published answer key |
| Audit Trail Quality | audit chain SHA-256 verification on a real evidence collection |
| Documentation | README + ground-truth + reproducible commands |
| Autonomous Execution | end-to-end run with no human in the loop |
| Architectural Guardrails | read-only MCP boundary preserved against external image |

## Phase 2 implications

The Phase-2-roadmap findings above tell us **exactly which functions to
add next** to lift recall above 80% on Linux web-server cases:

1. **`enumerate_filesystem_anomalies`** — surface unexpected files in
   `/tmp`, `/dev/shm`, `/var/tmp` (staging directories)
2. **MySQL binary log parser** — detect attacker queries from
   `mysql-bin.*` files

Both are small (1-day) additions and have known artefact formats.

## Reference

- Challenge homepage: https://www.ashemery.com/dfir.html
- Author's DFIR blog: https://www.ashemery.com/
- Public write-ups: searchable on aboutdfir.com and forensicfocus.com
- License: CC-BY-4.0 (academic and personal use)
