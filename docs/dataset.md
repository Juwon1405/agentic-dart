# Evidence Dataset Documentation

Agentic-DFIR is exercised against two tiers of evidence. Tier 1 is bundled with
the repository and has authored ground truth; Tier 2 is public third-party
material that is downloaded on demand. Per-case, per-model results for both
tiers are recorded in [`benchmarks/ledger.json`](./benchmarks/ledger.json) and
rendered into [`benchmarks/MODEL-COMPARISON.md`](./benchmarks/MODEL-COMPARISON.md)
and [`benchmarks/SUMMARY.md`](./benchmarks/SUMMARY.md).

## Primary dataset — bundled self-evaluation cases

Eight synthetic scenarios under
`examples/case-studies/self-evaluation/case-01` … `case-08`, authored for this
project. Every case directory carries a `README.md` (incident narrative) and a
`truth.json` (expected findings: `finding_id`, category, claim, artifact path,
the `dfir_mcp` function expected to surface it, MITRE ATT&CK technique(s), and
severity).

- **Evidence:** each case ships its own `evidence_root/` holding that
  scenario's artifacts plus benign noise, so recall is measured per case
  without any prompt hint. `truth.json` entries point at files inside the
  case's own tree (`disk/…`, `linux/…`, `mac/…`, `web/…`). The scenario
  narratives are in
  [`examples/case-studies/self-evaluation/README.md`](../examples/case-studies/self-evaluation/README.md).
- **Ground truth:** authored alongside the evidence; each `truth.json` records
  its provenance in `case_metadata.ground_truth_provenance`.
  `scripts/eval/validate_ground_truth.py` gates truth-file integrity in CI.
- **License:** authored for this project and distributed under the repository
  license; no third-party material.
- **Integrity:** every MCP call's output digest is SHA-256-chained into
  `audit.jsonl`; `scripts/eval/demo.py` additionally hashes every file under
  the evidence root before and after the deterministic run and reports
  `evidence_integrity`.

| Case | Title | Evidence type | Expected findings |
|---|---|---|---:|
| case-01 | IP-KVM remote-hands insider pattern | Multi-platform host triage | 5 |
| case-02 | Living-off-the-land PowerShell | Windows event logs / PowerShell | 7 |
| case-03 | macOS remote-admin infection + exfiltration | macOS unified logs / artifacts | 8 |
| case-04 | Phishing → download → execution → exfiltration | Browser / disk / network | 6 |
| case-05 | Authentication, AD, and lateral movement | Security event logs / AD | 8 |
| case-06 | Web attack + RDP brute force (dual entry) | Web logs / RDP / event logs | 10 |
| case-07 | Full ransomware chain (ATT&CK coverage) | Host triage / timeline | 13 |
| case-08 | Supply-chain → AD CS abuse → lateral movement | AD CS / registry / event logs | 12 |

## External tier — public datasets (downloaded on demand)

Three community-verified public forensic images under
`examples/case-studies/external-evaluation/case-01` … `case-03`. Each is a
multi-GB image under its own licence, so the full evidence is **not committed**;
only `README.md` and `truth.json` are bundled (case-01 also ships a small
`evidence-snippet/` of freely redistributable artifacts). Fetch the image with:

```bash
python3 analyze.py --case external-evaluation/case-01 --download
```

`--download` fetches and checksum-verifies the image only. To download,
verify and adapt the image into the case's `evidence_root/` in one step
without spending tokens, use `python3 -m scripts.eval.external --prepare-only`
(all three cases) or `--case external-evaluation/case-01` for one. The dataset
registry (URLs, checksums, image names) is `scripts/eval/datasets.py`;
`python3 -m scripts.eval.download --help` lists the fetch commands.

### 1. NIST CFReDS — Hacking Case (`external-evaluation/case-01`)

- **Source:** https://cfreds.nist.gov/all/NIST/HackingCase
- **Why:** Canonical intrusion-analysis scenario with published ground truth
- **Ground truth:** bundled with the dataset by NIST

### 2. Ali Hadi — DFIR Challenge #1, Web Server Case (`external-evaluation/case-02`)

- **Source:** https://www.ashemery.com/dfir.html (Ali Hadi's canonical DFIR challenges page)
- **Related:** https://github.com/ashemery/DFIR-ICTCS17 (his DFIR workshop repo)
- **Why:** Community-vetted challenges with documented answer keys; useful for regression

### 3. Digital Corpora — M57-Patents, subject Jo (`external-evaluation/case-03`)

- **Source:** https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
- **Why:** Multi-host, multi-day scenario with insider-threat elements; matches Agentic-DFIR's target case class
- **Ground truth:** published scenario narrative and artifact list

## Case classes exercised

| Class | Artifacts | Ground-truth source |
|---|---|---|
| Insider-threat / unauthorized access | USB history, Amcache, Prefetch, Security event logs | self-evaluation cases + M57-Patents |
| Remote-hands / IP-KVM pattern | USB setupapi, authentication telemetry, process tree | self-evaluation cases |
| Living-off-the-land | Scheduled tasks, PowerShell history, WMI persistence | CFReDS Hacking Case |

## Per-case results

Ground truth for every case lives in that case's `truth.json`; scoring is
`scripts/eval/score.py` (recall over the tool-reachable subset of findings).
Per-case, per-model results are recorded in
[`benchmarks/ledger.json`](./benchmarks/ledger.json) by
`python3 -m scripts.eval.self` and `python3 -m scripts.eval.external`; the
rendered tables are
[`benchmarks/MODEL-COMPARISON.md`](./benchmarks/MODEL-COMPARISON.md) (per
case), [`benchmarks/SUMMARY.md`](./benchmarks/SUMMARY.md) (totals), and
[`benchmarks/HISTORY.md`](./benchmarks/HISTORY.md) (run history).

## Integrity and reproducibility

- All dataset files are mounted read-only (`mount -o ro,noload`) before the agent is invoked
- `scripts/eval/demo.py` hashes every input before and after the deterministic run and fails if any digest changed
- No dataset file is ever modified; extraction writes only to the output directory
- Chain-of-custody for each deterministic run is preserved in the SHA-256-chained `audit.jsonl`

## See also

- [Accuracy report](./accuracy-report.md) — how these cases are scored and what the numbers mean
- [`benchmarks/README.md`](./benchmarks/README.md) — the ledger and its reading
- [Quick start](./QUICKSTART.md) — the download → adapt → analyze steps for the external tier
- [`scripts/eval/README.md`](../scripts/eval/README.md) — the evaluation suite
- [`examples/README.md`](../examples/README.md) — the evidence and case-study layout
