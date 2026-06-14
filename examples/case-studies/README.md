# Case studies

End-to-end DFIR investigations used to exercise the agent loop and benchmark
per-case detection. Cases are split into two tiers; every case directory is
**self-contained**:

```
case-studies/
├── self-evaluation/        # synthetic scenarios authored for this project
│   ├── case-01/  README.md  truth.json  evidence_root/   <- bundled evidence
│   ├── case-02/  README.md  truth.json
│   └── ... case-08/
└── external-evaluation/    # public third-party datasets (downloaded on demand)
    ├── case-01/  README.md  truth.json
    ├── case-02/  README.md  truth.json
    └── case-03/  README.md  truth.json
```

Folder names are **index-only** (`case-01`, `case-02`, …); the human title
lives in each case's `README.md`. Each case ships a `README.md` (incident
narrative + reasoning hooks) and a `truth.json` (expected findings, IOCs,
ATT&CK mapping). The agent resolves a case's evidence from its own
`case-XX/evidence_root/`. Per-case scoring lives in
`../../scripts/eval/score.py`.

Run a case with the primary CLI:

```bash
python3 analyze.py --case self-evaluation/case-01
python3 analyze.py --case external-evaluation/case-01 --download
```

## Tier 1 — self-evaluation (synthetic)

Curated incidents authored for this project. `case-01` ships the **canonical
bundled evidence** (`evidence_root/`, the production-volume realistic tree) and
is the measured regression baseline (recall 1.0, hallucination 0). The other
self-evaluation cases are scenario specifications (narrative + ground truth)
that share the same canonical evidence model; they are documentation-grade and
are not separately bundled with their own evidence tree.

| Tier | Case | Title | Dataset source | Evidence type | Expected findings |
|------|------|-------|----------------|---------------|------------------:|
| self | case-01 | IP-KVM remote-hands insider pattern | Authored (bundled `evidence_root/`) | Multi-platform host triage | 5 |
| self | case-02 | Living-off-the-land PowerShell | Authored scenario spec | Windows event logs / PowerShell | 7 |
| self | case-03 | macOS remote-admin infection + exfiltration | Authored scenario spec | macOS unified logs / artifacts | 8 |
| self | case-04 | Phishing → download → execution → exfiltration | Authored scenario spec | Browser / disk / network | 6 |
| self | case-05 | Authentication, AD, and lateral movement | Authored scenario spec | Security event logs / AD | 8 |
| self | case-06 | Web attack + RDP brute force (dual entry) | Authored scenario spec | Web logs / RDP / event logs | 10 |
| self | case-07 | Full ransomware chain (ATT&CK coverage) | Authored scenario spec | Host triage / timeline | 13 |
| self | case-08 | Supply-chain → AD CS abuse → lateral movement | Authored scenario spec | AD CS / registry / event logs | 12 |

## Tier 2 — external-evaluation (public datasets)

Built on community-verified public datasets. Evidence is **not bundled** (size
and third-party licensing); download on demand. `analyze.py --case
external-evaluation/case-XX --download` prints/runs the exact fetch command.

| Tier | Case | Title | Dataset source | Evidence type | Expected findings |
|------|------|-------|----------------|---------------|------------------:|
| external | case-01 | NIST CFReDS Hacking Case (Greg Schardt / "Mr. Evil") | [NIST CFReDS](https://cfreds-archive.nist.gov/all/NIST/HackingCase) | NTFS dd image (Windows XP) | 10 |
| external | case-02 | Ali Hadi DFIR Challenge #1 (Web Server Case) | [ashemery.com](https://www.ashemery.com/dfir.html) | E01 image (Win Server 2008 + XAMPP) | 10 |
| external | case-03 | Digital Corpora M57-Patents — Jo's PC | [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/) | E01 image (Windows XP, subject **Jo**) | 10 |

> **M57 subject note.** This benchmark uses the **M57-Patents** scenario, subject
> **Jo (Joanne)** — image `jo-2009-12-10.E01`, employees charlie/jo/pat/terry.
> It is *not* the separate single-machine "M57-Jean" scenario; an earlier draft
> mislabelled it "Jean". The download registry, README, truth file, and host
> paths now all agree on **Jo**.

External dataset registry, checksums, and download commands:
`../../scripts/eval/datasets.py` and
`python3 -m scripts.eval.download --help`.
