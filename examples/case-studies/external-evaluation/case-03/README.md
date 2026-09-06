# External Case 03 — Digital Corpora M57-Patents Scenario (Jo's PC)

**Tier:** external-evaluation (public dataset, downloaded on demand)

> **Why this case exists.** External cases 01 and 02 added the first two
> third-party benchmark datasets (NIST CFReDS, Ali Hadi). This case
> adds the **most realistic corporate scenario in public DFIR
> datasets** — the M57-Patents scenario, jointly authored by the Naval
> Postgraduate School and NIST, used in graduate-level forensics
> programs and many enterprise IR training courses.
>
> The point of this case is to measure dfir-mcp against an
> **insider-threat / corporate-IP-theft** scenario rather than the
> external-intrusion patterns of external cases 01-02. The threat model is
> different: legitimate user, legitimate credentials, illegitimate
> intent. The forensic surface that matters most is *user activity
> reconstruction*, not malware detection.

## Source

- **Dataset:** [Digital Corpora M57-Patents Scenario](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/)
- **Authors:** Simson Garfinkel (NPS), Kevin Fairbanks (Johns Hopkins),
  Joachim Metz (Google) — with funding support from NIST
- **License:** CC-BY-3.0 (academic and commercial use)
- **Scenario:** M57.biz, a fictional patent-research firm, over 17 days
  with 4 employees (Jo, Pat, Charlie, Terry)
- **This case targets:** Jo's PC subset only (~10 GB E01/AFF) — the
  PC at the centre of the corporate IP-theft narrative
- **Operating system:** Windows XP Professional
- **Full scenario size:** ~50 GB (4 PCs + network captures + USB drives)
  — we deliberately restrict to Jo's PC for tractable benchmarking

## The attack pattern

M57.biz is a small patent-research company. Four employees use company
laptops over a 17-day period. Two scenarios run in parallel:

1. **Primary thread (Jo's PC):** Jo exfiltrates patent-research
   documents to an external party. Evidence is on Jo's workstation:
   email, browser history, recently-used files, USB activity.

2. **Background thread:** Unrelated employee-conduct issue — useful as
   *noise* for testing whether dfir-mcp can distinguish the IP-theft
   signal from unrelated activity.

Forensic diagnostics in this dataset:

- **NTUSER.DAT** — Jo's RecentDocs MRU, TypedPaths, MUICache
- **Outlook Express `.dbx` files** — sent emails to external recipient
  with attached patent documents
- **IE browser history** — webmail logins, file-drop service visits
- **`$Recycle.Bin` + MFT** — deleted-and-emptied patent file artefacts
- **`$Extend\\$UsnJrnl:$J`** — USN journal capturing create/rename/delete
  events on patent files
- **Prefetch + Amcache** — execution of WinZip / 7-Zip / Outlook Express
  during exfiltration window
- **Pagefile.sys** / **hiberfil.sys** — residual memory artefacts

## Methodology

This case study deliberately does **not** ship the raw 10 GB image.
Reasons:

1. The image is freely downloadable from Digital Corpora's mirror — any
   reviewer can fetch it themselves.
2. Bundling 10 GB in a Git repository is wasteful and makes
   `git clone` painful.
3. Digital Corpora ships authoritative scenario documentation; the
   ground truth is peer-reviewed and stable.

What this case **does** ship:

- `truth.json` — 10 sampled findings focused on the IP-theft
  narrative, mapped to expected MCP functions and MITRE ATT&CK
  techniques
- Reproducible benchmark integration via
  `scripts/eval/external.py m57`

## How to fetch and run

```bash
# 1. Download Jo's PC subset (one-time, ~10 GB)
cd ~/agentic-dfir
python3 -m scripts.eval.download m57 ./datasets

# 2. Run the benchmark
python3 -m scripts.eval.external --case external-evaluation/case-03

# 3. Inspect the report
cat out/benchmarks/SUMMARY.md
cat out/benchmarks/MODEL-COMPARISON.md
```

Note: M57 images are distributed in AFF or E01 format. The downloader
auto-detects format. The benchmark runner uses
`agentic-dfir-collector-adapter` (or its raw-image fallback) to mount
and extract the filesystem before invoking `dfir_agent`.

## Expected detection surface

At v0.6.1, dfir-mcp's Windows artefact functions cover this case as
follows. Insider-threat / user-activity reconstruction is a different
surface than malware detection — many of the relevant functions are
already in the MCP catalogue.

| Status | Count | Findings |
|---|---:|---|
| Directly detectable | **4** | F-M57J-001 (SAM/NTUSER.DAT host attribution), F-M57J-002 (RecentDocs MRU), F-M57J-007 (Prefetch/Amcache), F-M57J-010 (mapped drives) |
| Partially detectable | **4** | F-M57J-005 (IE history via `parse_browser_history`), F-M57J-006 (Recycle Bin metadata — basic), F-M57J-008 (USN journal — exists, needs polish), F-M57J-009 (browser credentials) |
| Phase 2 roadmap | **2** | F-M57J-003 (Outlook Express DBX parser), F-M57J-004 (DBX attachment extraction) |

**Expected honest recall** (re-measured live by `scripts/eval/external.py`):

- Strict (full detection only): ~0.40
- Lenient (full + partial): ~0.80

The 0.40 strict number is **lower** than external case 02's expected 0.50
because the Outlook Express `.dbx` format requires a custom parser
that dfir-mcp does not ship yet. That's a Phase 2 gap, not a design
flaw.

## Why this case matters

| Property | What this case proves |
|---|---|
| Accuracy | Recall on an *insider-threat* dataset, not just intrusion |
| Hallucination rate | hallucination rate when the threat is *user behaviour*, not malware |
| Audit trail | SHA-256 audit chain on a multi-day activity reconstruction |
| Documentation | README + ground-truth + reproducible commands |
| Autonomous execution | end-to-end run with no human in the loop |
| Read-only boundary | read-only MCP boundary preserved on a 10 GB image |

## Phase 2 implications

The Phase-2-roadmap findings above tell us **exactly which functions to
add next** to lift recall above 80% on insider-threat cases:

1. **Outlook Express DBX parser** — parse `.dbx` mailbox structure,
   extract message metadata and bodies. Well-documented format,
   2-day implementation. Adds T1114 (Email Collection) detection
   surface to dfir-mcp.

2. **DBX attachment extraction** — once messages parse, extract MIME
   attachments. Trivial follow-on to the parser.

Both are bounded-scope additions with known artefact formats and would
also unlock value for legacy mail-format cases beyond M57.

## Comparison — three benchmark cases side by side

| Aspect | external case 01 CFReDS | external case 02 Hadi | external case 03 M57 |
|---|---|---|---|
| OS | Windows XP | Linux | Windows XP |
| Threat | WiFi sniffing tools | Web compromise | Insider IP theft |
| Size | ~5 GB | ~1.5 GB | ~10 GB (Jo only) |
| Era | 2004 | 2014 | 2009 |
| Primary surface | AmCache + Prefetch + registry | Apache + auth.log + bash | NTUSER + Email + USN |
| Predicted strict recall | 0.10 | 0.50 | 0.40 |
| Predicted lenient recall | 0.40 | 0.80 | 0.80 |

The three cases together test dfir-mcp across **two operating systems,
three threat models, three decade-eras** — far more diverse than any
single dataset alone could prove.

## Reference

- Scenario homepage: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
- Downloads: https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/
- Academic paper: Simson L. Garfinkel et al., "The M57-Patents
  Scenario: A Realistic, Synthetic Corpus for Forensics Research",
  DFRWS 2009
- License: CC-BY-3.0 (academic and commercial use)
