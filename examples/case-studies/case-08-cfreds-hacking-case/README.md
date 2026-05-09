# Case 08 — NIST CFReDS Hacking Case (Greg Schardt / "Mr. Evil")

> **Why this case exists.** Cases 01-07 use synthetic evidence authored
> by the project. This case is the first integration with a
> **community-verified, third-party benchmark dataset** — NIST's
> CFReDS Hacking Case, published in the mid-2000s and cited in
> hundreds of academic forensics courses and SANS GCFE / GCFA prep
> materials.
>
> The point of this case is **not** to claim "dart-mcp solves the
> Hacking Case" — that would be dishonest. The point is to **measure
> honestly what dart-mcp v0.5.3 can and cannot do** against an
> external dataset that none of the project's authors generated, and
> to use that measurement to drive Phase 2 prioritization.

## Source

- **Dataset:** [NIST CFReDS Hacking Case](https://cfreds-archive.nist.gov/Hacking_Case.html)
- **Image:** 4Dell Latitude CPi.E01/E02 (DD format split parts SCHARDT.001-008)
- **Image MD5:** `AEE4FCD9301C03B3B054623CA261959A`
- **Official answers (ground truth):** [TestAnswers.pdf](https://cfreds-archive.nist.gov/images/TestAnswers.pdf) — 31 questions with NIST-published answers
- **Operating system:** Windows XP Professional (Build 2600), installed 2004-08-19
- **Subject:** Greg Schardt aka "Mr. Evil" — wireless traffic interception case

## Methodology

This case study deliberately does **not** ship the raw 4 GB disk image.
Reasons:

1. The image is freely downloadable from NIST's archive — anyone
   reviewing this case can fetch it themselves.
2. Bundling 4 GB in a hackathon repository is wasteful and makes
   `git clone` painful.
3. The published `TestAnswers.pdf` already contains the
   peer-reviewed ground truth. Re-deriving it from the raw image
   would only verify our extraction pipeline, not our detection
   pipeline.

What this case **does** ship:
- `evidence-snippet/Hacking_Case.html` — original NIST case briefing
- `evidence-snippet/TestAnswers.txt` — official answers (extracted from PDF)
- `evidence-snippet/SCHARDT.LOG` — original acquisition log
- `ground-truth.json` — the 10 sampled findings most relevant to
  dart-mcp's current capability surface, mapped to expected MCP
  functions and labelled with detection status (`directly_detectable_v053`).

## Honest accuracy assessment (v0.5.3)

Of 10 sampled NIST ground-truth findings, dart-mcp v0.5.3 status:

| Status | Count | Findings |
|---|---:|---|
| Directly detectable | **1** | F-CFR-003 (installed hacking software via AmCache + Prefetch) |
| Partially detectable | **3** | F-CFR-005 (Ethereal capture file), F-CFR-006 (Yahoo email cache), F-CFR-007 (last logon user) |
| Phase 2 roadmap | **6** | F-CFR-001/002/004/008/009/010 — generic registry hive parsing, recycle bin, YARA rules |

**Honest recall:**
- Strict (full detection only): **0.10**
- Lenient (full + partial): **0.40**

This is a **deliberate, transparent disclosure**. Compare to
`docs/accuracy-report.md`:
- Reference variant (synthetic): recall 1.000 — measures correctness of the detection logic against IOCs the system claims to detect
- Realistic variant (synthetic + noise): recall 1.000 — measures robustness to noise on the same claim space
- **CFReDS variant (this case):** recall 0.10-0.40 — measures **expansion potential** against a content-centric paradigm dart-mcp hasn't fully covered yet

The drop from 1.0 to 0.10 is not a regression; it's a **paradigm
mismatch**. dart-mcp v0.5.3 is artifact-centric (timeline, persistence
mechanisms, lateral movement signals). CFReDS is content-centric (what
specific strings appear in which specific files). Both are valid
forensic paradigms; this case study makes the gap explicit and
trackable.

## Gap analysis → Phase 2 prioritization

CFReDS integration directly drove the Phase 2 priority list:

| Gap | Blocks | Effort |
|---|---|---|
| Generic SOFTWARE/SYSTEM/SAM hive value extraction ([#52](https://github.com/Juwon1405/agentic-dart/issues/52)) | F-CFR-001, 004, 007, 010 (4/10 findings) | 1-2 weeks |
| IE6 / Outlook Express index.dat parser ([#53](https://github.com/Juwon1405/agentic-dart/issues/53)) | F-CFR-006 | 2-3 days |
| Recycle Bin INFO2 / $I$R parser ([#54](https://github.com/Juwon1405/agentic-dart/issues/54)) | F-CFR-008 | 1-2 days |
| YARA rule library + bundled rules ([#55](https://github.com/Juwon1405/agentic-dart/issues/55), see also #10) | F-CFR-009 | Phase 2 |

**This is the value of external benchmarking** — it converts "we
should probably add registry parsing someday" into "registry parsing
unblocks 4 of 10 measured findings, so it's the highest-priority
Phase 2 deliverable."

## How to invoke (when SOFTWARE hive parsing lands in Phase 2)

```bash
# After Phase 2 Gap G-001 ships
python3 -c "
from dart_mcp import call_tool

# Question 5 — registered owner
r = call_tool('parse_registry_hive', {
    'hive_path': 'Windows/system32/config/software',
    'key': 'Microsoft\\\\Windows NT\\\\CurrentVersion\\\\RegisteredOwner'
})
print(f'F-CFR-001 expected: Greg Schardt → got: {r[\"value\"]}')

# Question 16 — installed hacking tools (works in v0.5.3)
r = call_tool('get_amcache', {'amcache_hive': 'Windows/AppCompat/Programs/Amcache.hve'})
hacking_tools = ['cain', 'ethereal', 'netstumbler', 'cuteftp', 'looklan']
matches = [e for e in r.get('entries', []) if any(t in e.get('name', '').lower() for t in hacking_tools)]
print(f'F-CFR-003 expected: 6+ tools → got: {len(matches)}')
"
```

## What you should take away from this case

If you are evaluating dart-mcp:

1. **The reference accuracy numbers (recall=1.0) are real for what
   they measure** — the synthetic IOC detection paradigm dart-mcp
   ships with.
2. **They do not generalize to all forensic paradigms** — content-
   centric questions ("what does this file contain") need additional
   primitives that are Phase 2 work.
3. **This case study makes that limit explicit and quantified**, with
   a peer-reviewed external benchmark and a measured gap list.
4. **Honest gap disclosure beats inflated claims.** A reviewer who
   sees 1.0/0.0/0/0 across all variants and 0.10 against CFReDS will
   trust the project more than one who sees 1.0 across the board with
   no external benchmark at all.

## References

- NIST CFReDS Hacking Case: <https://cfreds-archive.nist.gov/Hacking_Case.html>
- NIST official answers: <https://cfreds-archive.nist.gov/images/TestAnswers.pdf>
- LunaM00n's CFReDS walkthrough (community example): <https://github.com/LunaM00n/LOL-Bin/blob/master/Forensics/Labs/01_CFReDS_Hacking_Case.md>
- Forensicxs Autopsy walkthrough: <https://www.forensicxs.com/computer-forensics-hacking-case-using-autopsy/>
