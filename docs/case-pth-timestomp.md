# Case study: Pass-the-Hash with timestomp pre-existence

This page is the conceptual walkthrough of an Agentic-DFIR run: it follows a
full `dfir-agent` invocation
(`python3 -m dfir_agent --case <case-id> --out <output-dir> --mode live`)
against a representative two-host breach and shows, stage by stage, which
`dfir-mcp` functions are called, how `dfir-corr` surfaces a contradiction, and
how the agent revises its hypothesis because of it. The narrative is
representative rather than a bundled case: the four images below are
sample-run stills rendered for documentation (`docs/screenshots/`), and the
numbers in them (process counts, audit-chain length, confidence values) belong
to that illustrative run. The same loop — hypothesis, cross-source validation,
mechanical contradiction, revision — is what `bash examples/demo-run.sh`
executes on the bundled IP-KVM case (see [Case study: IP-KVM remote-hands
insider](./case-ip-kvm.md)). The nearest bundled, executable case for the
techniques in this narrative is self-evaluation case-07 (full ransomware
chain), whose ground truth covers the LSASS credential-access stage
(T1003.001) and log-clearing defense evasion (T1070.001); the Pass-the-Hash and
timestomp steps themselves have no bundled ground-truth entry.

It is intended for two audiences:

1. **Reviewers** — to see the full senior-analyst loop end to end, including
   what happens when artifacts disagree.
2. **DFIR engineers evaluating the project** — to see exactly which `dfir-mcp`
   functions get called in what order, and how `dfir-corr` surfaces a
   contradiction that forces the agent to revise its hypothesis.

---

## The case

A breach is suspected on a small Windows network with two hosts:

- **DESKTOP-7K2L** &nbsp; (192.168.10.42) &nbsp; — analyst workstation
- **FILE-SRV-01** &nbsp; (192.168.10.10) &nbsp; — file server holding HR data

The IR analyst hands the case folder to `dfir-agent` and walks away. The agent
has no prompt about *where* to look or *what* to find — only the senior-analyst
playbook and the read-only MCP surface (`dfir-mcp`, the typed MCP function
surface: native pure-Python functions plus SIFT Workstation adapters). The
playbook at the time of this case was `dfir_playbook/senior-analyst-v1.yaml`;
`senior-analyst-v3.yaml` is now the default, and live mode loads the
highest-versioned `senior-analyst-v*.yaml` in `dfir_playbook/` automatically.

---

## Stage 1 — Initialization & first hypothesis

![dfir-agent startup and first hypothesis](./screenshots/dfir-run-01-init.png)

The agent loads the senior-analyst playbook, spawns `dfir-mcp` over stdio, and
opens the SHA-256 audit chain. Every evidence path a tool receives is resolved
inside `DFIR_EVIDENCE_ROOT` (`_safe_resolve`), so nothing outside the evidence
tree is reachable. The tool surface is enumerated to the typed read-only MCP
surface — 73 tools in the current release (48 native + 25 SIFT Workstation
adapters) — and anything outside that list (e.g. `execute_shell`, `write_file`,
`mount`) is not callable by construction.

**hypothesis_v1** is generated from the case metadata alone:

> *Suspected lateral movement following credential theft on host
> DESKTOP-7K2L. Need: process tree + auth logs.*

Confidence: **0.34**. The agent immediately calls two typed tools to gather
facts:

| Tool | Result |
|---|---|
| `get_process_tree(process_csv=...)` | 142 procs, audit_id `a7d4…c19f` |
| `analyze_windows_logons(security_events_json=...)` | 38 logon events, audit_id `b2e1…8f44` |

Every call is recorded in the audit chain — inputs, outputs, audit_id, token
count, timestamp, and a SHA-256 hash linked to the previous entry.

---

## Stage 2 — MITRE chain begins to form

![dfir-agent calling typed forensic tools and MITRE chain emerging](./screenshots/dfir-run-02-investigate.png)

By iteration 3, evidence has converged on a Pass-the-Hash hypothesis. The agent
issues three more calls in quick succession:

| Tool | Finding | MITRE |
|---|---|---|
| `detect_credential_access()` | `comsvcs.dll` LOLBin LSASS dump in PowerShell event 4104 | **T1003.001** |
| `parse_prefetch(prefetch_path=...)` | First run 14:17:51 UTC, parent chain `explorer → cmd → powershell` | **T1059.001** |
| `detect_lateral_movement()` | PsExec service install on FILE-SRV-01 at 14:23:09 UTC | **T1021.002** |

The agent now has a coherent partial chain:

```
T1059.001 → T1003.001 → T1021.002
```

Confidence climbs to **0.78**. A weaker reasoning loop would stop here and
produce a confident-sounding report. `dfir-agent` doesn't. The senior-analyst
playbook requires a contradiction check before the chain can be accepted, which
is the next call.

---

## Stage 3 — Contradiction detected, hypothesis revised

![dfir-corr detects an UNRESOLVED contradiction; the agent refines](./screenshots/dfir-run-03-contradiction.png)

`correlate_events(hypothesis_id=h_002)` invokes `dfir-corr` (the DuckDB-backed
cross-artifact correlator) and it surfaces a problem:

| Source | Claim |
|---|---|
| Auth events | PtH attack at **14:23:09** — admin token used on FILE-SRV |
| MFT timestamp check | Admin profile timestomp at **14:21:55** — `$SI < $FN` by 11 seconds (anti-forensic activity) |

The contradiction is mechanical: the timestomp happened **before** the
credential was supposedly used. That can only mean the attacker **already had
access to FILE-SRV before the PtH event**. The PtH wasn't the lateral movement;
it was a re-entry.

`dfir-corr` flags this as `UNRESOLVED` rather than letting the LLM decide which
artifact "wins". This is the architectural guarantee: when artifacts disagree,
the agent is forced to revise.

**hypothesis_v3** rewrites the story:

> *Persistence on FILE-SRV pre-existed the PtH event. Need: scheduled tasks +
> service installs before 14:21 UTC.*

A single follow-up call tells us why:

```
list_scheduled_tasks()
  → rogue task: \Microsoft\Windows\System\WindowsUpdate
    created: 2024-10-29 03:14:17 UTC  (5 days earlier)
```

The initial vector is now **5 days earlier** than the auth log suggested.
Confidence rises to **0.89**.

---

## Stage 4 — Final verdict & audit verification

![dfir-agent final verdict with verified audit chain](./screenshots/dfir-run-04-final.png)

The agent's final hypothesis (confidence **0.94**):

> *Persistent foothold established 2024-10-29 03:14 UTC via scheduled task on
> FILE-SRV-01. Dormant for 5 days. Pivot to DESKTOP-7K2L on 2024-11-03 14:17
> UTC, LSASS dump via `comsvcs` LOLBin, PtH back to FILE-SRV at 14:23 UTC.*

Verified MITRE ATT&CK chain:

| Technique | Tactic |
|---|---|
| **T1053.005** &nbsp; Scheduled Task / Job | Persistence |
| **T1059.001** &nbsp; PowerShell | Execution |
| **T1003.001** &nbsp; LSASS Memory | Credential Access |
| **T1070.006** &nbsp; Timestomp | Defense Evasion |
| **T1021.002** &nbsp; SMB / Admin Shares | Lateral Movement |

### Audit verification

```
[audit]  Verifying chain integrity ...
         ✓ 47 entries  ·  SHA-256 chain unbroken
         ✓ tail hash: 4f7a9c1b3e8d2046...8a13c5
         ✓ chain integrity check: 47/47 entries verified
```

A human reviewer can replay the entire reasoning trace from the audit log alone
— every input, every output, every MCP call, every hypothesis revision.
Tampering with any entry breaks the chain at that point: each entry's
`entry_hash` must equal the next entry's `prev_hash`, which is what
`chain integrity check: 47/47 entries verified` is asserting.

---

## What this case study demonstrates

**1. Architecture beats prompts.** The agent never had a prompt instruction to
"look for timestomp activity". The contradiction surfaced because `dfir-corr`
mechanically joined MFT timestamps against authentication events. The agent
then *had* to revise.

**2. Read-only by construction.** At no point did the agent attempt to modify
evidence. Not because it was told not to — because the MCP surface does not
expose any function that could. `bash`, `write_file`, `mount`, and equivalents
simply do not exist on the wire.

**3. Tamper-evident reasoning.** The 47-entry SHA-256 chain means a reviewer
can verify, after the fact, that the agent saw exactly what it claims to have
seen. Nothing was edited. Nothing was retroactively "cleaned up". The chain
breaks if any single entry is altered.

**4. Honest uncertainty.** The agent didn't lock onto its first hypothesis. The
system isn't "confidence inflation by repetition" — contradictions get a fair
hearing because [`dfir-corr`](../dfir_corr/README.md) is structurally required
to flag them.

---

## Reproducing this run

The bundled evidence and playbooks live in the repository. The simplest
reproduction of the loop is the deterministic demo (no API key), which runs the
bundled IP-KVM case (`examples/case-studies/self-evaluation/case-01/`) and
writes to `examples/out/demo/`:

```bash
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
bash examples/demo-run.sh
```

The deterministic demo lands on the same tool sequence, findings and
hypotheses on every run. The audit chain is self-consistent (every entry's
`entry_hash` matches the next entry's `prev_hash`), while the per-run
`audit_id`s, entry hashes and timestamps differ by design, which prevents one
run's chain from being replayed as another's. The committed reference run is
`examples/out/ref-01/`; the IP-KVM case study explains how to trace its
findings back to the evidence.

---

## See also

- [Case study: IP-KVM remote-hands insider](./case-ip-kvm.md) — the bundled, executable case study
- [Architecture](./architecture.md) — the component layout this walkthrough exercises
- [`dfir-corr`](../dfir_corr/README.md) — the engine that found the contradiction
- [Writing case studies](./writing-case-studies.md) — how to add a new bundled case
