# Agentic-DART — SANS FIND EVIL! 2026 Submission

> **Submission URL:** https://findevil.devpost.com/
> **Project URL:** https://github.com/Juwon1405/agentic-dart
> **License:** MIT
> **Version at submission:** v0.7.0
> **Submission date:** 2026-06-15
> **Author:** Bang Juwon (sole contributor)

---

## Inspiration

Most agentic DFIR demos prove that an LLM can hallucinate persuasively
inside a Jupyter notebook. None of them answer the questions a senior
analyst actually asks when handed an evidence drive:

- Did the agent **trace its conclusions** back to specific MCP calls?
- Did the agent **retract** an early hypothesis when later evidence
  contradicted it?
- Could the agent **even attempt** a destructive operation if the LLM
  decided to?
- Can a reviewer **reproduce the same findings bit-for-bit** six months
  from now, on a different host, with no access to the original
  context window?

Agentic-DART is built around those four questions. The design is
**architecture-first, not prompt-first**: the LLM cannot misbehave
because the wire it speaks on does not expose misbehaviour.

---

## What it does

Agentic-DART is an autonomous DFIR (Digital Forensics and Incident
Response) agent that runs on the SANS SIFT Workstation. It exposes
**67 typed, read-only forensic functions** to Claude via a custom MCP
(Model Context Protocol) server, executes a structured **10-phase
playbook**, and emits:

- `findings.json` — typed evidence findings with provenance
- `audit.jsonl` — tamper-evident SHA-256-chained record of every MCP
  call made
- `report.md` — human-readable case report suitable for handing to a
  manager or attorney

The agent runs end-to-end with no human intervention on a clean
SIFT VM, and produces output a senior DFIR analyst would recognise as
their own — because the playbook codifies how a senior analyst
actually walks a case.

---

## How we built it

### Phase 0 — Architectural guardrails (the foundation)

Before any detection logic was written, the MCP boundary was defined
to be **physically incapable** of:

- executing shell commands
- writing files outside `evidence_root/`
- mounting partitions
- evaluating arbitrary code

This is enforced not by a system prompt asking the LLM to behave, but
by the fact that **those functions do not exist on the wire**. The
test suite includes a **bypass test pack** that verifies the absence
of these primitives is preserved across every release.

### Phase 1 — The 10-phase playbook

```
P0  Scope & volatility assessment
P1  Initial access vector triage
P2  Timeline reconstruction
P3  Anomaly surfacing
P4  Hypothesis formation
P5  Kill-chain assembly
P6  Contradiction handling
P7  Attribution & Diamond Model
P8  Recovery & denial check
P9  Finding emission
```

Each phase emits typed findings into `findings.json`, and every MCP
call is hashed into `audit.jsonl`. The playbook is YAML-defined
(`dart_playbook/senior-analyst-v3.yaml`), so a customer can swap in
their own playbook without modifying the agent code.

### Phase 2 — 67 native MCP functions

Each function is **typed**, **read-only**, and emits **structured
findings** the agent can correlate against later. Coverage by surface:

- **Windows** (24 functions): Amcache, Prefetch, ShimCache, Registry
  hives, Scheduled Tasks, Event Logs, USB history, ShellBags, MFT,
  USNJrnl, Recycle Bin, Browser history, Downloads, Persistence,
  Kerberos events, etc.
- **macOS** (8 functions): UnifiedLog, KnowledgeC, FSEvents, plist,
  LaunchAgents/Daemons, **LSQuarantineEvent** (v0.6.1), TCC, etc.
- **Linux** (12 functions): auth.log, syslog, journald, auditd,
  bash_history, web logs, **cron** (v0.6.1), shell history, package
  manager, network state.
- **Cross-platform / correlation** (23 functions): DuckDB scale-engine
  timeline correlation, process tree, lateral movement detection,
  ransomware behaviour, credential access, defense evasion, discovery,
  **DNS tunneling** (v0.6.1), MITRE ATT&CK mapping, etc.

### Phase 3 — SIFT Workstation adapter layer

For the heavy-lift artefact formats where reinventing the parser would
be wasteful, dart-mcp wraps existing SIFT toolchain binaries:
**Volatility 3, MFTECmd, EvtxECmd, PECmd, RECmd, AmcacheParser, YARA,
log2timeline, psort**. Each wrapper preserves the read-only guarantee
of the MCP boundary — the bypass tests cover the SIFT adapters
identically.

### Phase 4 — Collector-adapter (separate repository)

`agentic-dart-collector-adapter` is a stdlib-only Python layer that
converts third-party collection output (Velociraptor offline-collector
ZIP, raw disk images, and in v0.2 Falcon Forensics export) into the
`evidence_root/` layout dart_agent reads. This keeps the analysis
engine **decoupled from any single collection vendor**.

---

## Technologies used

| Component | Stack |
|---|---|
| Agent runtime | Python 3.10+, MCP stdio, Claude API |
| Forensic functions | stdlib-only Python (no third-party dependencies) |
| Scale engine | DuckDB (for cross-source timeline correlation) |
| Heavy parsers | SIFT toolchain (Volatility 3, MFTECmd, EvtxECmd, ...) |
| Audit chain | SHA-256 linked JSONL |
| Test suite | pytest (72 tests, all green at submission) |
| CI | GitHub Actions (Linux + macOS) |
| Sample evidence | seeded deterministic generator |

---

## Mapping to SANS FIND EVIL! 2026 evaluation criteria

### 1. IR Accuracy

Agentic-DART is evaluated against **11 case studies** spanning two
evidence tiers:

| Tier | Cases | Evidence | Total findings |
|---|---|---|---:|
| Internal (synthetic, production-noise-injected) | case-01 to case-07, case-11 | `examples/sample-evidence-realistic/` (748 KB bundled) | 69 |
| External (third-party, community-verified) | case-08 to case-10 | NIST CFReDS / Ali Hadi / Digital Corpora M57 (~13 GB downloaded) | 30 |

External datasets are deliberately chosen across three independent
authoring bodies (US NIST, Champlain College, Naval Postgraduate
School) to avoid source bias. All three predate dart-mcp by 10-20
years — they cannot represent in-distribution training data.

**Measured numbers on internal evidence** (Layer 1,
`docs/accuracy-report.md`):
- Recall: **1.000**
- False positive rate: **0.000**
- Hallucinations: **0**
- Evidence integrity preserved: **true** (SHA-256 pre/post match across 49 files in realistic variant)

**Measured numbers on external datasets** (Layer 2): see
`docs/benchmarks/SUMMARY.md`. Re-run the entire benchmark suite with:

```bash
python3 -m scripts.benchmark.run_all --download
```

### 2. Hallucination management

The headline demonstration is **Scene 4 of the demo video** and
**case-04 finding F-PHISH-006**: the agent forms an initial hypothesis
("OneDriveStartup persistence"), runs `parse_registry_hive`, sees that
the path actually points to a legitimate Microsoft component, and
**retracts the hypothesis**. Confidence drops from 0.62 to 0.43, the
agent then re-correlates and lands on the actual persistence mechanism
(`HKCU\...\Run\WinUpdate`), confidence rises to 0.91.

The retraction is recorded in `audit.jsonl` as a separate event with
its own SHA-256 hash. A reviewer can re-derive the corrected
conclusion deterministically.

**Mechanical hallucination metric:** any finding lacking an `audit_id`
reference is counted as hallucination. The benchmark suite reports
hallucination rate as a hard column in `SUMMARY.md`. No softer
definition is used.

### 3. Audit trail quality

Every MCP call is hashed into `audit.jsonl` with three fields:

- `prev_hash` — SHA-256 of the previous entry
- `entry_hash` — SHA-256 of this entry's canonical JSON
- `tool_name`, `args`, `result_digest`, `timestamp`

The chain is verified by `dart_audit verify` (and re-verified
automatically in CI). The benchmark suite reports
`audit_chain_intact: true|false` as a column.

A reviewer can trace any finding ID back to the exact MCP call that
produced it via `dart_audit trace F-NNN`.

### 4. Autonomous execution

The full 10-phase playbook runs end-to-end with no human in the loop:

```bash
# One command, no prompts, no human interaction
python3 -m dart_agent --evidence-root ./evidence --output ./out
```

Typical runtime on a clean SIFT VM with bundled sample evidence:
~30 seconds. On a 5 GB CFReDS image: ~5-10 minutes.

### 5. Architectural guardrails

Three properties verified by the test suite on every CI run:

- **No destructive primitives on the wire.** `bypass_tests/` confirms
  `execute_shell`, `write_file`, `mount`, `eval` are not registered as
  MCP tools, even after the SIFT adapter layer is loaded.
- **Path traversal blocked at the MCP boundary.** Attempts to access
  paths outside `evidence_root/` are refused by the typed path
  validator before any function body executes.
- **The boundary is the canonical name set.** Adding new tools cannot
  weaken the boundary because the boundary is enforced by which
  function names exist, not by per-function checks.

### 6. Documentation

| Surface | Path |
|---|---|
| Top-level overview | `README.md` |
| Per-case walkthroughs | `examples/case-studies/case-NN/README.md` (11 cases) |
| Per-case machine-readable ground truth | `examples/case-studies/case-NN/ground-truth.json` |
| Benchmark suite operator guide | `scripts/benchmark/README.md` |
| Accuracy report (Layer 1) | `docs/accuracy-report.md` |
| Accuracy report (Layer 2) | `docs/benchmarks/SUMMARY.md` |
| Architecture | `docs/architecture.md` |
| Playbook | `dart_playbook/senior-analyst-v3.yaml` |
| Audit format | `dart_audit/README.md` |
| Collector adapter | `https://github.com/Juwon1405/agentic-dart-collector-adapter` |
| Demo video | `docs/demo_assets/output/agentic-dart-demo-en.mp4` (also Korean + Japanese versions) |

---

## Challenges we ran into

1. **The drift problem.** Hardcoded counts (function counts, test
   counts, playbook step counts) had been duplicated across ~25
   locations: README, CHANGELOG, wiki, profile README, GitHub Pages,
   CI workflow, install scripts, demo scripts. Every release that
   touched any of these required hand-editing all 25 places, and CI
   went red for 10 consecutive pushes during v0.6.0. **Resolution:**
   moved all counts to a single source of truth and used invariant
   assertions ("at least N") in CI rather than exact-equals checks.

2. **The contradiction-handling problem.** Early playbook versions
   would smooth over conflicts between data sources (e.g. USB
   insertion at 14:19:47 vs operator logon at 14:22). LLMs prefer
   coherent narratives. **Resolution:** added a hard architectural
   constraint that **unresolved contradictions cannot be silently
   discarded** — the agent must surface them or declare them
   unreachable. case-01 IP-KVM insider demonstrates this.

3. **The provenance problem.** Many "agentic" tools produce findings
   with no traceable backing — the LLM said it found something, and
   that's the end of the audit trail. **Resolution:** every finding
   carries an `audit_id` that links to a specific MCP call in
   `audit.jsonl`. Findings without an `audit_id` are counted as
   hallucinations.

4. **The collection-coupling problem.** Early designs assumed
   Velociraptor as the only evidence collection layer. When a customer
   adopts Falcon Forensics or Tanium, the analysis engine should not
   need to change. **Resolution:** extracted a separate
   collector-adapter repo (stdlib-only Python) that normalises any
   input source into the same `evidence_root/` layout. The analysis
   engine doesn't care which collector produced the data.

---

## Accomplishments we're proud of

- **Single-developer end-to-end project** — autonomous agent + MCP
  server + SIFT adapter + collector adapter + benchmark suite + 10
  case studies + multilingual demo video (English / Korean / Japanese)
  shipped by one person in six weeks.
- **Zero third-party Python dependencies in the core MCP layer** —
  every native function is stdlib-only. Auditable in a single sitting.
- **MITRE ATT&CK coverage: 11 of 12 tactics** across the 67 native
  functions (Reconnaissance, Resource Development, Initial Access,
  Execution, Persistence, Privilege Escalation, Defense Evasion,
  Credential Access, Discovery, Lateral Movement, Collection, Command
  and Control, Exfiltration, Impact — Resource Development being the
  one tactic not in scope for a post-incident DFIR agent).
- **External-dataset honesty.** Layer 2 evaluation against three
  independent third-party datasets that the project's author did not
  create or have influence over. Numbers are what they are.

---

## What we learned

1. **Architecture wins over prompting.** A system prompt asking the
   LLM to "please don't execute arbitrary code" is a marketing claim.
   A wire protocol that doesn't expose `execute_code` is a guarantee.
2. **Self-correction is a measurable property.** It is not enough for
   an agent to *sometimes* retract wrong claims; the retraction itself
   needs to be a first-class auditable event with its own hash.
3. **The right unit of accuracy is per-finding, not per-case.** A
   single case can have 13 findings (case-07 ransomware) and the agent
   might get 10 right and 3 wrong. Reporting "case passed" or "case
   failed" hides that signal; reporting per-finding recall/precision
   exposes it.
4. **External benchmarks discipline internal claims.** As long as the
   only evidence is bundled with the project, "Recall 1.000" is just a
   number we wrote. Once the same agent runs against NIST CFReDS
   (which existed before this project did), the number means something.

---

## What's next for Agentic-DART

Post-submission roadmap, scheduled for after 2026-06-15:

- **Falcon Forensics input adapter** (v0.2 of collector-adapter). The
  agent already consumes Velociraptor and raw images; adding Falcon
  is one input-format module.
- **EZTools sidecar generation.** Auto-invoke PECmd / AmcacheParser /
  EvtxECmd / RECmd when their binaries are present on the local
  toolchain, merge parsed JSON into the manifest.
- **macOS + Linux artefact parity with Windows.** Unified log,
  KnowledgeC, FSEvents, auditd, journald, launchd — match the
  classification depth that the Windows surface currently has.
- **CI url-reachability check.** Detect dead external dataset URLs as
  drift, not as a benchmark failure.
- **Live benchmark run on user host.** The submission ships the
  benchmark infrastructure but the numerical results in
  `docs/benchmarks/SUMMARY.md` are produced from the maintainer's
  workstation rather than CI (the 13 GB external datasets are too
  large for a free runner). A separate machine in the post-submission
  period will host the rolling accuracy ledger.

---

## How to run Agentic-DART yourself

### Prerequisites

- SIFT Workstation (or any Linux/macOS with Python 3.10+)
- Anthropic API key (`ANTHROPIC_API_KEY` environment variable)
- ~16 GB disk space (only if running external benchmarks)

### Install

```bash
git clone https://github.com/Juwon1405/agentic-dart.git
cd agentic-dart
bash scripts/install.sh
```

The installer verifies Python, clones dependencies, probes the SIFT
toolchain, registers MCP adapters, and validates the bypass test pack.

### Run the bundled demo (~30 seconds)

```bash
bash examples/demo-run.sh
```

### Run the full benchmark suite

```bash
# Internal cases only (~10 seconds, no download)
python3 -m scripts.benchmark.run_all --layer 1

# Everything, auto-fetching external datasets (~30-60 min first time)
python3 -m scripts.benchmark.run_all --download
```

### Run against your own evidence

```bash
python3 -m dart_agent \
    --evidence-root /path/to/your/evidence_root \
    --playbook dart_playbook/senior-analyst-v3.yaml \
    --output ./out
```

---

## Submission artefacts checklist

- [x] Source code: https://github.com/Juwon1405/agentic-dart
- [x] License: MIT (`LICENSE` in repo root)
- [x] README with architecture overview and reproduction commands
- [x] Demo video (3 languages: English, Korean, Japanese — under `docs/demo_assets/output/`)
- [x] 11 documented case studies with machine-readable ground truth
- [x] Benchmark suite (`scripts/benchmark/`) covering internal + external evidence
- [x] Accuracy report (`docs/accuracy-report.md`)
- [x] Audit-chain verification utility (`dart_audit verify`)
- [x] Architectural guardrail test pack (`tests/bypass_tests/`)
- [x] Single-source-of-truth count discipline (no hardcoded drift)
- [x] CI green at submission (72 tests passing)
- [x] Companion collector-adapter repo: https://github.com/Juwon1405/agentic-dart-collector-adapter

---

**Contact:** open an issue on https://github.com/Juwon1405/agentic-dart/issues — issue templates are configured for `feature-request`, `bug`, `question`, and `dataset-suggestion`.
