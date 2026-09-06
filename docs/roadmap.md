# Roadmap

This page is the honest version of "where is Agentic-DFIR going". It is
structured as four phases. Phase 1 is the shipped release line and is
documented here in operator's-eye detail: what shipped, in which versions, what
is still open, and what was deferred by design. Phases 2–4 are not promises;
they are the directions the architecture was built to support. The page also
lists the companion repositories, what is explicitly *not* on the roadmap, and
how to influence it.

Later phases build on the same read-only, audit-chained core.

## At a glance

| Phase | Focus | Status | Window |
|:---:|---|:---:|:---:|
| **[Phase 1](#phase-1--agentic-dfir)** | Agentic DFIR — investigate one case end-to-end | **Shipped** | v1.x / v2.x |
| [Phase 2](#phase-2--agentic-detection-engineering) | Agentic detection engineering — Sigma synthesis, coverage-gap reasoning | Spec phase | ~Q3 2026 (estimate) |
| [Phase 3](#phase-3--agentic-soc) | Agentic SOC — supervised triage + response orchestration | Design only | ~Q1 2027 (estimate) |
| [Phase 4](#phase-4--broader-agentic-security) | Broader agentic security — vuln management, compliance, adversary emulation | Direction only | 2027+ (estimate) |

The quarter windows are estimates, not commitments.

**Phase 1 is the shipped release line.** Every architectural guarantee made in
Phase 1 (read-only MCP boundary, audit chain, contradiction enforcement, path
safety) propagates unchanged into later phases. Forking the playbook cannot
loosen them.

---

## Phase 1 — Agentic DFIR

Phase 1 is the shipped release line — the v1.x and v2.x versions. It is
*architecturally* complete and *empirically* validated against three public
DFIR datasets. Phase 1 is the foundation everything else builds on — every
architectural guarantee made here propagates unchanged into Phase 2, 3, and 4.

### In one sentence

> Phase 1 is the **agentic DFIR** layer — the autonomous reasoning loop that
> takes a single forensic case end-to-end with an architecturally enforced
> read-only boundary, an audit chain that survives reboot, and a contradiction
> handler that cannot be smoothed over.

### What "agentic DFIR" means in Phase 1

The agent investigates a single forensic case end-to-end. It loads the
senior-analyst playbook, walks the ten phases (volatility → initial access
triage → timeline → anomaly surfacing → hypothesis formation → kill chain
assembly → contradiction handling → attribution → recovery-denial check →
finding emission), and produces a courtroom-grade report where every claim
cites the audit ID of the MCP call that produced it.

Phase 1 is *offline-first*. The agent runs on mounted evidence, not live
hosts. Live response (`agentic SOC`) is explicitly Phase 3.

### The architectural guarantees (cannot be loosened by any future Phase)

Phase 1 is architecturally complete because these five guarantees hold in
code, not in prompt text:

- **The MCP boundary is real, not promised.** The 73-tool typed forensic
  function surface on the wire (48 native pure-Python + 25 SIFT adapters) is
  the whole available action space. Anything outside this surface
  (`execute_shell`, `write_file`, `mount`, `eval`) raises `ToolNotFound`
  regardless of what the prompt says. Asserted by a bypass suite that runs on
  every commit.
- **The audit chain is tamper-evident.** Every MCP call is hashed and chained
  with SHA-256; a tamper breaks the chain. 50 threads × 20 calls = 1000-entry
  chain verified concurrent-safe via `threading.Lock()` (v0.4.1 fix).
- **Path safety is fuzz-tested.** `_safe_resolve` rejects `../`, null bytes,
  absolute escapes, paths >1024 chars. Reuses Linux kernel's `realpath()`
  semantics.
- **Contradictions cannot be smoothed over.** `dfir-corr` flags `UNRESOLVED`
  when two artifacts disagree (e.g. MFT $SI < $FN by 11 seconds → timestomp
  pre-existed alert window). Unresolved contradictions are carried into
  `report.json` under `unresolved`; a finding cannot silently drop them.
- **Findings cite their evidence.** Every finding carries the `audit_id`s of
  the MCP calls that produced it, so any claim can be traced back to the
  logged call with `python3 -m dfir_audit trace <audit.jsonl> <finding_id>`.
  v3 additionally requires an [ADS template](../dfir_playbook/README.md).

These five guarantees are the load-bearing architecture for **all four
phases**. Phase 2 / 3 / 4 are *extensions*, not replacements.

### Phase 1 deliverables (Done)

#### Core architecture

- The typed forensic function surface (native + SIFT adapters) across
  **broad MITRE ATT&CK enterprise tactic coverage** (10 of 12 in-scope
  tactics; TA0009 Collection and full TA0011 C2 are Phase-2, though
  `detect_dns_tunneling` already adds DNS-tunneling C2 indicators)
  ([MCP function catalog](./mcp-function-catalog.md))
- Read-only MCP boundary, asserted by the bypass suite
  ([Architecture](./architecture.md))
- SHA-256 chained audit log, replayable, tamper-evident, lock-protected
  ([dfir-audit](../dfir_audit/README.md))
- Cross-artifact correlation engine with `UNRESOLVED` contradiction surfacing
  ([dfir-corr](../dfir_corr/README.md))
- Path sandbox (`_safe_resolve`) with fuzz-validated
  traversal/null-byte/escape protection ([Threat model](./threat-model.md))
- Live mode — real Claude API + JSON-RPC stdio MCP server
  ([Live mode](./live-mode.md))

#### Cross-platform coverage

| OS | Coverage |
|---|---|
| **Windows** | EVTX, MFT, AmCache, Prefetch, ShimCache, Shellbags, USB history, Registry, Scheduled Tasks, Kerberos events, Windows logons |
| **Linux** *(added v0.4 — 2026-04-30)* | auditd, systemd-journal, bash history, web access logs, Unix auth logs |
| **macOS** *(added v0.4 — 2026-04-30)* | unified log, launchd plists, bash history |
| **Memory + Network** | process tree, open sockets, credential signals |

Broad MITRE ATT&CK enterprise tactic coverage — **10 of the 12 in-scope
tactics** covered by scoped detection rules. `detect_dns_tunneling` (added in
v0.6.1) adds DNS-tunneling C2 indicators (Iodine/dnscat2 signatures plus
Shannon-entropy and per-domain volume heuristics), but full TA0011 (Command
and Control) and TA0009 (Collection) are the two tactics deferred to Phase 2
(full C2 needs end-to-end PCAP; Collection has parsers but no scoped detection
rule yet). The per-tactic table is in
[Platform support](./platform-support.md).

#### Methodology — three playbook versions, each layer adds discipline

| Playbook | Lines | Status |
|---|:---:|---|
| `senior-analyst-v1.yaml` | 133 | Quick-demo baseline |
| `senior-analyst-v2.yaml` (2026-04-30) | 845 | Methodology baseline (Mandiant + Bianco + Diamond + 25 references) |
| **`senior-analyst-v3.yaml`** (2026-05-01) | **1238** | **Default. Industrialization release** — adds Palantir ADS + MaGMa UCF + TaHiTI hunt cycle + Bianco HMM. 42 references. |

Line counts are read from the shipped files.

- **v2** synthesizes Mandiant M-Trends 2026, Targeted Attack Lifecycle, SANS
  PICERL, Lockheed Kill Chain, Bianco Pyramid of Pain + HMM, Diamond Model,
  MITRE ATT&CK v16, F3EAD, NIST SP 800-61/86/150, DFIR Report case studies,
  CISA #StopRansomware advisories, and field practice from Metcalf, Edwards,
  Wardle, Pomeranz, Zimmerman, Case, Roth, JPCERT/CC. 10 phases, 10 case
  classes, 25 references.
- **v3** adds four mature-SOC framework blocks **as YAML data scaffolds** on
  top of v2's runtime path: Palantir ADS Framework (9-section detection
  contract), MaGMa UCF (FI-ISAC NL three-tier traceability with CMMI 5-level
  maturity), TaHiTI threat hunt cycle (H1/H2/H3 with designed trigger), Bianco
  HMM (v3 yaml self-declares HMM3 Innovative). Extensive reference list — adds
  awesome-soc, awesome-incident-response, awesome-threat-detection,
  ThreatHunter-Playbook, Atomic Red Team, Sigma schema, *Crafting the InfoSec
  Playbook*, plus external Yamato Security references (Hayabusa,
  EnableWindowsLogSettings) cited as third-party prior art only. **v3 is the
  default playbook.** Runtime activation of the four scaffolds in
  `dfir_agent` / `dfir_corr` is open work: the v3 keys `ads_template`,
  `magma_ucf`, `hunt_cycle` and `hunting_maturity_model` are data the agent
  reads, and v2's ten-phase sequence remains the runtime path.

See [dfir-playbook](../dfir_playbook/README.md) for the deep dive.

#### Validation

- The full pytest suite passes on a fresh clone with the documented
  dependencies installed (CI matrix: Python 3.10 – 3.13); run `pytest` for the
  current count
- Dedicated bypass tests assert `ToolNotFound` for forbidden operations
- The bundled demo (`bash examples/demo-run.sh`) runs deterministically with
  no API key in about 5 seconds
- Two reproducible case-study walkthroughs:
  - [Case: IP-KVM remote-hands compromise](./case-ip-kvm.md)
  - [Case: Pass-the-Hash with timestomp](./case-pth-timestomp.md)

#### Documentation

- The documentation set under `docs/` — concept pages, package READMEs, case
  studies, operator guide, threat model, FAQ, glossary
  ([index](./README.md))
- [The Memex Bet](./memex-bet.md) — frames Agentic-DFIR in the lineage from
  Vannevar Bush 1945 → Karpathy 2026 → Agentic-DFIR 2026
- [About the name](./about-the-name.md) — what the name says
- [Threat model](./threat-model.md) — what we defend against and what we
  explicitly do NOT defend against
- Bundled demo (`bash examples/demo-run.sh`) and sample run screenshots in
  [`docs/screenshots/`](./screenshots/)

### Implemented end-to-end — the full typed read-only MCP surface, all callable from Claude Code live mode

The 48 native functions ship in five modules of `dfir_mcp`. Each function's
purpose, inputs and output shape are in the
[MCP function catalog](./mcp-function-catalog.md); this table only records
where each group lives.

| Group | Module | Functions |
|---|---|---|
| Windows execution & user activity | `dfir_mcp/__init__.py` | `get_amcache`, `parse_prefetch`, `parse_shimcache`, `get_process_tree`, `analyze_usb_history`, `parse_shellbags`, `extract_mft_timeline` |
| Windows system state & event analysis | `dfir_mcp/__init__.py` | `list_scheduled_tasks`, `detect_persistence`, `analyze_event_logs`, `parse_registry_hive` |
| Authentication, lateral movement, web/RDP attacks | `dfir_mcp/__init__.py` | `analyze_windows_logons`, `detect_lateral_movement`, `analyze_kerberos_events`, `analyze_unix_auth`, `detect_privilege_escalation`, `analyze_web_access_log`, `detect_webshell`, `detect_brute_force_rdp` |
| MITRE ATT&CK gap-fillers | `dfir_mcp/__init__.py` | `detect_credential_access`, `detect_ransomware_behavior`, `detect_defense_evasion`, `detect_discovery` |
| Browser, downloads, exfiltration | `dfir_mcp/__init__.py` | `parse_browser_history`, `analyze_downloads`, `correlate_download_to_execution`, `detect_exfiltration` |
| macOS artifacts (unified log, KnowledgeC, FSEvents) | `dfir_mcp/__init__.py` | `parse_unified_log`, `parse_knowledgec`, `parse_fsevents` |
| Linux text logs and shell history (v0.7.1) | `dfir_mcp/__init__.py` | `parse_linux_text_log`, `parse_linux_shell_history` |
| Cross-artifact reasoning | `dfir_mcp/__init__.py` | `correlate_events` (Python proximity join — USB ↔ logon, contradiction flagging), `correlate_timeline` (**DuckDB-backed cross-source join at scale** — N event sources, time-proximity join, KVM-precedes-logon pattern, hardened user-rule ON-clause) |
| Linux + macOS expansion (v0.4) | `dfir_mcp/_v04_expansion.py` | `parse_auditd_log`, `parse_systemd_journal`, `parse_bash_history`, `parse_launchd_plist` |
| Supply-chain IOC sweeps (v0.6.0) | `dfir_mcp/_v05_supply_chain.py` | `scan_pth_files_for_supply_chain_iocs`, `detect_pypi_typosquatting`, `detect_nodejs_install_hooks`, `detect_python_backdoor_persistence`, `detect_credential_file_access`, `grep_shell_history_for_c2` |
| macOS quarantine + Linux cron + DNS tunneling (v0.6.1) | `dfir_mcp/_v06_macos_linux.py` | `parse_macos_quarantine`, `parse_linux_cron_jobs`, `detect_dns_tunneling` |
| Sigma matcher (v1.1.0) | `dfir_mcp/_v07_sigma.py` | `match_sigma_rules` |

**SIFT Workstation adapters (25)** *(`dfir_mcp/sift_adapters/`)* — 12
Volatility 3, 9 Eric Zimmerman (MFTECmd / EvtxECmd / PECmd / RECmd /
AmcacheParser), 2 YARA, 2 Plaso. The per-adapter table is in
[SIFT adapter layer](./sift-adapter-layer.md). All 25 share the same
architectural guarantees as the native layer — read-only `EVIDENCE_ROOT`
inputs, persistent derived artifacts constrained to `DFIR_DERIVED_ROOT` when a
tool must write one (Plaso storage), subprocess timeout, SHA-256 of inputs and
outputs to the audit chain, typed `SiftToolNotFoundError` graceful fallback
when a binary is absent.

**Infrastructure**

| Component | What it does |
|---|---|
| `dfir_agent` (CLI) | Iteration controller, hypothesis tracker, self-correction loop, `--max-iterations` hard cap, `deterministic` and `live` modes |
| `dfir_audit` (CLI) | SHA-256-chained JSONL logger; `verify / lookup / trace / summary` subcommands; thread-safe under concurrent writers |
| `dfir_mcp.server_stdio` | **JSON-RPC 2.0 MCP stdio server** — `claude mcp add agentic-dfir -s user -- python3 -m dfir_mcp.server_stdio` |
| `dfir_playbook/senior-analyst-v3.yaml` | **Recommended** — ten-phase senior-analyst methodology with ADS + MaGMa + TaHiTI + HMM industrialization. v2 (methodology baseline) and v1 (quick demo) also bundled. |
| `dfir_corr/` (extracted package) | Standalone cross-artifact JOIN engine — DuckDB `:memory:`, 9-rule operator-tunable pack. Imports cleanly without `dfir_mcp`. The dfir_mcp wrappers delegate here for backwards-compat MCP wire surface. |

### Phase 1 rollout roadmap

The Agentic-DFIR Phase 1 deliverables are split across this repository and
the companion adapter:

| Step | Deliverable | Status |
|---|---|---|
| **1.0** | Analysis-PC cold workflow (read disk image → produce report) | Shipped in `dfir_agent` + `dfir_playbook` |
| **1.1** | LLM integration (Anthropic Claude via the direct API) | Shipped |
| **1.2** | Live host workflow scaffolding (SSH-driven `dfir_mcp` subprocess on remote) | Shipped |
| **1.3** | Velociraptor → `evidence_root` adapter — [agentic-dfir-collector-adapter](https://github.com/Juwon1405/agentic-dfir-collector-adapter) | **Shipped (current focus)** |
| **1.4** | `dfir-mcp` HTTP transport mode for multi-analyst central deployment | In progress |
| **1.5** | Mode selector matrix (cold / live / hybrid) baked into `dfir_agent` CLI | Next |
| **1.6** | Cross-replay verification (same case, two analysts, identical findings) | Next |
| **1.7** | Handover + analyst training pack | Next |

### Companion projects

The Agentic-DFIR ecosystem is intentionally small. Each repository owns one
job.

| Repo | Role | License |
|---|---|---|
| **[agentic-dfir](https://github.com/Juwon1405/agentic-dfir)** *(this repo)* | Autonomous DFIR analysis engine. Reads an `evidence_root/` and emits findings + audit chain. | MIT |
| **[agentic-dfir-collector-adapter](https://github.com/Juwon1405/agentic-dfir-collector-adapter)** | *Phase 1.3 — current.* Converts Velociraptor offline-collector ZIPs into the `evidence_root` layout this engine reads. Seeds the chain-of-custody (`manifest.json` + SHA-256 index). | MIT |
| **[yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector)** *(archived)* | Single-file bash collector for macOS hosts that cannot run Velociraptor. Supply-chain IOC patterns ported into `dfir_mcp._v05_supply_chain`. | MIT |

**Collection layer is intentionally not part of this repo.** Velociraptor
(Win / Linux / Mac, [docs](https://docs.velociraptor.app/)) is the recommended
collector; the adapter above handles the layout glue. The collect → adapt →
analyze workflow is in the [Operator guide](./operator-guide.md).

### Versions shipped during Phase 1

Dates follow [`CHANGELOG.md`](../CHANGELOG.md).

| Date | Version | Highlight |
|---|---|---|
| 2026-04-28 | v0.3 | Initial 31-function MCP surface |
| 2026-04-29 | v0.3.1 | dfir-corr correlation engine GA |
| 2026-04-30 | **v0.4** | Linux + macOS expansion → 35 native functions |
| 2026-04-30 | v0.4.1 | Audit chain race condition fix (`threading.Lock()`) |
| 2026-04-30 | **Playbook v2** (v0.4.2) | 845-line methodology release |
| 2026-05-01 | **Playbook v3** | Industrialization release — Palantir ADS + MaGMa + TaHiTI + HMM |
| 2026-05-01 | Playbook v3 patch | Yamato Security external references added to v3 (no separate v3.1 file; refs merged into `senior-analyst-v3.yaml`) |
| 2026-05-02 | **v0.5** | SIFT Workstation tool adapter layer → 60 functions (35 native + 25 SIFT) |
| 2026-05-03 | v0.5.1 | Evergreen visuals + full-surface QA pass (counts removed from PNG identity) |
| 2026-05-03 | **v0.5.2** | Defensive runtime guards + regression tests. `dfir_audit` JSON `default=str` consistency, `dfir_agent._report()` early-exit guard, `correlate_timeline` SQL-injection hardening |
| 2026-05-09 | v0.5.3 | Evidence variants + methodology disclosure — noise-injected realistic variant of the bundled evidence (same IOCs at ~1:30 benign ratios) |
| 2026-05-09 | **v0.5.4** | First external benchmark — NIST CFReDS Hacking Case integrated as case-08. `parse_registry_hive` shipped, recall 0.10/0.40 → 0.50/0.80 (strict/lenient) on 10 sampled findings |
| 2026-05-13 | **v0.6.0** | Supply-chain IOC sweep functions (litellm PyPI 2026-03, npm typosquat, preinstall hook abuse, credential file access) + agentic-dfir-collector-adapter |
| 2026-05-14 | **v0.6.1** | macOS QuarantineV2 (T1204 download provenance) + Linux cron enumeration with attacker-pattern flagging (T1053.003) + DNS tunneling detection (T1071.004/T1568.002/T1572) — opens TA0011 Command and Control |
| 2026-05-16 | **v0.7.0** | **case-11 supply-chain → ADCS ESC8 → DCSync → Golden Ticket** (12 findings; now `self-evaluation/case-08` after the v1.0.2 tiered layout) + every canonical evidence_root file enriched to native forensic-tool dump fidelity (EvtxECmd / Zeek conn.log / MFTECmd / PECmd / SBECmd / RECmd / Hindsight / systemd-journald / auditd / FSEventsParser / log show). 11 cases / 99 findings at that release |
| 2026-05-16 | **v0.7.1** | Linux DFIR triplet (`parse_linux_text_log` + `parse_linux_shell_history`; `parse_linux_cron_jobs` already in v0.6.1). case-09 ground-truth function-name reconciliation. 47 native + 25 SIFT = 72 typed MCP tools, 32 of 36 expected functions implemented (89% coverage) |
| 2026-06-05 | **v1.0.0** | First stable release — schema-validated MCP calls, measured case-01 baseline, full-suite QA. |
| 2026-06-10 | **v1.0.1** | Evidence isolation via `DFIR_DERIVED_ROOT`, schema-validation hardening, cross-platform overhaul. |
| 2026-06-11 | **v1.0.2** | The stable, efficient build — one-command `analyze.py` (live mode), self-contained tiered case studies (`self-evaluation/` + `external-evaluation/`, per-case `truth.json`), collector adapter `--source {zip,image}`. |
| 2026-06-15 | **v1.1.0** | External evaluation first-class (self + external in one run), **Sigma detection pack v1**, playbook technique classification (IP-KVM / scheduled-task / Kerberos), whole-disk image support (`tsk_recover` at partition offsets), append-only history ledger. |
| 2026-06-15 | **v1.2.0** | Sigma pack **v2 (11 rules)** — DCSync, Golden Ticket, ransomware shadow-copy deletion, web-shell creation, local account creation, Kerberoasting, AS-REP roasting, HID insertion, remote exec, event-log clearing — plus **model-aware authentication** (`dfir-auth`: Haiku → OAuth subscription, Sonnet/Opus → metered API), persistent install aliases (`dfir-pull`, `dfir-auth`), unified per-case ledger, case-02 ground-truth fix (Hadi #1 = Windows XAMPP; recall 0% → 60%). **73 typed MCP tools (48 native + 25 SIFT).** |
| 2026-09-05 | **v2.0.0** | Project renamed to **Agentic-DFIR**: packages `dfir_audit` / `dfir_mcp` / `dfir_agent` / `dfir_corr` / `dfir_playbook` / `dfir_sigma`, `DFIR_*` environment variables, `dfir-*` CLI aliases. Major bump because import paths changed. |

The bundled ground truth today is 11 cases (8 self-evaluation + 3
external-evaluation), 94 findings, 102 MITRE technique references, 66 unique
techniques — see [Dataset](./dataset.md). Counts quoted in the rows above are
what each release shipped at the time.

### Open Phase 1 items

| Item | Status | Reference |
|---|---|---|
| Accuracy measured on the three external datasets — NIST CFReDS, Ali Hadi #1, Digital Corpora M57 (three models) | Done 2026-06-15 | [`docs/benchmarks/SUMMARY.md`](./benchmarks/SUMMARY.md) |
| Accuracy report committed | Done | [Accuracy report](./accuracy-report.md) |
| Remaining NIST CFReDS parser gaps — IE6 / Outlook Express `index.dat`, Recycle Bin INFO2 / `$I`/`$R` metadata, a bundled YARA rule library (findings F-CFR-006 / 008 / 009) | Open work, Phase 2 | [Accuracy report](./accuracy-report.md) |

### Remaining roadmap (honest)

| Item | Status / target |
|---|---|
| Standalone `dfir_corr` cross-artifact JOIN engine (MFT ↔ memory process tree) | **Shipped in v0.7.1** — see [`dfir_corr/`](../dfir_corr/README.md) for the package and its unit tests |
| Sigma rule matcher (`match_sigma_rules`) | **Shipped in v1.1.0** — matches parsed events against the [`dfir_sigma/`](../dfir_sigma/README.md) pack (11 rules) |
| Native EVTX binary parser (drop EvtxECmd CSV sidecar requirement) | Phase 2 — currently `analyze_event_logs` consumes JSON exports; SIFT adapter `sift_evtxecmd_parse` covers the binary path |
| Remaining NIST CFReDS parser gaps (F-CFR-006 / 008 / 009) | Phase 2 — open work, see the table above |
| Multi-agent decomposition (Memory / Disk / Network / Synthesizer specialists) | Planned |
| TimeSketch export format | Planned |
| Cloud DFIR (CloudTrail / GuardDuty) | Phase 2 |

### What Phase 1 explicitly does NOT do (deferred by design)

These are intentional omissions, deferred by design — Phase 1 ships a tight,
defensible architecture rather than a sprawling feature surface.

| Capability | Phase | Why deferred |
|---|:---:|---|
| Live response (kill / quarantine / block) | **Phase 3** | No `kill_process`, no `quarantine`, no `block` — the agent reads evidence, never modifies it. Read-only Phase 1 cannot grow response without breaking the architectural guarantee. Response gets a *separate* armed MCP server with a *different* audit chain and human-in-the-loop confirmation. |
| Sigma rule synthesis from observed evidence | **Phase 2** | v3 cites Sigma schema and hayabusa-rules as prior art, but Agentic-DFIR does not yet *generate* Sigma rules from observed evidence. The `dfir-synth` package is scoped but unimplemented. |
| Cloud DFIR (CloudTrail / GuardDuty) | **Phase 2** | No CloudTrail, GuardDuty, or cloud-native log analysis. `analyze_aws_cloudtrail` is scoped, not implemented. |
| Native memory forensics beyond process tree + sockets | **Phase 2** | Plugin-level coverage today comes from the 12 `sift_vol3_*` adapters and needs Volatility 3 on the host; a native implementation is a separate engineering project. |
| Auto-execute YAML playbooks (no Python phase scaffold) | **Phase 2** | The v2/v3 YAML is *read* by the agent today; execution still goes through hardcoded Python phase scaffolds. |
| Enterprise multi-host orchestration | **Phase 3** | Phase 1 is single-host offline. Multi-host is a Phase 3 `dfir_responder` concern. |

---

## Phase 2 — Agentic detection engineering

Estimated window: ~Q3 2026. Extending the agent from "investigate one case" to
"improve the detection corpus from many cases".

> **Detailed design: [The self-learning loop](./self-learning-loop.md)** — Run
> → Reflect → Extract → Loop, in-context (not fine-tuned), gated by a
> recall-regression Git-rollback guard, with an always-on Haiku/OAuth cost
> model.

### Goals

- Read a corpus of historical incidents (audit logs from past runs) and
  surface coverage gaps
- Synthesize new Sigma rules from observed attacker behavior
- Quantify rule overlap, dead rules, and false-positive patterns
- Maintain a versioned detection-as-code repo separate from the agent codebase

### What changes architecturally

- **New package: `dfir_synth`** — Sigma rule synthesizer. Reads audit logs,
  emits `.yml`. Pure function: `(audit_log → rule_yaml)`.
- **No change to MCP boundary.** The synthesizer reads JSONL, not evidence.
  The boundary stays where it is.
- **New playbook: `coverage-gap-analyst-v1.yaml`** for the new reasoning
  class.

### What does **not** change

- The agent still cannot write to the evidence tree.
- The synthesizer's output is reviewed by a human before it lands in the
  production rule base. Agentic-DFIR does not auto-deploy rules.

### Measure of success

- Generate Sigma rules from 10+ historical cases
- ≥80% of generated rules pass review without modification
- Detection coverage gaps are surfaced *before* an analyst notices them in
  production

---

## Phase 3 — Agentic SOC

Estimated window: ~Q1 2027. Triage, enrichment, and **supervised** response
orchestration.

### Goals

- Ingest live SIEM alerts, route them to the right playbook
- Enrich with TI, asset context, recent case history
- Produce response drafts (containment, lateral-movement scoping, user
  notifications)
- Hand off to a human-in-the-loop for any action with side effects

### What changes architecturally

- **New package: `dfir_responder`** — proposes responses, does not execute
  them. Output is a structured action plan, not a script.
- **New boundary: response side effects.** A separate module owns the verbs
  that have effects (quarantine, isolate, kill-process, etc.). It is
  feature-flagged off by default. Enabling it requires per-environment
  configuration *and* a human approval step on every action.
- **New audit chain category: `proposed_action`** vs `taken_action`. Proposed
  actions are logged like findings. Taken actions require cryptographic
  approval from a human key.

### What does **not** change

- The DFIR boundary (Phase 1) stays as-is. SOC functions live in a different
  boundary.
- Human approval is **always** required for actions with side effects. The
  architecture refuses to be auto-deployed without a human-in-the-loop.

### Measure of success

- Mean time to triage drops by 50% on a representative SOC corpus
- Zero auto-executed actions without human approval (asserted by
  `test_responder_no_auto_execute`)
- Response plans match analyst plans on ≥70% of incidents

---

## Phase 4 — Broader agentic security

Estimated window: 2027 and beyond. Vague on purpose. The architecture is
designed to support directions we haven't picked yet:

- **Continuous detection-engineering loop** — Phase 2 + Phase 3 in a single
  closed feedback loop
- **Threat-hunting agent** — proactive hypothesis generation against cold
  storage
- **Code-review assistant for security infrastructure** — reads PRs to
  detection-as-code repos and flags rule regressions
- **Cross-environment correlation** — multi-tenant `dfir-corr` for
  organizations operating multiple SOCs

What's *constant* across Phase 4 directions:

- The architectural rules from Phase 1 still hold. Nothing has a
  general-purpose escape hatch. Every new verb is typed.
- Every action with side effects requires a human-in-the-loop.
- Every reasoning step is replayable from an audit chain.

---

## What's **not** on the roadmap

These have been considered and rejected for the foreseeable future:

### Auto-remediation without human approval

Even with high confidence, the architecture refuses to take actions with side
effects without a human approving each one. We will not ship this; if you need
it, fork and own the consequences.

### A general-purpose tool ("ask_anything")

The whole project is built on the premise that typed surfaces beat prompted
ones. A general-purpose tool would defeat that.

### Closed-source distribution

The architectural guarantees are only meaningful if the surface is auditable.
The project is MIT and will stay open source.

### Vendor-specific integrations as core packages

Splunk, Sentinel, XSOAR, etc. — these belong in *adapters*, not in the core.
We will document the adapter interface and keep core surface vendor-neutral.

---

## How to influence the roadmap

The roadmap is open to community input:

- **Issues tagged `roadmap`** — discuss direction
- **Issues tagged `phase-2`, `phase-3`, `phase-4`** — propose specific
  features for that phase
- **Pull requests with prototypes** — strong signal. A working prototype of a
  Phase 2 feature is worth more than 100 issues.

The contribution policy is in [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Anti-roadmap (what we will refuse)

To be explicit:

| Request | Response |
|---|---|
| "Can you add `execute_shell` for power users?" | No. |
| "Can the agent auto-terminate processes?" | Not without per-action human approval. |
| "Can we ship a binary blob that 'just works'?" | No. Architecture must be auditable. |
| "Can we make the prompt more permissive 'just for this case'?" | No. Guardrails are architectural. |

---

## See also

- [Architecture](./architecture.md) — why the design decisions in Phase 1 are
  load-bearing for Phases 2–4
- [Threat model](./threat-model.md) — what the boundary protects, what it
  doesn't
- [The self-learning loop](./self-learning-loop.md) — the Phase 2 design note
- [The Memex Bet](./memex-bet.md) — why this architecture
- [Running on SIFT](./running-on-sift.md) — how to run it
- [`CHANGELOG.md`](../CHANGELOG.md) — what has actually shipped
