# dfir-playbook

`dfir-playbook` holds the agent's playbooks: YAML files that encode "what should a senior analyst look at next, given the current state of the case?" — sequencing rules that are operator-tunable and live outside the model prompt, without writing imperative Python. This page describes the three bundled playbooks, what v3 adds on top of v2, the methodology each phase is grounded in, the schema of `senior-analyst-v3.yaml`, what the runtime actually consumes from it, and how to fork one for your own case class. The architecture-first guarantees apply equally to every playbook — forking cannot loosen the read-only MCP boundary, the audit chain, or contradiction enforcement.

## Why YAML, not Python

The whole point of `architecture-first, not prompt-first` is that *operator-tunable* rules don't live in the model's prompt. They live in YAML the operator can read and edit.

A Python playbook would couple the rules to the agent's release cycle. A YAML playbook is data: an analyst can fork the playbook, tune for their specific case class (web-app breach vs insider threat vs ransomware), and commit it to their own runbook repo.

## Bundled playbooks

| Playbook | Lines | Phases | Case classes | Routing rules | Recommended for |
|---|---:|---:|---:|---:|---|
| `senior-analyst-v1.yaml` | 133 | 6 | 3 | — | Quick demos, simple scenarios, tutorials |
| `senior-analyst-v2.yaml` | 845 | 10 | 10 | 25 | Methodology baseline (Mandiant + Bianco + Diamond) |
| **`senior-analyst-v3.yaml`** | **1238** | **10** | **10** | **24** | **Default. Industrialized — adds ADS + MaGMa + TaHiTI + HMM** |

In v3 each `target_case_classes` entry is an object `{id, magma_l2}` that maps the case class to one of the MaGMa L2 attack patterns `AP-001`–`AP-008`; v2 lists bare ids. **v3 is the default for any new case.** v2 is retained as the methodology baseline (no v3 industrialization scaffolds) so pre-industrialization runs remain reproducible. v1 is kept for backward compatibility and tutorials; its six phases (`volatile_first`, `timeline_reconstruction`, `anomaly_surfacing`, `hypothesis_formation`, `cross_source_validation`, `structured_report`) target three case classes (`insider_threat_unauthorized_access`, `remote_hands_ip_kvm`, `living_off_the_land_execution`) and it carries `self_challenge`, `termination` and `evidence_integrity` blocks that later versions fold into `stop_conditions` and the MCP boundary. The deterministic agent's `progress.jsonl` snapshots use v1's phase names.

## senior-analyst-v3 — industrialization release (default)

v3 is the **industrialization release**. v2 encoded a senior analyst's *reasoning*. v3 encodes a *mature SOC's operating model* around that reasoning **as YAML data**, so it is inspectable, forkable, and citable. Four new framework blocks layer on top of v2.

> **Honest framing.** The four framework blocks below ship in v3 as **structured YAML data**. They define the contract a mature-SOC implementation should satisfy. Their **runtime activation** in `dfir_agent` and `dfir_corr` is deferred (written up in [issue #44](https://github.com/Juwon1405/agentic-dfir/issues/44), closed as not planned) — activating any of them at runtime would shift the baseline measured by `scripts/eval/self.py` and `scripts/eval/external.py`. What the agent executes today is described under [How the playbook gets executed](#how-the-playbook-gets-executed).

### 1. Palantir ADS template

[github.com/palantir/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework)

Encoded as `ads_template`. Every detection gets a 9-section documentation contract (`required_sections`):

1. **Goal** — one-sentence plaintext description
2. **Categorization** — MITRE ATT&CK tactic + technique (format-checked against `T\d{4}(\.\d{3})?`)
3. **Strategy abstract** — high-level detection logic
4. **Technical context** — data source, field, expected shape
5. **Blind spots and assumptions** — honest catalog of failure modes
6. **False positives** — known legitimate triggers + whitelist guidance
7. **Validation** — Atomic Red Team test ID or reproducible scenario
8. **Priority** — critical / high / medium / low (tied to the MaGMa risk score)
9. **Response** — SOAR runbook reference or manual steps

`lint_modes` are `permissive` → `warn` → `strict`; `current_default` is `warn`. The lint pass that enforces the contract on each finding is deferred. This is what separates a hobby detection from one a large enterprise runs in production.

### 2. MaGMa Use Case Framework

FI-ISAC NL · [Rob van Os (SOC-CMM author)](https://www.soc-cmm.com/) · [full paper](https://www.betaalvereniging.nl/wp-content/uploads/FI-ISAC-Use-Case-Framework-Full-Documentation.pdf)

Encoded as `magma_ucf`. Three-tier traceability:

- **L1 — business drivers** (`l1_business_drivers`, 4 entries) — "Protect data integrity", "Detect ransomware before recovery denial", etc.
- **L2 — attack patterns** (`l2_attack_patterns`, 8 entries, MITRE-mapped) — `AP-001` ransomware-recovery-denial through `AP-008` IP-KVM-physical-access
- **L3 — detection coverage** (`l3_detection_coverage`) — MCP function mapping per L2 pattern

**CMMI 5-level maturity scale** (`maturity_levels`): 1 Initial (ad-hoc) → 2 Managed (documented) → 3 Defined (ADS-templated) → 4 Quantitatively Managed (FP/TP measured) → 5 Optimizing (TI feedback loop active). `self_classification` declares **L3 Defined** as the current target, with the rule that L4 requires a measured false-positive rate and L5 an active TI feedback loop. Per-run runtime CMMI scoring is deferred; L4 is a Phase 2 target.

### 3. TaHiTI Threat Hunt Cycle

[Rob van Os et al.](https://www.first.org/events/colloquia/amsterdam2019/program)

Encoded as `hunt_cycle`, with the designed trigger `confidence < 0.6 AND iterations >= 8` (action `enter_hunt_mode`: the investigation has plateaued and deterministic sequencing isn't reaching a verdict) and three phases:

- **H1 Initiate** — document the hypothesis as a hunt artifact, attach TI context (M-Trends, DFIR Report, CISA, Sigma), state a falsifiable hunt hypothesis
- **H2 Hunt** — execute targeted MCP calls, pivot through the Pyramid of Pain (TTPs over IOCs), log every step in the audit chain
- **H3 Finalize** — emit findings + a new ADS, OR document the negative result, OR hand off

A sixth stop condition, `hunt_mode_active AND H3_finalize_complete → emit_with_hunt_findings`, closes the cycle. Runtime entry into hunt mode on plateau detection is deferred — the data scaffold defines what a TaHiTI-aware run *would* look like. This is the missing piece between "automated investigation" and "automated hunting".

### 4. Bianco Hunting Maturity Model

[David Bianco · sans.org](https://www.sans.org/tools/hunting-maturity-model)

Encoded as `hunting_maturity_model`. Five `levels`, each with its data-source expectation and hypothesis source:

- **HMM0** Initial — no hunt
- **HMM1** Minimal — TI-driven (IOC-based)
- **HMM2** Procedural — published procedures (e.g. ThreatHunter-Playbook)
- **HMM3** Innovative — analyst-formed, data-driven hypotheses — **v3's self-declared level**
- **HMM4** Leading — automated hypothesis generation (Phase 2 target)

`agentic_dfir_self_classification.current_level` is `HMM3_innovative`. Each v3 phase also carries an `hmm_level_required`. Per-run runtime self-classification by the agent is deferred.

### Reference corpus

42 published references organized into **6 categories** (`references:`). v3 adds **+17 net items vs v2's 25** (15 industrialization frameworks + 2 inspiration tools + 2 new vendor-research entries; v2's `primary_methodology` consolidated 8 → 6):

- **industrialization_frameworks_v3** (15, added in v3) — Palantir ADS (framework + blog), MaGMa, TaHiTI, SOC-CMM, Hunting Maturity Model, MITRE 11 Strategies of a World-Class SOC, [awesome-soc](https://github.com/cyb3rxp/awesome-soc) (cyb3rxp), [awesome-incident-response](https://github.com/meirwah/awesome-incident-response) (meirwah), [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection) (0x4D31), [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) (OTRF), Florian Roth's Detection Engineering Cheat Sheet, *Crafting the InfoSec Playbook* (Bollinger et al.), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Sigma rule schema](https://github.com/SigmaHQ/sigma)
- **related_tools_for_inspiration** (2, added in v3) — Hayabusa, EnableWindowsLogSettings (both [Yamato Security](https://github.com/YamatoSecurity), Tokyo) cited as third-party prior art*
- **primary_methodology** (6, consolidated from v2's 8) — Mandiant M-Trends 2026, Mandiant Targeted Attack Lifecycle, Bianco Pyramid of Pain, Diamond Model of Intrusion Analysis, *Intelligence-Driven Computer Network Defense* (Lockheed Martin kill chain), F3EAD
- **case_studies_2025** (4, carried from v2) — The DFIR Report: *Navigating Through The Fog*, *BlackSuit Ransomware*, *Lynx Ransomware (Cat's Got Your Files)*; CISA #StopRansomware Akira joint advisory AA24-109A
- **vendor_research** (10, +2 vs v2: Roberto Rodriguez of OTRF, Zach Mathis of Yamato Security*) — Sean Metcalf, Sarah Edwards, Patrick Wardle (*The Art of Mac Malware* vol. 1), Hal Pomeranz, Eric Zimmerman, Andrew Case, Florian Roth, Roberto Rodriguez, Zach Mathis, JPCERT/CC (*Detecting Lateral Movement through Tracking Event Logs*)
- **standards** (5, carried from v2) — MITRE ATT&CK Enterprise v16, NIST SP 800-61 / 800-86 / 800-150, Verizon DBIR 2025 + 2026

> *Yamato Security is an independent Tokyo-based DFIR group; Agentic-DFIR has no affiliation or partnership with them. Their tools are cited as external community references and field-calibration prior art only — no code or rules are imported.*

## Methodology lineage (inherited from v2, still authoritative in v3)

This section documents the **methodological foundation** that v2 first encoded and that v3 inherits unchanged. v3's industrialization scaffolds sit *on top of* this lineage. Operators forking v3 should read this section to understand *why* each phase, decision rule, and contradiction trigger is shaped the way it is.

v2 (created 2026-04-30, 845 lines) synthesizes every authoritative source on modern DFIR practice into a single executable playbook. It is, in effect, an audit-chained encoding of how a senior analyst with 10+ years of frontline IR experience would approach a case. `methodology_lineage` lists 7 entries in v2 (`mandiant_targeted_attack_lifecycle`, `lockheed_kill_chain`, `sans_picerl`, `mitre_attack_v16`, `bianco_pyramid_of_pain`, `diamond_model`, `f3ead`) and 13 in v3, which adds `palantir_ads_framework`, `magma_ucf`, `tahiti_threat_hunting`, `soc_cmm`, `bianco_hunting_maturity_model` and `mitre_11_strategies_world_class_soc`.

### Primary frameworks

- **Mandiant M-Trends 2026** — 500K hours of 2025 IR engagements; informs the `posture` block (14-day median dwell time, 22-second hand-off, 32% exploit / 11% vishing / 10% IAB initial-access priors, "recovery denial" ransomware trend)
- **Mandiant Targeted Attack Lifecycle** — 8-phase model from Initial Recon to Complete Mission
- **SANS PICERL** — Preparation / Identification / Containment / Eradication / Recovery / Lessons learned
- **Lockheed Martin Cyber Kill Chain** — Hutchins, Cloppert & Amin 2011, *Intelligence-Driven Computer Network Defense*; 7-phase intelligence-driven defense
- **David Bianco** — [Pyramid of Pain](https://www.sans.org/tools/the-pyramid-of-pain) (TTPs over IOCs) + [Hunting Maturity Model](https://www.sans.org/tools/hunting-maturity-model) + hypothesis-driven hunting
- **Diamond Model of Intrusion Analysis** — Caltagirone, Pendergast, Betz 2013 (adversary / capability / infrastructure / victim)
- **MITRE ATT&CK Enterprise v16** — 14 tactics (Reconnaissance through Impact), 200+ techniques mapped
- **F3EAD** — Find, Fix, Finish, Exploit, Analyze, Disseminate (originally U.S. military targeting; now standard DFIR practice)
- **NIST SP 800-61 / 800-86 / 800-150** — incident handling, forensic integration, threat intel sharing

### Case studies grounded in frontline reports (2024–2026)

- The DFIR Report — BlackSuit, Akira, Fog, Lynx, BlueSky, RansomHub, MEOWBACKCONN
- CISA #StopRansomware advisories — Akira AA24-109A (Nov 2025)
- Verizon DBIR 2025/2026 — vulnerability exploitation +180%, third-party compromise 30% of breaches

### Field practitioners cited per technique

- **Sean Metcalf** (adsecurity.org) — Active Directory attack detection, Kerberoasting / AS-REP roasting
- **Sarah Edwards** (mac4n6) — macOS forensic analysis, KnowledgeC, unified log
- **Patrick Wardle** (objective-see.org) — *The Art of Mac Malware* persistence catalog
- **Hal Pomeranz** — Linux IR workflows, auditd methodology
- **Eric Zimmerman** (ericzimmerman.github.io) — Windows artifact field semantics: "MFT is god. Everything else is a witness."
- **Andrew Case** (Volatility Foundation) — memory forensics
- **Florian Roth** (signature-base, SigmaHQ) — detection corpus, Sigma rules
- **JPCERT/CC** — *Detecting Lateral Movement through Tracking Event Logs*

## The 10 phases

```
P0  Volatility & scope                   memory, sockets, credential signals
P1  Initial access vector triage         exploit (32%) / vishing (11%) / IAB (10%)
P2  Timeline reconstruction              MFT + AmCache + Prefetch + auditd + journal
P3  Anomaly surfacing                    list anomalies WITHOUT explaining them
P4  Hypothesis formation                 falsifiable, MITRE-named, data-source-named
P5  Kill-chain assembly                  >=3 tactics, monotonic timestamps, audit_id
P6  Contradiction handling               UNRESOLVED -> revise hypothesis (architecturally enforced)
P7  Attribution / Diamond Model          adversary / capability / infrastructure / victim
P8  Recovery-denial check                identity / virtualization / backup (M-Trends 2026 #1 trend)
P9  Finding emission                     every finding carries the audit_ids of its MCP calls
```

Each phase in `sequence` has:

- **`rationale`** — why this order. Cited to source.
- **`pyramid_layer`** — where it sits in Bianco's Pyramid (foundation / middle / top / orientation / deliverable)
- **`mcp_calls`** — which `dfir-mcp` functions to invoke
- **`anti_patterns`** — what naive analysts do wrong
- **`exit_criteria`** — when the phase is closed
- **`hmm_level_required`** (v3) — the hunting-maturity level the phase presumes

Some phases carry a phase-specific block on top of these keys. P1 carries `bianco_priority_targets` in both v2 and v3; P2 carries `senior_analyst_heuristic` in v2 only (v3 drops it); P3 carries `surfacing_rules` (and P8 does too in v2); P4 `hypothesis_template`; P5 `chain_validation_rules`; P6 `contradiction_heuristics` (`contradiction_heuristics_v3_enhanced` in v3); P7 `diamond_model_required_fields`; P9 `finding_schema`.

## What v2 encodes that v1 didn't

- **10 case classes** vs 3 — adds `ransomware_response_recovery_denial`, `identity_centric_intrusion`, `vishing_initial_access`, `exploit_initial_access`, `third_party_compromise`, `cloud_hybrid_lateral_movement`, `division_of_labour_handoff`
- **`posture` block** — M-Trends 2026 priors (`dwell_time_assumption_days: 14`, `initial_access_priors`, `attacker_speed_assumption`) so the agent's first guess is grounded in 2025 frontline data, not generic textbook scenarios
- **`bianco_priority_targets`** (on the initial-access triage phase, P1) — `ttps`, then `tools`, then `host_artifacts`; IOCs last (the Pyramid of Pain made operational)
- **`senior_analyst_heuristic`** (on the timeline phase) — what experienced analysts actually do (e.g. "build timelines backwards from alert in 60-second windows, then 5-min, then 1-hour")
- **`anti_patterns`** per phase — what naive analysts do wrong (e.g. "rebooting 'to be safe' destroys all volatile evidence")
- **7 contradiction triggers** — `timestomp_predates_alert`, `vpn_kvm_session_overlap_violation`, `process_in_memory_no_evtx_creation`, `admin_privilege_no_escalation_path`, `ssh_auth_success_no_keys_no_password_log`, `launchd_user_writable_runatload`, `ransomware_without_recovery_denial_evidence`
- **`stop_condition: declare_complex_case_request_human`** — `hypothesis_revision_count >= 5` hands off to a human with the audit chain attached. Senior analysts know when not to commit.
- **Citations everywhere** — every numeric prior, every heuristic, every contradiction rule is grounded in a published source listed in `references:`

## Anatomy of `senior-analyst-v3.yaml`

`senior-analyst-v3.yaml` is the canonical and default playbook. Below is its top-level shape — the v2 carry-over keys (`target_case_classes`, `posture`, `sequence`, `next_call_decisions`, `contradiction_triggers`, `stop_conditions`, `references`, `operator_notes`) plus four new top-level keys for the v3 industrialization frameworks and a `classification_guidance` block. Counts are read from the file in the current tree.

```yaml
version: 3
name: senior-analyst-v3
created: 2026-05-01
supersedes: senior-analyst-v2

methodology_lineage:               # 13 cumulative citations (v2's 7 + 6 added in v3)
  - mandiant_targeted_attack_lifecycle
  - lockheed_kill_chain
  - sans_picerl
  - mitre_attack_v16
  - bianco_pyramid_of_pain
  - diamond_model
  - f3ead
  # v3 additions:
  - palantir_ads_framework
  - magma_ucf
  - tahiti_threat_hunting
  - soc_cmm
  - bianco_hunting_maturity_model
  - mitre_11_strategies_world_class_soc

# === v3 industrialization additions (4 framework blocks) ===

ads_template:                      # Palantir 9-section detection contract
  required_sections: [goal, categorization, strategy_abstract,
                      technical_context, blind_spots_and_assumptions,
                      false_positives, validation, priority, response]
  lint_modes: [permissive, warn, strict]
  current_default: warn

magma_ucf:                         # FI-ISAC NL three-tier UCF
  l1_business_drivers: [...]       # 4
  l2_attack_patterns: [...]        # 8, AP-001 .. AP-008
  l3_detection_coverage: {...}
  maturity_levels: {...}           # CMMI 1_initial .. 5_optimizing
  self_classification: {...}       # rule_for_case_class, current_target: 3

hunt_cycle:                        # TaHiTI H1 / H2 / H3
  trigger:
    condition: "confidence < 0.6 AND iterations >= 8"
    action: enter_hunt_mode
  phases: [H1_initiate, H2_hunt, H3_finalize]

hunting_maturity_model:            # Bianco HMM 0-4
  levels: {HMM0_initial, HMM1_minimal, HMM2_procedural,
           HMM3_innovative, HMM4_leading}
  agentic_dfir_self_classification:
    current_level: HMM3_innovative

# === v2 carry-over ===

target_case_classes: [...]         # 10 case classes (insider, remote-hands,
                                   #   LotL, ransomware, identity, vishing,
                                   #   exploit, third-party, cloud-hybrid,
                                   #   division-of-labour)

posture:                           # M-Trends priors
  dwell_time_assumption_days: 14
  initial_access_priors: [...]
  attacker_speed_assumption: {...}

classification_guidance:           # technique-mapping rules the live prompt carries
  initial_access: [...]            # (added with v1.1.0: IP-KVM, scheduled-task,
  persistence: [...]               #  Kerberos recognition)
  credential_access: [...]

sequence:                          # 10 phases, P0-P9
  - phase: P0_scope_and_volatility
    pyramid_layer: orientation
    hmm_level_required: ...
    rationale: |
      Memory and network state evaporate on reboot. ...
    mcp_calls: [get_process_tree, detect_credential_access]
    anti_patterns:
      - "Pulling the disk image before snapshotting memory"
      - "Rebooting 'to be safe' - destroys all volatile evidence"
      - "Running antivirus scan as first action - may quarantine evidence"
    exit_criteria:
      process_tree_captured: true
      credential_access_signals_logged: true
  # ... (P1-P9, see file for full)

next_call_decisions: [...]         # 24 state -> tool routing rules
  # - when_state: "no MFT timeline yet"
  #   call: extract_mft_timeline
  #   confidence_gain: 0.20
  #   rationale: "MFT is foundational - Eric Zimmerman: 'MFT is god'"

contradiction_triggers: [...]      # 7 architectural contradictions
  # - id: timestomp_predates_alert
  #   rule: "If $SI < $FN AND mismatch_ts < alert_ts, persistence pre-existed"
  #   severity: critical
  #   mitre: T1070.006

stop_conditions:                   # 6 termination conditions
  - condition: confidence >= 0.92
    action: emit_findings
  - condition: iterations >= 30
    action: emit_with_warning_low_confidence
  - condition: all_phases_closed AND no_unresolved_contradictions
    action: emit_findings
  - condition: unresolved_contradictions > 0 AND iterations >= 25
    action: emit_with_unresolved_section
  - condition: hypothesis_revision_count >= 5
    action: declare_complex_case_request_human
    note: |
      A case that has revised the hypothesis 5+ times is beyond what
      automated reasoning should commit to. Hand off to a human
      analyst with the audit chain attached.
  - condition: hunt_mode_active AND H3_finalize_complete      # v3
    action: emit_with_hunt_findings

references: {...}                  # 6 categorized reference groups, 42 entries
operator_notes: |                  # senior-analyst principles + forking rule
  ...
```

## How the playbook gets executed

The designed execution model, phase by phase: determine the current phase from what has been done; read `next_call_decisions` to pick the next MCP call; invoke it through `dfir-mcp` (bounded by the architecture-first surface); log the result to the audit chain (`dfir-audit`); run `dfir-corr` to surface contradictions; if a contradiction matches a `contradiction_trigger`, revise the hypothesis; check `stop_conditions` to decide whether to emit findings.

What the runtime consumes from the YAML in the current tree:

- **Live mode** (`dfir_agent/src/dfir_agent/live.py`) loads the highest-sorting `dfir_playbook/senior-analyst-v*.yaml` at import time and renders `sequence` into the system prompt — each phase's name, the first sentence of its `rationale` and up to six of its `mcp_calls` — followed by the two cross-cutting rules (competing hypotheses and cross-validation; every finding cites a tool call) and the `classification_guidance` rules. Claude chooses the next call within that guidance; every call still goes through the typed `dfir-mcp` surface, and the iteration ceiling is the CLI's `--max-iterations`.
- **Deterministic mode** does not read the YAML at all. `DeterministicAnalyst` scripts four phases in code — timeline, hypothesis, cross-source validation (where a contradiction forces a re-run and a replaced hypothesis), finalize — using v1's phase names in `progress.jsonl`.
- `next_call_decisions`, `contradiction_triggers`, `stop_conditions` and the four v3 framework blocks are not read by any code path today. They document the intended routing, contradiction and termination contract; contradiction handling and the hard iteration cap are enforced by the agent code and the MCP boundary rather than by evaluating these keys. Editing `sequence` changes live-mode behaviour; editing the other keys does not, until the activation tracked in issue #44 lands.

## Forking for your case class

1. Copy `senior-analyst-v3.yaml` to `dfir_playbook/<your-name>-v1.yaml`
2. Update `target_case_classes` to your scope (with your MaGMa L2 mappings)
3. Tune `next_call_decisions` for your environment's priorities
4. Add environment-specific `contradiction_triggers`
5. Optionally adjust `ads_template`, `magma_ucf`, and `hunt_cycle` for your SOC's maturity profile, and add ADS templates for your custom detections
6. Make the live controller pick it up. There is no `--playbook` flag in the current CLI (the `operator_notes` in both YAML files still mention one); the live controller loads `sorted(dfir_playbook.glob("senior-analyst-v*.yaml"))[-1]`, so a fork is used only if its filename matches that pattern and sorts after `senior-analyst-v3.yaml` — or if it replaces the shipped file in your checkout.

The agent will follow your sequencing while the architectural guarantees (read-only MCP boundary, audit chain, contradiction enforcement) are unchanged. **You cannot loosen them by forking.** A playbook can only choose *what* to call from the surface, never *expand* the surface: a playbook that tries to call `execute_shell` still fails with `ToolNotFound` — because the function doesn't exist on the wire, regardless of what the playbook says.

## Files

```
dfir_playbook/
├── README.md
├── senior-analyst-v1.yaml      # 133 lines, 6 phases, 3 case classes (legacy; its volatile-first phase calls the SIFT Volatility 3 adapters)
├── senior-analyst-v2.yaml      # 845 lines, 10 phases (methodology baseline; retained for reproducibility)
└── senior-analyst-v3.yaml      # 1238 lines, 10 phases + 4 framework blocks (default)
```

`dfir_playbook` is YAML data, never imported as a Python package — there is no `src/` and nothing to install.

## Six principles every senior analyst remembers

(From `senior-analyst-v2.yaml::operator_notes`. v3's `operator_notes` describe the four framework additions and repeat the forking rule; the principles below are inherited unchanged.)

1. **Phase order is strict.** Memory disappears. Volatility before disk, always.
2. **Hypotheses are falsifiable.** "Something bad happened" is not a hypothesis. "T1003.001 LSASS dump via comsvcs.dll executed at 14:23:09 UTC" is.
3. **Contradictions are gold.** When two artifacts disagree, that's the most valuable signal in the case. Smoothing it over is malpractice.
4. **Recovery-denial check is mandatory** for any modern ransomware case (M-Trends 2026 #1 trend). Endpoint encryption is the diversion, not the impact.
5. **Attribution is multi-vector.** Diamond Model with 4 corners or no attribution claim. Single-IOC attribution is what gets analysts fired.
6. **Findings cite audit_ids.** Always. Every finding carries the audit_ids of the MCP calls that produced it, and `python3 -m dfir_audit trace <audit.jsonl> <finding-id>` walks the chain back to every entry that produced it — that's not a guideline, that's architecture.

## See also

- [dfir-agent](../dfir_agent/README.md) — how the playbook reaches the model
- [Architecture](../docs/architecture.md)
- [Case study: Pass-the-Hash with timestomp](../docs/case-pth-timestomp.md) — worked example showing the 10 phases in action
- [`senior-analyst-v3.yaml`](./senior-analyst-v3.yaml) — the default playbook
- [`senior-analyst-v2.yaml`](./senior-analyst-v2.yaml) — methodology baseline (retained)
- [Roadmap](../docs/roadmap.md) — runtime activation of the v3 blocks
