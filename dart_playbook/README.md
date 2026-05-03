# dart-playbook

YAML sequencing rules for the senior-analyst loop. Operator-tunable; lives outside the model prompt. The architectural-first guarantees apply equally to every playbook — forking cannot loosen the read-only MCP boundary, audit chain, or contradiction enforcement.

## Bundled playbooks

| Playbook | Lines | Phases | Case classes | Recommended for |
|---|---:|---:|---:|---|
| `senior-analyst-v1.yaml` | 133 | 4 | 3 | Quick demos, simple scenarios |
| `senior-analyst-v2.yaml` | 845 | 10 | 10 | Methodology baseline (Mandiant + Bianco + Diamond) |
| **`senior-analyst-v3.yaml`** ⭐ | **1135** | **10** | **10 + UC IDs** | **Default. Industrialized — adds ADS + MaGMa + TaHiTI + HMM** |

## senior-analyst-v3 — what v3 adds (industrialization release) ⭐

v3 is the **industrialization release**. v2 encoded a senior analyst's *reasoning*. v3 encodes a *mature SOC's operating model* around that reasoning. Four new framework blocks layer on top of v2:

### 1. Palantir ADS template ([github.com/palantir/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework))

Every detection now has a 9-section documentation contract:
1. **Goal** — one-sentence plaintext description
2. **Categorization** — MITRE ATT&CK tactic + technique
3. **Strategy abstract** — high-level detection logic
4. **Technical context** — data source, field, expected shape
5. **Blind spots and assumptions** — honest catalog of failure modes
6. **False positives** — known legitimate triggers + whitelist guidance
7. **Validation** — Atomic Red Team test ID or reproducible scenario
8. **Priority** — critical / high / medium / low (tied to MaGMa risk score)
9. **Response** — SOAR runbook reference or manual steps

This is what separates a hobby detection from one a $billion company runs in production.

### 2. MaGMa Use Case Framework (FI-ISAC NL, [Rob van Os](https://www.soc-cmm.com/))

Three-tier traceability with CMMI maturity scoring:
- **L1 — Business drivers** (4 entries): "Protect data integrity", "Detect ransomware before recovery denial", etc.
- **L2 — Attack patterns** (8 entries, MITRE-mapped): AP-001 through AP-008
- **L3 — Detection rules** (mapped to MCP functions): coverage matrix per L2

**CMMI 5-level maturity self-classification** per case run:
- L1 Initial (ad-hoc) → L2 Managed (documented) → L3 Defined (ADS-templated) → L4 Quantitatively Managed (FP/TP measured) → L5 Optimizing (TI-feedback-loop active)

v3 ships at **L3 Defined** by default. L4 is a Phase 2 target.

### 3. TaHiTI Threat Hunt Cycle (Rob van Os et al.)

When the deterministic playbook plateaus (`confidence < 0.6 AND iterations >= 8`), the agent shifts into structured hunt mode:
- **H1 Initiate** — document hypothesis, attach TI context
- **H2 Hunt** — execute targeted MCP calls, pivot through Pyramid of Pain
- **H3 Finalize** — emit findings + new ADS, OR document negative result, OR hand off

This is the missing piece between "automated investigation" and "automated hunting".

### 4. Bianco Hunting Maturity Model (HMM 0–4) — operationalized

Every run self-classifies its hunting maturity:
- **HMM0** Initial — no hunt
- **HMM1** Minimal — TI-driven (IOC-based)
- **HMM2** Procedural — published procedures (e.g. ThreatHunter-Playbook)
- **HMM3** Innovative — analyst-formed hypotheses ⭐ **v3 default**
- **HMM4** Leading — automated hypothesis generation (Phase 2 target)

### Reference corpus

39 published references organized into 5 categories. v3 adds 14 new references vs v2:

- **industrialization_frameworks_v3** (15) — Palantir ADS, MaGMa, TaHiTI, SOC-CMM, MITRE 11 Strategies, awesome-soc, awesome-incident-response, awesome-threat-detection, ThreatHunter-Playbook, Florian Roth Detection Engineering Cheat Sheet, *Crafting the InfoSec Playbook*, Atomic Red Team, Sigma schema
- **primary_methodology** (6) — Mandiant M-Trends 2026, Targeted Attack Lifecycle, Bianco Pyramid of Pain, Diamond Model, Lockheed Kill Chain, F3EAD
- **case_studies_2025** (4) — DFIR Report (Fog, BlackSuit, Lynx), CISA AA24-109A
- **vendor_research** (9) — Metcalf, Edwards, Wardle, Pomeranz, Zimmerman, Case, Roth, Rodriguez (OTRF), JPCERT/CC
- **standards** (5) — MITRE ATT&CK v16, NIST 800-61/86/150, Verizon DBIR

---



A comprehensive senior-analyst methodology synthesizing every authoritative source on modern DFIR practice:

**Methodology lineage**
- **Mandiant M-Trends 2026** — 500K hours of 2025 IR engagements; 14-day median dwell time, 22-second hand-off, 32% exploit + 11% vishing initial access, "recovery denial" ransomware trend
- **Mandiant Targeted Attack Lifecycle** — 8-phase model from Initial Recon to Complete Mission
- **SANS PICERL** — Preparation / Identification / Containment / Eradication / Recovery / Lessons learned
- **Lockheed Martin Cyber Kill Chain** — 7-phase intelligence-driven defense (Hutchins, Cloppert & Amin 2011)
- **David Bianco** — Pyramid of Pain (TTPs over IOCs) + Hunting Maturity Model + hypothesis-driven hunting
- **Diamond Model of Intrusion Analysis** — Caltagirone, Pendergast, Betz 2013 (adversary / capability / infrastructure / victim)
- **MITRE ATT&CK Enterprise v16** — 12 tactics, 200+ techniques mapped
- **F3EAD** — Find, Fix, Finish, Exploit, Analyze, Disseminate (originally U.S. military targeting; now standard DFIR practice)
- **NIST SP 800-61 / 800-86 / 800-150** — incident handling, forensic integration, threat intel sharing

**Case studies grounded in 2024–2026 frontline reports**
- The DFIR Report — BlackSuit, Akira, Fog, Lynx, BlueSky, RansomHub, MEOWBACKCONN
- CISA #StopRansomware advisories — Akira AA24-109A (Nov 2025)
- Verizon DBIR 2025/2026 — vulnerability exploitation +180%, third-party compromise 30% of breaches

**Field practitioners cited per technique**
- Sean Metcalf (adsecurity.org) — Active Directory attack detection, Kerberoasting/AS-REP roasting
- Sarah Edwards (mac4n6) — macOS forensic analysis, KnowledgeC, unified log
- Patrick Wardle (objective-see.org) — *The Art of Mac Malware* persistence catalog
- Hal Pomeranz — Linux IR workflows, auditd methodology
- Eric Zimmerman (ericzimmerman.github.io) — Windows artifact field semantics: "MFT is god. Everything else is a witness."
- Andrew Case (Volatility Foundation) — memory forensics
- Florian Roth (signature-base, SigmaHQ) — detection corpus
- JPCERT/CC — *Detecting Lateral Movement through Tracking Event Logs*

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
P9  Finding emission                     audit_id citation enforced by serializer
```

## What v2 encodes that v1 didn't

- **10 case classes** vs 3 — covers ransomware-recovery-denial, vishing-initial-access, exploit-initial-access, third-party-compromise, cloud-hybrid, division-of-labour-handoff
- **`posture` block** — M-Trends 2026 priors so the agent's first guess is grounded in 2025 frontline data, not generic textbook scenarios
- **`bianco_priority_targets`** — TTPs first, host artifacts second, IOCs last (the Pyramid of Pain made operational)
- **`senior_analyst_heuristic`** per phase — what experienced analysts actually do (e.g. "build timelines backwards from alert in 60-second windows, then 5-min, then 1-hour")
- **`anti_patterns`** per phase — what naive analysts do wrong (e.g. "rebooting 'to be safe' destroys all volatile evidence")
- **7 contradiction triggers** — including timestomp-predates-alert, vpn-kvm-overlap-violation, process-in-memory-no-evtx-creation, admin-privilege-no-escalation-path
- **`stop_condition: declare_complex_case_request_human`** — case revisions >=5 hands off to a human with the audit chain attached. Senior analysts know when not to commit.
- **Citations everywhere** — every numeric prior, every heuristic, every contradiction rule is grounded in a published source listed in `references:`

## Schema

See `senior-analyst-v2.yaml` for the canonical shape. Top-level keys:

```yaml
version: 2
name: senior-analyst-v2
target_case_classes: [...]
methodology_lineage: [...]

posture:                          # M-Trends priors
  dwell_time_assumption_days: 14
  initial_access_priors: [...]
  attacker_speed_assumption: {...}

sequence:                         # 10 phases, P0-P9
  - phase: P0_scope_and_volatility
    pyramid_layer: orientation
    rationale: |
      Memory disappears. ...
    mcp_calls: [...]
    anti_patterns: [...]
    senior_analyst_heuristic: |
      ...
    exit_criteria: {...}

next_call_decisions: [...]        # 25 state -> tool routing rules
contradiction_triggers: [...]     # 7 architectural contradictions
stop_conditions: [...]            # confidence >=0.92, max_iter, etc.
references:                       # 25 citations
  primary_methodology: [...]
  case_studies_2025: [...]
  vendor_research: [...]
  standards: [...]
operator_notes: |                 # 6 senior-analyst principles
  ...
```

## Forking for your case class

1. Copy `senior-analyst-v2.yaml` to `dart_playbook/<your-name>-v1.yaml`
2. Update `target_case_classes` to your scope
3. Tune `next_call_decisions` for your environment's priorities
4. Add environment-specific `contradiction_triggers`
5. Run with `python3 -m dart_agent --playbook dart_playbook/<your-name>-v1.yaml`

The architectural guarantees (read-only MCP boundary, audit chain, contradiction enforcement) apply to every playbook. **You cannot loosen them by forking.** A Skill or playbook that tries to call `execute_shell` still fails with `ToolNotFound` — because the function doesn't exist on the wire, regardless of what the playbook says.

## Six principles to remember (from `operator_notes`)

1. **Phase order is strict.** Memory disappears. Volatility before disk, always.
2. **Hypotheses are falsifiable.** Name a MITRE technique + data source + confirming indicator. "Something bad happened" is not a hypothesis.
3. **Contradictions are gold.** When two artifacts disagree, that's the most valuable signal in the case. Smoothing it over is malpractice.
4. **Recovery-denial check is mandatory** for any modern ransomware case. Endpoint encryption is the diversion, not the impact.
5. **Attribution is multi-vector.** Diamond Model with 4 corners or no attribution claim. Single-IOC attribution is what gets analysts fired.
6. **Findings cite audit_ids.** Always. The serializer refuses anything else — that's not a guideline, that's architecture.
