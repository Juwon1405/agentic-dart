<p align="center">
  <img src="./agentic-dart-thumbnail.png" alt="Agentic-DART — Autonomous DFIR Agent" width="100%">
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://findevil.devpost.com/"><img src="https://img.shields.io/badge/SANS%20FIND%20EVIL%21-2026-dc2626.svg" alt="SANS FIND EVIL! 2026"></a>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-11%2F12%20tactics-4F46E5.svg" alt="MITRE ATT&CK 11/12">
  <img src="https://img.shields.io/badge/tests-17%2F17%20passing-22c55e.svg" alt="tests 17/17">
</p>

# Agentic-DART — Autonomous DFIR Agent on SANS SIFT Workstation

> *An autonomous DFIR agent that thinks like a senior analyst.*
> *Architecture-first, not prompt-first.*

**Submission to:** [SANS FIND EVIL! Hackathon 2026](https://findevil.devpost.com/)
**License:** MIT
**Status:** 🟢 MVP runs end-to-end; self-correction path validated. Active development through June 15, 2026.

---

## Table of contents

- [About the name](#about-the-name)
- [Development approach](#development-approach)
- [What Agentic-DART is (and what it is not)](#what-agentic-dart-is-and-what-it-is-not)
- [Why Agentic-DART exists](#why-agentic-dart-exists)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [**Quick start — prove it works in 30 seconds**](#quick-start--prove-it-works-in-30-seconds)
- [Running the tests](#running-the-tests)
- [Target case class](#target-case-class)
- [Judging-criteria alignment (SANS FIND EVIL!)](#judging-criteria-alignment-sans-find-evil)
- [Platform support](#platform-support)
- [Live mode (real Claude API + MCP stdio)](#live-mode-real-claude-api--mcp-stdio)
- [Case study for judges](#case-study-for-judges)
- [Measured accuracy (reproducible)](#measured-accuracy-reproducible)
- [Status — what is implemented vs. what is roadmap](#status--what-is-implemented-vs-what-is-roadmap)
- [License](#license)
- [Author](#author)

---

## About the name

**DART** = **D**etection **A**nd **R**esponse **T**eam.

**Agentic-DART** starts as an *agentic DFIR* assistant (the focus of this hackathon submission), but is named with deliberate room to grow:

- **Phase 1 (current)** &mdash; agentic DFIR: senior-analyst reasoning encoded as architecture across forensic artifacts.
- **Phase 2** &mdash; agentic detection engineering: detection-as-code generation, Sigma rule synthesis, coverage-gap reasoning.
- **Phase 3** &mdash; agentic SOC: triage, enrichment, and supervised response orchestration.
- **Phase 4** &mdash; broader agentic security workflows beyond traditional D&R boundaries.

The codename is intentionally generic so it remains accurate as the project's scope expands.

---

## Development approach

This project is developed by [Juwon Bang](https://github.com/Juwon1405) with extensive use of [Claude](https://www.anthropic.com/claude) (Anthropic's AI assistant) as a coding collaborator.

- **Human-driven**: architectural decisions, security model, threat coverage taxonomy, MITRE ATT&CK mapping, evidence-integrity invariants, and final code review.
- **AI-accelerated**: implementation, sample-evidence generation, test scaffolding, documentation drafting.
- **Validated**: every function is reviewed and exercised against the bundled sample evidence; the 17-test suite must pass on a clean clone before any commit lands on `main`.

This disclosure follows the spirit of the [SANS FIND EVIL!](https://findevil.devpost.com/) ethos and modern open-source practice: AI-assisted development is a tool, not a substitute for engineering judgement.

---


## What Agentic-DART is (and what it is not)

**Agentic-DART is:** an autonomous AI agent that sits on top of the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation) and the [Protocol SIFT](https://findevil.devpost.com/) framework, runs a senior-analyst-style reasoning loop with architectural evidence-integrity guarantees, and produces a courtroom-traceable report of its findings.

**Agentic-DART is not:** a replacement for Velociraptor, KAPE, Timesketch, Plaso, or any SIEM/EDR. Those are the layers underneath. See [`docs/comparison.md`](./docs/comparison.md) for the layer map and a side-by-side table.

**The single design principle:** evidence integrity is a property of the system's shape — what functions exist on the MCP server — not a rule the agent is asked to follow. The baseline [Protocol SIFT](https://findevil.devpost.com/) agent prompts the model to behave; Agentic-DART removes the ability to misbehave.

## Why Agentic-DART exists

Protocol SIFT proved that AI agents can operate the SIFT Workstation. It also hallucinates more than a DFIR practitioner can stand behind in a courtroom-grade report. Agentic-DART is an attempt to close that gap by encoding the *reasoning pattern of a senior analyst* as architecture — not as a prompt.

The name is a Japanese reading of **優心**, meaning "discerning mind."

## Architecture

![Agentic-DART Architecture](./dart-architecture.png)

1. **Custom MCP Server** (`dart_mcp`) is the primary enforcement layer. The agent has no `execute_shell()`. Destructive commands are not refused — they are *not present*.
2. **Direct Agent Extension on Claude Code** (`dart_agent`) handles session ergonomics. Security boundaries live in the server, not the prompt.
3. **Persistent Learning Loop** — every iteration writes hypothesis, confidence, and unresolved gaps to `progress.jsonl`. The next iteration must address those gaps or declare them unreachable.
4. **Tamper-evident audit chain** (`dart_audit`) — every MCP call is recorded in a SHA-256-chained JSONL file. Any rewrite fails verification.

Evidence is mounted **read-only at the OS level** before the agent is ever started. For the full design rationale, see [`docs/architecture.md`](./docs/architecture.md).

## Repository layout

```text
agentic-dart/
├── dart_audit/      # Tamper-evident JSONL logger with SHA-256 chain
├── dart_mcp/        # Custom MCP server: typed, read-only forensic functions
├── dart_agent/      # Iteration controller + self-correction loop
├── examples/
│   ├── sample-evidence/  # Reproducible test fixtures (triggers IP-KVM finding)
│   ├── demo-run.sh       # One-command demo — exactly what the video records
│   └── out/              # Generated on each run: audit.jsonl, progress.jsonl, report.json
├── tests/             # pytest-compatible; runs without network
├── docs/              # architecture.md, dataset.md, accuracy-report.md, troubleshooting.md
└── dart-architecture.png
```

## Quick start — prove it works in 30 seconds

```bash
git clone https://github.com/Juwon1405/agentic-dart.git
cd agentic-dart
bash examples/demo-run.sh
```

Expected output:

```
[dart-agent] iterations: 5
[dart-agent] findings: 2
[dart-agent] audit chain: chain verified: 3 entries, tail=1e995b6afc6a6660...
[demo] bypass test — attempting to call an unregistered destructive function:
[demo] PASS — "ToolNotFound: 'execute_shell' is not exposed by dart-mcp"
```

The demo walks the full senior-analyst loop against sample evidence, triggers a USB contradiction, **auto-self-corrects** by widening the time window, and writes a chain-verified audit log. The bypass test proves the `execute_shell` guardrail is architectural, not prompt-based.

### What a real run looks like

Below is a sample run on the SANS SIFT Workstation against a representative case. **Stage 1 — startup, MCP handshake, first hypothesis:**

<p align="center">
  <img src="./docs/screenshots/dart-run-01-init.png" alt="dart-agent startup and first hypothesis" width="92%">
</p>

**Stage 2 — typed tool calls, MITRE chain begins to form:**

<p align="center">
  <img src="./docs/screenshots/dart-run-02-investigate.png" alt="dart-agent calling typed forensic tools" width="92%">
</p>

**Stage 3 — contradiction detected, hypothesis refined automatically:**

<p align="center">
  <img src="./docs/screenshots/dart-run-03-contradiction.png" alt="dart-corr detecting an UNRESOLVED contradiction and the agent refining" width="92%">
</p>

This is the architecture-first claim made concrete: when artifacts disagree, `dart-corr` flags the contradiction as `UNRESOLVED` and the agent is forced to revise. No prompt instruction was needed — the contradiction surfaces from the data itself.

**Stage 4 — final verdict, MITRE ATT&CK chain verified, audit chain integrity confirmed:**

<p align="center">
  <img src="./docs/screenshots/dart-run-04-final.png" alt="dart-agent final verdict with verified audit chain" width="92%">
</p>

> *Sample run output — representative of an actual SIFT Workstation execution. A live screencast will replace these stills in the final hackathon submission video (June 2026).*

## Running the tests

```bash
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"
export DART_EVIDENCE_ROOT="$PWD/examples/sample-evidence"

python3 tests/test_audit_chain.py            #  3 — chain integrity + tamper detection
python3 tests/test_mcp_surface.py            #  3 — surface is the exact positive set
python3 tests/test_mcp_bypass.py             #  6 — destructive ops are blocked
python3 tests/test_agent_self_correction.py  #  1 — end-to-end self-correction
python3 tests/test_live_mcp.py               #  4 — JSON-RPC stdio wire tests
                                             # ──
                                             # 17 tests
```

All 17 pass on a clean checkout. The repo also contains
`tests/_pending/` — tests for Phase 2 functions not yet on the
MCP surface. Those are intentionally not part of the 17/17 count.

## Target case class

Insider-threat and DPRK IT-worker-style patterns:

- IP-KVM indicators and anomalous remote-access stacks
- USB timelines contradicting authentication telemetry
- Process-tree anomalies associated with remote-hands operations
- Living-off-the-land sequencing across MFT / Amcache / Prefetch / memory

The MVP demo case exercises the IP-KVM remote-hands pattern end-to-end.

## Judging-criteria alignment (SANS FIND EVIL!)

| Criterion | How Agentic-DART addresses it | Evidence |
|---|---|---|
| Autonomous Execution Quality | Hypothesis tracker + persistent learning loop + self-correction | `progress.jsonl` shows iteration 4 contradiction + auto-widened retry |
| IR Accuracy | Cross-artifact correlation; contradictions flagged, not smoothed | F-013 replaces F-001 hypothesis when USB contradicts logon |
| Breadth / Depth | Disk + USB + memory + MFT + Prefetch + browser + auth + scheduled tasks + Sigma — full breadth | `dart_mcp/__init__.py` exposes 35 typed functions |
| Constraint Implementation | **Architectural** — no `execute_shell` function exists in the registry | `test_mcp_surface.py::test_calling_unregistered_function_raises` |
| Audit Trail Quality | Every finding → `audit_id` → MCP call → command → raw output | `audit.jsonl` chain verifiable end-to-end |
| Usability / Documentation | One-command demo; typed schemas; YAML playbook | `examples/demo-run.sh` runs on any Python 3.10+ host |


## Platform support

Agentic-DART runs on **Linux**, **macOS**, and **Windows** as the host (Python 3.10+, no native dependencies). Evidence from any of those operating systems can be analyzed regardless of which OS the agent runs on.

### Supported analysis targets — explicit matrix

| Target OS | Coverage | Evidence types analyzed |
|---|:---:|---|
| **Windows** &nbsp;<sub>10 / 11 / Server 2016+</sub> | 🟢 Deep | Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, AmCache.hve), $MFT, Prefetch, ShellBags, ShimCache, EVTX (Security/System/Application/Sysmon), Scheduled Tasks, USBSTOR + setupapi.dev.log, Volume Shadow metadata |
| **macOS** &nbsp;<sub>11 Big Sur → 14 Sonoma</sub> | 🟢 Standard | UnifiedLog (`log show --style ndjson`), KnowledgeC.db (CoreDuet), FSEvents (fseventsd), LaunchAgent / LaunchDaemon plists, browser SQLite (Safari, Chrome, Firefox), Spotlight metadata, Quarantine xattrs |
| **Linux** &nbsp;<sub>RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 11+</sub> | 🟢 Standard | auditd (`/var/log/audit/audit.log`), systemd-journal (`journalctl -o json`), syslog (`auth.log` / `secure`), bash/zsh history, cron / systemd-units, web access logs (Apache / Nginx) |
| **Cross-platform** | 🟢 | Process trees, browser SQLite (Chrome / Firefox / Safari / Edge), Sigma rule matching against any pre-extracted event log, MITRE ATT&CK chain reasoning |

> **Note on host vs. target:** the agent reads forensic *output* the
> operator produces (CSV / JSON / SQLite / plist / NDJSON). It does not
> require live agent installation on the target host. This is what
> makes it work on disk images and offline triage.

### 35 typed forensic functions — by platform

The full surface is enumerated by `python3 -c "from dart_mcp import list_tools; [print(t['name']) for t in list_tools()]"`.

| Platform | Functions | Count |
|---|---|:---:|
| **Windows** | `get_amcache`, `parse_prefetch`, `parse_shimcache`, `parse_shellbags`, `extract_mft_timeline`, `list_scheduled_tasks`, `analyze_usb_history`, `analyze_event_logs`, `analyze_windows_logons`, `detect_lateral_movement`, `detect_brute_force_rdp`, `detect_persistence` | 12 |
| **Windows AD** | `analyze_kerberos_events` (4768 / 4769 / 4770 / 4771) | 1 |
| **macOS** | `parse_unified_log`, `parse_knowledgec`, `parse_fsevents`, `parse_launchd_plist` | 4 |
| **Linux** | `parse_auditd_log`, `parse_systemd_journal`, `analyze_unix_auth` | 3 |
| **Linux + macOS** | `parse_bash_history` (with attacker-pattern detection: T1059.004, T1098.004, T1070.003, T1105, T1548.001, etc.) | 1 |
| **Cross-platform** | `get_process_tree`, `parse_browser_history`, `analyze_downloads`, `correlate_download_to_execution`, `detect_exfiltration`, `detect_credential_access`, `detect_ransomware_behavior`, `detect_defense_evasion`, `detect_discovery`, `detect_privilege_escalation`, `analyze_web_access_log`, `detect_webshell`, `correlate_events`, `correlate_timeline` | 14 |
| **Total** | | **35** |

### How the surface was built — references and provenance

The 35 functions are not invented from scratch. Each one is grounded in a published reference. The full mapping with hyperlinks lives in the wiki ([MCP function catalog](https://github.com/Juwon1405/agentic-dart/wiki/MCP-function-catalog)). High-level sources:

| Domain | Primary references |
|---|---|
| **Windows artifacts** | SANS FOR500 (Windows Forensic Analysis), SANS FOR508 (Advanced IR & Threat Hunting), Microsoft official docs (EVTX schema, Sysmon, Amcache), Eric Zimmerman's tools (PECmd, AmcacheParser, ShellBags Explorer, MFTECmd) — naming and field semantics aligned for operator familiarity |
| **macOS artifacts** | SANS FOR518 (Mac & iOS Forensic Analysis), Apple Developer Library, Patrick Wardle's *The Art of Mac Malware* (vol. 1: persistence; vol. 2: detection), mac4n6.com, Sarah Edwards' KnowledgeC research |
| **Linux artifacts** | SANS FOR577 (Linux IR & Threat Hunting), Red Hat RHEL Security Guide ch.7 (auditd), `systemd.journal-fields(7)`, freedesktop.org Journal Export Format, Hal Pomeranz's Linux IR talks |
| **Cross-platform / TTPs** | MITRE ATT&CK Enterprise (every detection function is mapped to a tactic + technique), Sigma rules (community detection corpus), Florian Roth's signature-base, Atomic Red Team |
| **Architecture** | MITRE Cyber Resiliency Engineering Framework, Anthropic's Model Context Protocol spec, "Threat Hunting in the Real World" (NIST SP 800-150), the AuditChain pattern from RFC 6234 (SHA-256) + RFC 5246 (chained MAC) |

### MITRE ATT&CK coverage — 11 of 12 enterprise tactics

| # | Tactic | Covered by |
|:---:|---|---|
| TA0001 | Initial Access | `analyze_usb_history`, `analyze_web_access_log`, `detect_webshell` |
| TA0002 | Execution | `get_amcache`, `parse_prefetch`, `parse_shimcache`, `get_process_tree`, `parse_bash_history` |
| TA0003 | Persistence | `detect_persistence`, `list_scheduled_tasks`, `parse_launchd_plist`, `parse_systemd_journal` (units), `parse_bash_history` (cron, rc.local) |
| TA0004 | Privilege Escalation | `detect_privilege_escalation`, `parse_auditd_log` (setuid syscalls), `parse_bash_history` (chmod +s) |
| TA0005 | Defense Evasion | `detect_defense_evasion`, `extract_mft_timeline` ($SI/$FN timestomp), `parse_bash_history` (history clear) |
| TA0006 | Credential Access | `detect_credential_access`, `analyze_windows_logons`, `analyze_kerberos_events`, `analyze_unix_auth`, `detect_brute_force_rdp` |
| TA0007 | Discovery | `detect_discovery`, `parse_shellbags`, `parse_knowledgec` |
| TA0008 | Lateral Movement | `detect_lateral_movement` (PsExec / WMIExec / WinRM / SMB) |
| TA0009 | Collection | `parse_browser_history`, `analyze_downloads`, `parse_fsevents` |
| TA0010 | Exfiltration | `detect_exfiltration`, `correlate_download_to_execution` |
| **TA0011** | **Command and Control** | ⚠ **Partial** — process-side indicators only. Full PCAP-based C2 detection is **deferred to Phase 2** (honest scope) |
| TA0040 | Impact | `detect_ransomware_behavior` (mass-rename + shadow-copy delete + ransom notes) |

Coverage = **11 / 12** with one tactic explicitly partial. We do not claim 12/12 because doing so would require reading PCAPs end-to-end, which is a Phase-2 deliverable. See [`docs/accuracy-report.md`](./docs/accuracy-report.md) for the per-technique mapping that includes specific T-IDs.


## Live mode (real Claude API + MCP stdio)

Agentic-DART can run in `live` mode where Claude is the agent, connected to `dart-mcp` over real MCP stdio JSON-RPC:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m dart_agent --mode live --case my-case --out /tmp/out \
    --prompt "Investigate for IP-KVM insider pattern"
```

Or without an API key (scripted mock-Claude over real MCP plumbing):

```bash
python3 -m dart_agent --mode live --case test --out /tmp/out --dry-run
```

See [`docs/live-mode.md`](./docs/live-mode.md) for the architecture, the tool-use loop, and `tests/test_live_mcp.py` for end-to-end wire-level tests (no API key needed).

## Case study for judges

Two case studies are bundled:

1. **[Pass-the-Hash with timestomp pre-existence](./docs/case-pth-timestomp.md)** &mdash; the headline walkthrough. Watch the agent build a coherent partial MITRE chain, then have it broken by a `dart-corr` contradiction (timestomp before the credential event), then revise to a correct verdict. This is the architecture-first claim made concrete.

2. **[IP-KVM remote-hands insider](./examples/case-studies/case-01-ipkvm-insider/README.md)** &mdash; a step-by-step walkthrough of the bundled IP-KVM case showing what the agent does at each iteration, what `audit.jsonl` records, and how `dart-audit trace F-013` resolves a finding back to raw evidence in three clicks.

## Measured accuracy (reproducible)

```
Recall:                    1.000
False positive rate:       0.000
Hallucination count:       0
Evidence integrity:        preserved (8 files, all SHA-256 hashes match pre/post)
Self-correction observed:  true
```

Produced by `python3 scripts/measure_accuracy.py`. See [`docs/accuracy-report.md`](./docs/accuracy-report.md) for the full methodology, ground truth, honest limitations, and the measured bypass test table (6/6 passing).


## Status — what is implemented vs. what is roadmap

### Implemented end-to-end — 35 MCP functions, all callable from Claude Code live mode

**Windows artifacts**

| Function | What it does |
|---|---|
| `get_amcache` | Amcache.hve reader, paginated output |
| `extract_mft_timeline` | MFTECmd-CSV reader with `[start, end]` window |
| `parse_prefetch` | Native + PECmd-sidecar reader |
| `list_scheduled_tasks` | Evidence tree enumeration with per-file SHA-256 |
| `analyze_usb_history` | setupapi.dev.log parser + IP-KVM VID/PID signature detection |
| `parse_evtx` | EVTX event log reader (EvtxECmd CSV sidecar) with event_id + time window filters |

**Memory forensics**

| Function | What it does |
|---|---|
| `volatility_summary` | Volatility 3 sidecar reader — surfaces injected processes + candidate C2 IPs |

**macOS artifacts**

| Function | What it does |
|---|---|
| `parse_knowledgec` | KnowledgeC.db SQLite reader with Cocoa-epoch → ISO 8601 decoding |
| `parse_fsevents` | FSEvents CSV reader with flag filter (ItemCreated / ItemRenamed / …) |
| `parse_unified_log` | UnifiedLog `log show --style csv` reader with subsystem + process filters |

**Reasoning layer**

| Function | What it does |
|---|---|
| `correlate_events` | Python cross-artifact timeline join, contradiction flagging |
| `duckdb_timeline_correlate` | **Real DuckDB-backed cross-source join at scale** — accepts N named sources, joins on time proximity, returns paired events |
| `match_sigma_rules` | YAML Sigma matcher (`equals`, `contains`, `startswith` modifiers) |

**Infrastructure**

| Component | What it does |
|---|---|
| `dart_agent` (CLI) | Iteration controller, hypothesis tracker, self-correction loop, `--max-iterations` cap |
| `dart_audit` (CLI) | SHA-256-chained JSONL logger + `verify / lookup / trace / summary` subcommands |
| `dart_mcp.server` | **JSON-RPC 2.0 MCP stdio server** — `claude mcp add agentic-dart python3 -m dart_mcp.server` |
| `dart_playbook/senior-analyst-v1.yaml` | Sequencing rules for insider-threat / remote-hands class |

### Remaining roadmap (honest)

| Item | Target |
|---|---|
| Native EVTX binary parser (drop EvtxECmd CSV dependency) | W3 |
| Native Volatility 3 subprocess wiring (drop info.json sidecar) | W3 |
| Baseline Protocol SIFT agent head-to-head accuracy runs on 2 external datasets | W4 |
| Ali Hadi Challenge #1 + NIST CFReDS Hacking Case measured accuracy | W4–W5 |
| Multi-agent decomposition (Memory / Disk / Network / Synthesizer specialists) | Post-submission |
| TimeSketch export format | Post-submission |



## License

MIT — see [LICENSE](./LICENSE).

## Author

**Bang Juwon** &nbsp;·&nbsp; 방주원 &nbsp;·&nbsp; 優心 (ゆうしん)

DFIR practitioner & detection engineer based in Tokyo.

- 🐙 GitHub &nbsp; &mdash; &nbsp; [github.com/Juwon1405](https://github.com/Juwon1405)
- ✉️ Email &nbsp; &mdash; &nbsp; juwon1405.jp@doubles1405.com
- 🎯 Hackathon &nbsp; &mdash; &nbsp; [SANS FIND EVIL! 2026](https://findevil.devpost.com/)

This project is a **personal/independent submission**. Built outside any
employer relationship. All work, opinions, and code in this repository
are my own and do not represent the views of any organization I am
affiliated with.

