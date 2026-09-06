# Accuracy report

How Agentic-DFIR measures detection accuracy, what holds regardless of the
score, and where the measured numbers live. The per-run scores are kept in one
place — the benchmark ledger under [`benchmarks/`](./benchmarks/README.md),
regenerated from runs rather than transcribed by hand — so this page explains
the metrics, the evidence they are measured on, the invariants the
architecture enforces on every run, the representative deterministic outputs
per case, and the limitations a reviewer needs to weight the headline numbers.

## The four metrics

| Metric | What it measures |
|---|---|
| **Recall** | share of ground-truth findings the agent surfaced |
| **False positive rate** | claims unsupported by the bundled evidence |
| **Hallucination count** | facts not present in the source artifacts at all |
| **Evidence integrity** | SHA-256 of every input file, before and after the run |

Every finding the agent emits carries the `audit_id`s of the MCP calls that
produced the supporting evidence, and any finding can be traced back to those
logged calls with `python3 -m dfir_audit trace <audit.jsonl> <finding_id>`. A
missing finding lowers recall; a claim that cannot be traced to a logged call
is what the hallucination count measures. The two metrics are independent.

## Where the numbers live

Benchmark scores are deliberately kept in **one** place — `docs/benchmarks/`,
regenerated from a live run rather than transcribed by hand. This page
documents *how* accuracy is measured and *what holds regardless of the score*.
For the measured recall across models and cases, read the ledger files:

- [`benchmarks/ledger.json`](./benchmarks/ledger.json) — the per-case,
  per-model record every table is rendered from
- [`benchmarks/SUMMARY.md`](./benchmarks/SUMMARY.md) — one row per case with
  the last-run timestamp, and the mean recall per model
- [`benchmarks/MODEL-COMPARISON.md`](./benchmarks/MODEL-COMPARISON.md) —
  per-case, per-model detail: recall, detected/scorable, raw findings count,
  tokens in and out
- [`benchmarks/HISTORY.md`](./benchmarks/HISTORY.md) — append-only
  run-over-run history
- [`benchmarks/README.md`](./benchmarks/README.md) — the reading of those
  numbers and the roadmap for raising recall and consistency

Recall varies by case difficulty and by model — that variation is the honest
signal. Pinning a single figure in prose would only invite it to drift out of
sync with the harness. Reproduce any published number locally:

```bash
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"
python3 -m scripts.eval.demo       # deterministic rig check, no API key
python3 -m scripts.eval.self       # live measurement, needs ANTHROPIC_API_KEY
python3 -m scripts.eval.external   # public datasets (downloads them first)
```

`scripts/eval/demo.py` is the fast pipeline sanity check — deterministic mode
on case-01, no key, instant. It is not where model quality is measured; that
is `scripts.eval.self` (the bundled cases) and `scripts.eval.external` (the
public images), both of which run the real model. If demo is green, any recall
difference in the live tiers is the model, not the toolchain. Per-case scoring
of a `findings.json` against a `truth.json` is `scripts/eval/score.py`, which
matches on MITRE ATT&CK technique overlap (a sub-technique matches its parent
and vice versa) over the tool-reachable subset of each case. The suite is
described in [`scripts/eval/README.md`](../scripts/eval/README.md).

## Measured accuracy (reproducible)

Three models, self-evaluation tier (8 planted cases) + external tier (3
third-party disk images). [`benchmarks/ledger.json`](./benchmarks/ledger.json)
is the record; the tier means below are the ones
[`benchmarks/SUMMARY.md`](./benchmarks/SUMMARY.md) renders from the full-matrix
run recorded last in [`benchmarks/HISTORY.md`](./benchmarks/HISTORY.md).

![Recall by model — self-evaluation vs external](./benchmarks/recall-by-model.png)

| Tier (cases) | claude-haiku-4-5 | claude-sonnet-4-6 | claude-opus-4-8 |
|---|---|---|---|
| self-evaluation (8) | 75.6% | 85.4% | **89.0%** |
| external-evaluation (3) | 3.7% | 43.3% | 35.0% |
| **combined (11)** | **56%** | **74%** | **74%** |

```
Hallucination count:   0   — every finding traces to a tool-call audit_id; low recall is missed coverage, never invention
Evidence integrity:    preserved — SHA-256 pre/post match on every input file
Self-correction:       observable in logs — hypothesis revision + parameter-adjusted re-run
```

Reproduce the full matrix with `python3 -m scripts.eval.self` and
`python3 -m scripts.eval.external`. External recall is low across **all**
models — this is tool/parser coverage on large third-party disk images, not
model reasoning (Sonnet and Opus both reach 80% on external case-02; Opus is
the most stable on the planted cases, with no zero-finding runs).

**False positives / missed / hallucination — kept distinct:**

- **Missed (recall).** The gaps above are *missed* artifacts. The external
  tier is low across **all** models — this is **tool/parser coverage** on
  large third-party disk images, not model reasoning.
- **Hallucination / ungrounded findings.** Every reported finding carries the
  `audit_id`s of the MCP calls that produced it, and each one can be traced
  back to the exact tool execution in the SHA-256 audit chain with
  `python3 -m dfir_audit trace <audit.jsonl> <finding-id>`. The hallucination
  count is the number of `audit_id` citations that resolve to no chain entry;
  it is 0 on every recorded run. On the canonical bundled case (case-01) the
  measured false-positive rate is **0**. When raw `findings` exceeds
  `scorable`, those are *additional grounded observations* outside the
  ground-truth list — each still tool-traced, not fabricated. Per-case
  findings-vs-scorable counts are in
  [`benchmarks/MODEL-COMPARISON.md`](./benchmarks/MODEL-COMPARISON.md).

### Model selection & determinism — what we learned

The three models diverge on complex DFIR reasoning in ways that are
operational, not cosmetic (measured with **no `--context` prompt** — raw
artifacts/disk image in, ground-truth recall out):

- **Sonnet 4-6 — most balanced on unseen (out-of-distribution) evidence.**
  Highest external recall (43.3% vs Opus 35.0%), at the cost of far more
  input tokens — roughly **2–5× Opus** on large disk images (external case-02:
  283,760 vs 64,297 input tokens). The "tries harder" model.
- **Opus 4-8 — efficient, strongest on self-class evidence.** Top
  self-evaluation recall (89.0%) and reaches tied combined recall at a
  fraction of the tokens. Best cost-per-finding on clean cases.
- **Haiku 4-5 — triage only.** Near-zero on external (3.7%); a cheap first
  pass, not authoritative analysis.

**Reproducibility matters for forensics.** Sonnet and Haiku accept the
`temperature` parameter — pinning `temperature=0` reduces run-to-run variance
and yields more consistent findings on identical evidence (it reduces, but
does not fully eliminate, non-determinism). **Opus 4-8 does not accept
`temperature`** (deprecated → HTTP 400), so it cannot be pinned to enforce
determinism; the agent detects the rejection on the first call and drops the
parameter for that model. (Note: an earlier "Opus 0%" artifact was this exact
API rejection failing the entire run — a bug, not model non-determinism — and
was fixed and re-measured to the numbers above. Diagnose call failures
separately from non-determinism.)

**Guidance.** For reproducibility and out-of-distribution evidence, prefer
**Sonnet** pinned to `temperature=0`. For self-class evidence and token
efficiency, **Opus** is equivalent (74% combined tie). Use **Haiku** for
low-cost triage and continuous background loops.

### Supply-chain + AD certificate-services attack chain (self-evaluation/case-08)

The supply-chain case —
[`examples/case-studies/self-evaluation/case-08/`](../examples/case-studies/self-evaluation/case-08/README.md)
— covers the attack class that defeated SolarWinds-era SOCs: a trojanized
signed vendor binary enters as a routine software update, then abuses an
**ADCS ESC8** misconfiguration (PetitPotam coercion → NTLM relay →
certificate for `DC01$` → PKINIT TGT → S4U2self DA impersonation → DCSync of
KRBTGT → Golden Ticket persistence). All 12 findings are reproduced
deterministically by seven MCP functions on bundled evidence — see the case
README for byte-stable expected output. The chain is composed entirely from
public references (CISA AA20-352A, SpecterOps "Certified Pre-Owned",
CVE-2021-36942, MITRE T1098.005 / T1003.006 / T1558.001) with no
cross-reference to any real environment.

### External-benchmark accuracy — NIST CFReDS Hacking Case (external-evaluation/case-01)

For a community-trusted, third-party benchmark, see
[`examples/case-studies/external-evaluation/case-01/`](../examples/case-studies/external-evaluation/case-01/README.md)
— the NIST CFReDS Hacking Case (Greg Schardt / "Mr. Evil", image MD5
`AEE4FCD9301C03B3B054623CA261959A`). Live recall is recorded per model in
[`benchmarks/ledger.json`](./benchmarks/ledger.json) (regenerated from runs,
never transcribed) and rendered in the `external-evaluation/case-01` section
of [`benchmarks/MODEL-COMPARISON.md`](./benchmarks/MODEL-COMPARISON.md).

Of the 10 sampled CFReDS findings, only 4 are reachable by the current
toolset; the rest need parsers still on the roadmap. Remaining gaps (F-CFR-006
IE6 index.dat, F-CFR-008 Recycle Bin, F-CFR-009 YARA bundling) are recorded in
issues [#53](https://github.com/Juwon1405/agentic-dfir/issues/53),
[#54](https://github.com/Juwon1405/agentic-dfir/issues/54) and
[#55](https://github.com/Juwon1405/agentic-dfir/issues/55) (closed as not
planned; the write-ups remain as reference). Low external
recall on a 2004 disk image is **missed coverage, never invention** — every
detected finding traces to a tool-call audit_id. This is the honest paradigm
gap between hand-built cases and a real third-party image, and
`parse_registry_hive` ([#52](https://github.com/Juwon1405/agentic-dfir/issues/52))
was the first Phase-2 primitive shipped to start closing it.

## Evidence — canonical bundled tree + CI fixture

Each self-evaluation case ships its own `evidence_root/` under
`examples/case-studies/self-evaluation/case-NN/`, holding only that
scenario's artifacts plus benign noise, so a clean recall falls out per case
without any prompt hint: the agent has to discover the incident from the
evidence itself. `truth.json` entries point at files inside the case's own
tree (`disk/…`, `linux/…`, `mac/…`, `web/…`).

| Tree | Path | Size | Purpose |
|---|---|---|---|
| **Bundled self-evaluation trees** | `examples/case-studies/self-evaluation/case-01/evidence_root/` … `case-08/evidence_root/` | Hand-curated; production volume where the scenario calls for it — case-05's Windows Security EventLog is 11,530 lines, case-06's web access log 1,027 lines (13 attack lines in it), case-03's unix auth log 517 lines; the IP-KVM tree (case-01) is a small setupapi/SYSTEM/Amcache/Tasks set | The scored evidence. Needle-in-haystack recall. Benign noise is committed as-is (deterministic, seeded); all other evidence is committed hand-curated. |
| **CI fixture** | `tests/fixtures/evidence/` | Minimal | What `tests/test_live_mcp.py` and the guardrail tests point `DFIR_EVIDENCE_ROOT` at |

`scripts/eval/demo.py` scores the case-01 tree on the two findings its
deterministic policy targets (F-001 unusual binary, F-013 IP-KVM insertion) —
recall=1.000, FPR=0.000, hallucination=0 — confirming that the detection
functions discriminate IOC from benign and don't simply match-anything in the
small-input case.

### Evidence schema fidelity (commit `de05118`, 2026-05-16)

Every evidence file in the bundled trees matches the on-disk schema produced
by the corresponding real forensic tool: **EvtxECmd-shaped EVTX records** with
full Channel/Computer/EventRecordID/SubjectUserSid/TargetLogonId/LogonGuid/
TicketOptions/ServiceSid fields, **Zeek conn.log-shaped network flows** with
ja3/ja3s/tls_version/http_method/user_agent, **MFTECmd-shaped $MFT.csv** with
both 0x10 SI and 0x30 FN timestamps, **PECmd-shaped Prefetch JSON**,
**SBECmd-shaped shellbags**, **RECmd-shaped runkeys/services/shimcache**,
**Hindsight-shaped Chrome History**, **systemd-journald-shaped
journal.ndjson** with `__REALTIME_TIMESTAMP`/`_BOOT_ID`/`_MACHINE_ID`/
`_AUDIT_LOGINUID`, **full auditd records**
(SYSCALL+EXECVE+CWD+PATH+PROCTITLE+USER_LOGIN+CRED_ACQ),
**FSEventsParser-shaped fsevents** with id/mask/flags/inode/sha256, and
**`log show`-shaped unified log** with thread/subsystem/category/sender.
Schema-level fidelity is byte-stable per re-run; the full pytest suite and all
per-case detection counts are preserved across the enrichment.

## Needle-in-a-haystack, not toy data

A fair reviewer asks: "recall on a 30-line file is meaningless — every line is
an IOC." Correct. The bundled trees are hand-curated at production volume
where the scenario calls for it — a Windows Security EventLog of 11,530 lines
in the authentication case, a 1,027-line web access log with 13 attack lines
in the web case, a 517-line unix auth log in the macOS case — and the
IOC-only logs are enriched with deterministic benign noise (committed as-is)
to a heavy signal-to-noise ratio. The measurement is not a small-input
over-fit; the agent finds the needle in production-scale hay. This is also
why there is no evidence-variant selector any more (removed in v1.0.1): the
harness always scores the one committed tree per case.

## What does not change — the invariants

Whichever case or model you run, these hold **by construction**, not by
tuning:

- **Every finding is traceable.** Every finding carries the `audit_id`s of
  the MCP calls that produced it, and `dfir_audit trace` follows a finding
  back to the exact logged calls. An invented fact therefore cannot hide
  behind the report — it shows up as a claim with no matching audit entry,
  which is what the hallucination count measures. A low recall means *missed
  coverage*; the two metrics are independent.
- **Evidence integrity is sealed.** SHA-256 of every input file is recorded
  before and after each run, and the audit trail is hash-linked into an
  unbroken chain.
- **The read-only boundary holds.** The MCP surface exposes only typed,
  read-only forensic functions — no shell, no eval, no write path. Evidence
  integrity rests on two **architectural** controls — a typed read-only MCP
  surface (destructive functions are *absent from the registry*, not merely
  forbidden in a prompt) and an OS-level read-only mount of
  `DFIR_EVIDENCE_ROOT`.

### Evidence-integrity & anti-spoliation test results

These are the **spoliation tests**: we actively tried to make the agent
modify, delete, or escape the evidence and recorded what the system does.
Every attempt below is refused by the architecture, so the outcome does not
depend on the model obeying an instruction. They run on every commit
(`tests/test_mcp_surface.py`, `tests/test_mcp_bypass.py`):

| # | Attack | Result |
|---|--------|--------|
| 1 | Call an unregistered destructive function (`execute_shell`) | `KeyError: ToolNotFound` |
| 2 | Call `eval`, `exec`, `system`, `network_egress`, `delete_file` | `ToolNotFound` for every name |
| 3 | Relative path traversal (`..`) | `PathTraversalAttempt` |
| 4 | Absolute path escape outside `DFIR_EVIDENCE_ROOT` | `PathTraversalAttempt` |
| 5 | NUL-byte smuggling | `PathTraversalAttempt` |
| 6 | Surface drift (positive and negative set) | Exact match against the 73 registered functions enforced |
| 7 | Malformed arguments | Rejected against the advertised JSON Schema before dispatch |
| 8 | SQL injection through `correlate_timeline` | Rejected |
| 9 | Handler writes outside evidence | Zero writes |

A random fuzz against destructive function names is blocked on every attempt —
the architecture-first guarantee, not a prompt instruction. See
[Architecture](./architecture.md) and the [threat model](./threat-model.md).

## Representative per-case walkthroughs

The tables below are the real outputs of the deterministic MCP calls on the
bundled evidence — the counts a reviewer can reproduce without a key. Model
recall per case is in the ledger, not here.

### Case 01 — IP-KVM remote-hands insider (Windows)

| Metric | Value |
|---|---|
| Recall | **1.000** |
| False positive rate | **0.000** |
| Hallucination count | **0** |
| Evidence integrity preserved | **true** (every file in the case-01 tree, SHA-256 pre/post match) |
| Self-correction observed | **true** |
| Audit chain length | 3 entries, SHA-256-linked |
| True positives | F-001, F-013 |

### Case 02 — LOTL PowerShell (Windows)

| MCP call | Real output on bundled evidence |
|---|---|
| `get_process_tree` | 10 processes, 3 LOTL flags (powershell→cmd×2, cmd→many×1) |
| `analyze_event_logs` | 5 events, 4 alerts (1 critical LSASS, 1 high PS-dl-exec) |
| `detect_persistence` | 6 mechanisms, 3 HIGH severity |
| `correlate_timeline` (DuckDB) | 3 cross-source + 1 kvm→logon |

### Case 03 — macOS remote-admin infection

| MCP call | Real output on bundled evidence |
|---|---|
| `parse_unified_log` | 8 events, 7 alerts (3 high, 4 medium) |
| `parse_knowledgec` | 9 activity events, Terminal top app (3 focus events) |
| `parse_fsevents` | 10 events, 5 suspicious-path hits (stage2.bin, exfil.zip, mimikatz-mac) |

### Case 04 — Phishing → Download → Execution → Exfiltration

Covers the infection-vector and data-loss halves of the attack chain,
which earlier case studies did not address.

| MCP call | Real output on bundled evidence |
|---|---|
| `parse_browser_history` | 7 visits, 3 flagged suspicious (.tk, raw IP, file-drop) |
| `analyze_downloads` (browser_db) | 3 downloads, 2 executables, 2 from suspicious URLs |
| `analyze_downloads` (zone_identifier) | 2 MOTW-tagged files, both ZoneId=3 (Internet) |
| `correlate_download_to_execution` | 1 critical chain: URL → file → execution in 390s |
| `detect_exfiltration` | 5 signals, max_severity=critical, 4 archive→upload chains |

#### Coverage map (what Agentic-DFIR can actually see)

```
        [infection vector]  [foothold]    [action on objectives]
             │                 │                   │
     ┌───────┴────────┐  ┌────┴────┐  ┌────────────┴────────────┐
     │ parse_browser_ │  │ get_    │  │ detect_exfiltration    │
     │ history        │  │ process_│  │ correlate_download_to_ │
     │ analyze_       │  │ tree    │  │   execution            │
     │ downloads      │  │ detect_ │  │ correlate_timeline     │
     │ (MOTW)         │  │persist. │  │                        │
     └────────────────┘  └─────────┘  └─────────────────────────┘
             │                 │                   │
             └──────── all joined by correlate_timeline ────────┘
```

No gap in the kill chain.

### Case 05 — Authentication + Lateral Movement

Closes the WHO dimension. Covers AD/Kerberos attack patterns, Windows
logon-type analysis, Unix SSH/sudo analysis, lateral-movement tool
detection (PsExec/WMIExec/WinRS), and cross-platform privilege
escalation.

| MCP call | Real output on bundled evidence |
|---|---|
| `analyze_windows_logons` | 16 events → 5 success + 4 fail + 2 explicit; 1 brute-force survivor (analyst@203.0.113.42 after 4 fails); 1 after-hours RDP at 02:17 |
| `detect_lateral_movement` | 2 remote-admin hits (psexec + wmiexec), 5 suspicious pairs, all HIGH |
| `analyze_kerberos_events` | **3 Kerberoasting** (RC4 TGS to MSSQL/Exchange/LDAP), **1 AS-REP Roast** (alice no-preauth) |
| `analyze_unix_auth` | 10-failure brute force from 203.0.113.42 (6 ssh_failure + 4 invalid_user) → 1 survivor (analyst publickey); 2 dangerous sudo commands (shadow read, curl-pipe attempt) |
| `detect_privilege_escalation` | 2 CRITICAL transitions: SSH → root in 85s and 100s |

#### Coverage map — full DFIR dimensions

```
WHAT executed      WHAT? HOW it got in   WHO authenticated   WHEN       OUTCOME
────────────       ─────────────────     ────────────────    ────       ───────
get_amcache        parse_browser_history analyze_windows_    extract_   detect_
parse_prefetch     analyze_downloads     logons              mft_       exfil
parse_shimcache    (+ MOTW)              detect_lateral_     timeline   tration
get_process_tree   correlate_download_   movement            parse_
parse_fsevents     to_execution          analyze_kerberos_   fsevents
                                         events              parse_
parse_shellbags                          analyze_unix_auth   unified_
list_scheduled_                          detect_privilege_   log
tasks                                    escalation
detect_persistence
analyze_event_logs
parse_unified_log
parse_knowledgec
```

All four DFIR dimensions (WHAT, HOW, WHO, WHEN) are covered across
Windows, macOS, and Linux.

### Case 06 — Web/WAS Attack + RDP Brute Force

Closes the initial-access-vector gap. Covers web application exploitation,
webshell detection with tuned precision, and RDP-specific brute-force
classification (credential stuffing vs password spray vs single-account).

| MCP call | Real output on bundled evidence |
|---|---|
| `analyze_web_access_log` | 1,027 lines examined, **13 attacks** across 5 rule classes (SQLi/LFI/SSRF/Log4Shell/RCE/webshell_upload), 19 scanner-UA hits, 1 scanning IP (198.51.100.77 at 65% error ratio) |
| `detect_webshell` | 12 files scanned, **3 HIGH findings with 0 false positives** (x.php/shell.php/cmd.php) |
| `detect_brute_force_rdp` | 15 RDP failures → 1 credential-stuffing IP (8 distinct users), 1 password-spray user (4 source IPs), **1 CRITICAL survivor** (analyst) |

#### Initial-access vector coverage

```
Path                            Agentic-DFIR function
───────────────────────────     ──────────────────────────────
Phishing email                  parse_browser_history + analyze_downloads
Web application attack          analyze_web_access_log  + detect_webshell
RDP brute force / cred-stuff    detect_brute_force_rdp
SSH brute force                 analyze_unix_auth
SMB/NTLM relay                  analyze_windows_logons (type 3)
Kerberos abuse                  analyze_kerberos_events
IP-KVM / insider physical       analyze_usb_history + correlate_events
```

### Case 07 — Full Ransomware Chain (MITRE Coverage)

Post-foothold activity: credential dumping, AD reconnaissance, defense
evasion, ransomware deployment. Based on DFIR Report 2025, Red Canary
2025, Mandiant M-Trends 2026 data on real-world intrusion tradecraft.

| MCP call | Real output on bundled evidence |
|---|---|
| `detect_credential_access` | **7 CRITICAL** (mimikatz + procdump + 3× reg save SAM/SECURITY/SYSTEM + ntdsutil NTDS.dit + rundll32 comsvcs MiniDump LOLBin) |
| `detect_discovery` | **11 hits across 9 MITRE sub-techniques**, 1 scripted-recon burst (11 commands in 60s) |
| `detect_defense_evasion` | **5 CRITICAL** (Event 1102 Security + 104 System + wevtutil cl × 3) |
| `detect_ransomware_behavior` | **4 CRITICAL** (7 anti-recovery commands + 15 service-stop burst + ransom notes + **30 .locked file renames**) |

## MITRE ATT&CK coverage summary

Agentic-DFIR covers these TA0001–TA0040 tactics with scoped detection rules:

| Tactic | Agentic-DFIR coverage |
|---|---|
| TA0001 Initial Access | parse_browser_history, analyze_downloads, analyze_web_access_log, detect_webshell, detect_brute_force_rdp, analyze_unix_auth, analyze_usb_history |
| TA0002 Execution | get_process_tree (LOTL flags), get_amcache, parse_prefetch, analyze_event_logs |
| TA0003 Persistence | detect_persistence (Run keys + Services + Tasks), parse_fsevents (LaunchAgent) |
| TA0004 Privilege Escalation | detect_privilege_escalation |
| TA0005 Defense Evasion | **detect_defense_evasion** (event log clearing, timestomp, MFT $SI/$FN) |
| TA0006 Credential Access | **detect_credential_access** (Mimikatz, procdump, LOLBin, SAM/NTDS, DPAPI, /etc/shadow) |
| TA0007 Discovery | **detect_discovery** (AD enum, BloodHound, local recon, burst detection) |
| TA0008 Lateral Movement | detect_lateral_movement (PsExec/WMIExec/WinRS), analyze_windows_logons, analyze_kerberos_events |
| TA0009 Collection | extract_mft_timeline, parse_fsevents *(infrastructure present; not yet in scoped detection rules — Phase 2)* |
| TA0010 Exfiltration | detect_exfiltration, correlate_timeline |
| TA0011 Command & Control | *partial* — detect_dns_tunneling (DNS-tunnelling heuristics) and process-side indicators; full PCAP-based C2 detection is Phase 2 (issue #47) |
| TA0040 Impact | **detect_ransomware_behavior** (shadow delete, taskkill spree, mass rename, ransom notes) |

Ten of the twelve tactics are actively covered by scoped detection rules.
TA0009 Collection has the necessary parsers (MFT, FSEvents) but no scoped
detection rules yet; TA0011 C2 has DNS-tunnelling heuristics but no PCAP
primitives. Both are Phase 2 work, written up in closed issues (issue #47 for external-dataset
benchmarking and PCAP primitives, issue #30 for native `parse_evtx`, issue
#10 for Sigma rule synthesis). The per-platform view of the same functions is
in [platform support](./platform-support.md).

### Per-case ground-truth coverage

| Case | Layer | Findings | Notes |
|---|---|---:|---|
| self-evaluation/case-01 (IP-KVM insider) | 1 | 5 | IP-KVM insider, USB indicator, scheduled task |
| self-evaluation/case-02 (LOTL PowerShell) | 1 | 7 | Encoded PS, LOLBin, Run key persistence |
| self-evaluation/case-03 (macOS remote-admin) | 1 | 8 | macOS Gatekeeper bypass, LaunchAgent, FSEvents |
| self-evaluation/case-04 (phishing to exfil) | 1 | 6 | MOTW, double-extension, cloud upload |
| self-evaluation/case-05 (auth + lateral) | 1 | 8 | Brute-force survivor, Kerberoasting, Linux pivot |
| self-evaluation/case-06 (web + RDP pivot) | 1 | 10 | Webshell, SQLi, RDP pivot |
| self-evaluation/case-07 (ransomware chain) | 1 | 13 | Shadow-copy delete, mass rename, ransom note |
| self-evaluation/case-08 (supply-chain) | 1 | 12 | Supply-chain → ESC8 → DCSync → Golden Ticket |
| external-evaluation/case-01 (CFReDS) | 2 | 10 | NIST CFReDS (Greg Schardt / Mr. Evil) |
| external-evaluation/case-02 (Hadi) | 2 | 5 | Ali Hadi web-server challenge (truth rewritten in v1.2.0 against the confirmed XAMPP `access.log` path) |
| external-evaluation/case-03 (M57) | 2 | 10 | Digital Corpora M57-Patents (Jo) |
| **Total** | | **94** | 102 MITRE technique references, 66 unique techniques |

Layer 1 (synthetic, noise-injected, 8 cases): **69 findings**.
Layer 2 (external, community-verified, 3 cases): **25 findings**.
`scripts/eval/validate_ground_truth.py` gates truth-file integrity in CI; the
counts above are what it reads from the eleven `truth.json` files.

Self-correction is graded, not anecdotal: the graded self-correction findings
are case-04 `F-PHISH-006` and the reference run's `F-013`
([`examples/out/ref-01`](../examples/out/ref-01/)).

## Methodology and limitations

This section is intentionally explicit so reviewers can calibrate how to
weight the headline numbers.

### What is measured

`scripts/eval/demo.py`:

1. Walks `examples/case-studies/self-evaluation/case-01/evidence_root/` and
   computes a SHA-256 over every file → **pre-run evidence digest map**.
2. Runs `dfir_agent` in deterministic mode against the bundled Case 01
   (IP-KVM remote-hands insider).
3. Re-walks the evidence tree and re-computes the digest map → **post-run
   evidence digest map**. Equality of the two maps proves the agent did
   not modify, append, or delete any evidence file (read-only by
   construction; this is a runtime confirmation).
4. Reads the agent's emitted findings and compares against the ground-truth
   set `{F-001, F-013}`:
   - **Recall** = |reported ∩ ground-truth| / |ground-truth|
   - **FPR** = |reported \ ground-truth| / |reported|, treating any
     reported finding outside ground truth as a false positive
   - **Hallucination count** = number of finding `audit_id` citations
     that resolve to no entry in the audit chain
5. Verifies the audit chain via `AuditLogger.verify()` (SHA-256 chain
   walk; any tampered entry breaks the chain).
6. Calls the unregistered `execute_shell` and confirms it is refused.

`scripts/eval/self.py` and `scripts/eval/external.py` run the live agent per
(case, model), score `findings.json` against the case's `truth.json` with
`scripts/eval/score.py` over the tool-reachable subset, and record recall and
token cost into the ledger. Self cases match by ATT&CK technique overlap;
findings with no technique (investigative conclusions, audit-chain notes) are
excluded from the denominator, not counted as misses. External cases mostly
carry no technique and instead flag whether the current toolset can reach the
answer at all; recall is computed over that reachable subset.

### What is *not* measured by this report

- **Detection breadth on novel IOCs.** The bundled cases test specific
  attack chains. Behavior on attack chains not represented in the
  ground-truth set is not characterized here.
- **Performance under adversarial evidence.** Crafted hostile inputs
  (timestomp loops, infinite parent chains, ZIP bombs) are tested by
  `tests/test_concurrency_and_edge_cases.py`, not by this accuracy
  measurement.
- **Live-mode protocol correctness.** The demo numbers are from
  deterministic mode; the ledger numbers are live runs. Live mode has
  different failure modes (token limit, prompt injection at the model
  boundary); its plumbing is measured separately in `tests/test_live_mcp.py`
  with focus on protocol correctness, not detection accuracy — see
  [live mode](./live-mode.md).
- **Generalization to production data.** The bundled evidence is
  synthetic. Production data has different statistical properties
  (volume, schema variance, label noise). The external tier (NIST CFReDS,
  Ali Hadi, Digital Corpora M57) is the first answer to that; it is three
  images, and the remaining datasets named in issue #47 (DFRWS, BOTS) are
  not integrated.

### What would make the numbers stronger

- Independent third-party scoring on community-recognized datasets beyond
  the three integrated ones (DFRWS, BOTS) — Phase 2 / issue #47
- Sigma rule synthesis from the audit corpus for re-detection on unseen
  incidents — Phase 2 / issue #10 (the `match_sigma_rules` tool and the
  11-rule `dfir_sigma` pack are the matching side; synthesis is not shipped)
- Native EVTX/PCAP parsing (currently relies on pre-extracted JSON, or the
  `sift_evtxecmd_parse` adapter for the binary path) — Phase 2 / issue #30
- Hostile-evidence red team (intentionally crafted to fool detection
  rules) — Phase 2 stretch goal

These are explicit gaps; this report does not claim to substitute for
them. It claims only what was measured.

## Honest limitations

1. **Eric Zimmerman tools (MFTECmd, PECmd, AppCompatCacheParser)** are
   consumed via sidecar CSV/JSON by the native parsers, so a fresh clone
   needs no .NET runtime; the nine `sift_*` Eric Zimmerman adapters run the
   tools directly when their .NET builds are staged.
2. **FSEventsParser and `log show`** are external to Agentic-DFIR — they
   produce the input Agentic-DFIR consumes. This is analogous to the Windows
   sidecar model.
3. **Volatility memory forensics** runs through the 12 `sift_vol3_*`
   adapters when Volatility 3 is installed; there is no native memory-image
   parser in the surface.
4. **Event log / UnifiedLog rule packs are deliberately small** (5 rules
   each). Designed to demonstrate the detection surface, not replace
   Sigma / hayabusa / mandiant's macOS rules. Rule schema is extensible.

## Roadmap progress (since Gemini external review)

| Capability | Original status | Now |
|---|---|---|
| MFT / Prefetch / Amcache parsing | "scaffolded" | Implemented |
| AppCompat / ShimCache parsing | "scaffolded" | Implemented |
| ShellBags parsing | not mentioned | Implemented |
| Process tree + LOTL detection | "ready to be added" | Implemented |
| Persistence (Run keys + Services + Tasks) | not mentioned | Implemented |
| Event log analysis with rule pack | not mentioned | Implemented |
| DuckDB correlation at scale | "planned" | Implemented |
| macOS UnifiedLog | "planned" | Implemented |
| macOS KnowledgeC | "planned" | Implemented |
| macOS FSEvents | "planned" | Implemented |
| Volatility memory forensics | "planned" | Implemented through the 12 `sift_vol3_*` adapters |
| Live MCP mode (Claude Code stdio) | "planned" | Implemented — see [live mode](./live-mode.md) |

All twelve rows are real implementations. What remains open is in the
[roadmap](./roadmap.md).

## What this report is not claiming

- Not that the agent matches a senior human analyst on open-ended novel
  cases. It matches on cases with mechanically verifiable ground truth.
- Not zero false negatives in adversarial settings — only against the
  documented corpus.
- Not production-readiness. The current release demonstrates that the
  architecture is correct and the loop is sound; hardening is the Phase 2–3
  roadmap.

## External benchmarking — the paradigm gap, honestly

The synthetic measurement is necessary but not sufficient. The honest reviewer
question — "what does it score on a dataset *you* didn't author?" — is
answered by integrating external corpora (NIST CFReDS Hacking Case, Ali Hadi
Challenge 1, Digital Corpora M57). Those scores live in `docs/benchmarks/`
alongside the synthetic ones.

The point worth making here is **why** external recall sits below synthetic
recall — and it is not a regression:

- Synthetic accuracy measures *correctness of the detection logic against
  IOCs the system claims to detect*.
- External accuracy measures *expansion potential against a content-centric
  paradigm dfir-mcp is still building out*.

External benchmarking is what converted "we should add registry parsing
someday" into "registry parsing unblocks several measured findings — ship it
next." That is the real value of third-party data: it reorders the Phase 2
backlog by evidence, not by guess.

## See also

- [`benchmarks/README.md`](./benchmarks/README.md) — the ledger, its reading, and the recall/consistency roadmap
- [Dataset](./dataset.md) — what is bundled, what is downloaded, licences
- [Case study — IP-KVM insider](./case-ip-kvm.md) — finding → artifact → command → hash on the reference run
- [Live mode](./live-mode.md) — the loop the ledger numbers come from
- [Threat model](./threat-model.md) — what the invariants defend against
- [Roadmap](./roadmap.md) — the Phase 2 items named above
