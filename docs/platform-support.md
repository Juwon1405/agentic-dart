# Platform support

This page states where Agentic-DFIR runs (the host) and what it can analyze (the targets), then maps the 73-tool MCP surface onto those targets: the native functions by platform, the SIFT adapters by tool family, the published references the surface is built from, and the MITRE ATT&CK tactics it covers. Use it to decide whether a piece of evidence is in scope before you start a run; the per-function detail lives in the [MCP function catalog](./mcp-function-catalog.md).

**Host (where the agent runs): Linux only.** Agentic-DFIR is developed and verified on the **SANS SIFT Workstation (Ubuntu 22.04)**; other Linux distributions (RHEL / Rocky / AlmaLinux 8+, Fedora) work via `dnf`/`yum` — `scripts/install.sh` detects `apt-get`, `dnf` or `yum` and stops if none is present. macOS and Windows are **not** supported as the host — the Plaso / libyal forensic toolchain does not build cleanly on them (see [Operator guide — Prerequisites](./operator-guide.md#prerequisites)); Windows under WSL2 is untested. The default shell is bash. CI runs the test suite on Python 3.10, 3.11, 3.12 and 3.13, and every package declares `requires-python >= 3.10`.

**Analysis targets (the OS the evidence came from) are cross-platform** — Windows, macOS, and Linux evidence are all analyzed regardless of the (Linux) host the agent runs on. That matrix is below.

## Supported analysis targets — explicit matrix

| Target OS | Coverage | Evidence types analyzed |
|---|:---:|---|
| **Windows** &nbsp;<sub>10 / 11 / Server 2016+</sub> | Deep | Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, AmCache.hve), $MFT, Prefetch, ShellBags, ShimCache, EVTX (Security/System/Application/Sysmon), Scheduled Tasks, USBSTOR + setupapi.dev.log, Volume Shadow metadata; memory images through the Volatility 3 adapters |
| **macOS** &nbsp;<sub>11 Big Sur → 14 Sonoma</sub> | Standard | UnifiedLog (`log show --style ndjson`), KnowledgeC.db (CoreDuet), FSEvents (fseventsd), LaunchAgent / LaunchDaemon plists, browser SQLite (Safari, Chrome, Firefox), Spotlight metadata, Quarantine xattrs and the `QuarantineEventsV2` database; in-memory bash history through Volatility 3 |
| **Linux** &nbsp;<sub>RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 11+</sub> | Standard | auditd (`/var/log/audit/audit.log`), systemd-journal (`journalctl -o json`), syslog (`auth.log` / `secure` / `messages`), bash/zsh history, cron / anacron / systemd-units, web access logs (Apache / Nginx); process list and in-memory bash history through Volatility 3 |
| **Cross-platform** | Broad | Process trees, browser SQLite (Chrome / Firefox / Safari / Edge), DNS query logs (BIND9 / dnsmasq), Python `site-packages` and npm `package.json` trees for supply-chain sweeps, Sigma rule matching against any pre-extracted event log, YARA scans, Plaso super-timelines, MITRE ATT&CK chain reasoning |

> **Note on host vs. target:** the agent reads forensic *output* the
> operator produces (CSV / JSON / SQLite / plist / NDJSON), or hands a raw
> artifact, image or memory dump to a SIFT adapter. It does not require live
> agent installation on the target host. This is what makes it work on disk
> images and offline triage.

## Typed forensic functions (native layer) — by platform

The full surface is enumerated at runtime via `python3 -c "from dfir_mcp import list_tools; [print(t['name']) for t in list_tools()]"` (with `PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src`). The 48 native functions are summarized by platform below; the SIFT adapter layer follows. Each function's artifact, MITRE mapping and references are in the [MCP function catalog](./mcp-function-catalog.md).

| Platform | Count | Functions |
|---|:---:|---|
| **Windows** | 13 | `get_amcache`, `parse_prefetch`, `parse_shimcache`, `parse_shellbags`, `extract_mft_timeline`, `list_scheduled_tasks`, `analyze_usb_history`, `analyze_event_logs`, `analyze_windows_logons`, `detect_lateral_movement`, `detect_brute_force_rdp`, `detect_persistence`, `parse_registry_hive` |
| **Windows AD** | 1 | `analyze_kerberos_events` (4768 / 4769 / 4770 / 4771) |
| **macOS** | 5 | `parse_unified_log`, `parse_knowledgec`, `parse_fsevents`, `parse_launchd_plist`, `parse_macos_quarantine` |
| **Linux** | 6 | `parse_auditd_log`, `parse_systemd_journal`, `analyze_unix_auth`, `parse_linux_cron_jobs`, `parse_linux_text_log`, `parse_linux_shell_history` |
| **Linux + macOS** | 2 | `parse_bash_history` (with attacker-pattern detection: T1059.004, T1098.004, T1070.003, T1105, T1548.001, etc.), `grep_shell_history_for_c2` |
| **Cross-platform** | 15 | `get_process_tree`, `parse_browser_history`, `analyze_downloads`, `correlate_download_to_execution`, `detect_exfiltration`, `detect_credential_access`, `detect_ransomware_behavior`, `detect_defense_evasion`, `detect_discovery`, `detect_privilege_escalation`, `analyze_web_access_log`, `detect_webshell`, `correlate_events`, `correlate_timeline`, `match_sigma_rules` |
| **Cross-platform (network)** | 1 | `detect_dns_tunneling` |
| **Supply-chain IOC sweeps** (cross-platform) | 5 | `scan_pth_files_for_supply_chain_iocs`, `detect_pypi_typosquatting`, `detect_nodejs_install_hooks`, `detect_python_backdoor_persistence`, `detect_credential_file_access` |
| **Native total** | **48** | |

## 25 SIFT Workstation tool adapters — by tool family

With the SIFT adapters loaded the surface counts **73** tools (48 native + 25 SIFT). The adapters are named with a `sift_` prefix and split by tool family as follows: Volatility 3 v2.27 — 12 (nine Windows plugins, Linux pslist and bash, macOS bash); Eric Zimmerman tools — 9 (MFTECmd 2, EvtxECmd 2, PECmd 2, RECmd 2 with the ASEPs batch as default, AmcacheParser 1); YARA — 2; Plaso (log2timeline + psort) — 2. The adapter-by-adapter table, the plugin each one wraps, binary resolution and the env-var overrides (`DFIR_VOLATILITY3_BIN`, `DFIR_MFTECMD_BIN`, etc.) are in [SIFT Workstation adapter layer — What's exposed](./sift-adapter-layer.md#whats-exposed-25-adapters).

Adapters are optional at runtime: on a host without the SIFT binaries they raise `SiftToolNotFoundError` and the agent falls back to the native function covering the same artifact, so the analysis-target matrix above holds on any supported Linux host, with the memory-image and super-timeline rows depending on the SIFT toolchain being present.

## How the surface was built — references and provenance

The native functions are not invented from scratch. Each one is grounded in a published reference. The full mapping with hyperlinks is in the [MCP function catalog](./mcp-function-catalog.md). High-level sources:

| Domain | Primary references |
|---|---|
| **Windows artifacts** | SANS FOR500 (Windows Forensic Analysis), SANS FOR508 (Advanced IR & Threat Hunting), Microsoft official docs (EVTX schema, Sysmon, Amcache), Eric Zimmerman's tools (PECmd, AmcacheParser, ShellBags Explorer, MFTECmd) — naming and field semantics aligned for operator familiarity |
| **macOS artifacts** | SANS FOR518 (Mac & iOS Forensic Analysis), Apple Developer Library, Patrick Wardle's *The Art of Mac Malware* (vol. 1: persistence; vol. 2: detection), mac4n6.com, Sarah Edwards' KnowledgeC research |
| **Linux artifacts** | SANS FOR577 (Linux IR & Threat Hunting), Red Hat RHEL Security Guide ch.7 (auditd), `systemd.journal-fields(7)`, freedesktop.org Journal Export Format, Hal Pomeranz's Linux IR talks |
| **Cross-platform / TTPs** | MITRE ATT&CK Enterprise (every detection function is mapped to a tactic + technique), Sigma rules (community detection corpus), Florian Roth's signature-base, Atomic Red Team |
| **Architecture** | MITRE Cyber Resiliency Engineering Framework, Anthropic's Model Context Protocol spec, "Threat Hunting in the Real World" (NIST SP 800-150), the AuditChain pattern from RFC 6234 (SHA-256) + RFC 5246 (chained MAC) |

The SIFT adapters inherit provenance from the tools they wrap (Volatility 3, the Eric Zimmerman tools, YARA, Plaso); see [SIFT Workstation adapter layer](./sift-adapter-layer.md).

## MITRE ATT&CK coverage — broad enterprise tactic coverage

| # | Tactic | Covered by |
|:---:|---|---|
| TA0001 | Initial Access | `analyze_usb_history`, `analyze_web_access_log`, `detect_webshell`, `detect_brute_force_rdp`, `parse_macos_quarantine` (download chain), `scan_pth_files_for_supply_chain_iocs` / `detect_pypi_typosquatting` / `detect_nodejs_install_hooks` (T1195.002 supply chain) |
| TA0002 | Execution | `get_amcache`, `parse_prefetch`, `parse_shimcache`, `get_process_tree`, `parse_bash_history`, `parse_linux_shell_history` |
| TA0003 | Persistence | `detect_persistence`, `list_scheduled_tasks`, `parse_launchd_plist`, `parse_systemd_journal` (units), `parse_bash_history` (cron, rc.local), `parse_linux_cron_jobs`, `detect_python_backdoor_persistence`, `detect_webshell` (T1505.003) |
| TA0004 | Privilege Escalation | `detect_privilege_escalation`, `parse_auditd_log` (setuid syscalls), `parse_bash_history` (chmod +s) |
| TA0005 | Defense Evasion | `detect_defense_evasion`, `extract_mft_timeline` ($SI/$FN timestomp), `parse_bash_history` (history clear), `parse_linux_shell_history` (T1070.003, T1027) |
| TA0006 | Credential Access | `detect_credential_access`, `analyze_windows_logons`, `analyze_kerberos_events`, `analyze_unix_auth`, `detect_brute_force_rdp`, `detect_credential_file_access` (T1552) |
| TA0007 | Discovery | `detect_discovery`, `parse_shellbags`, `parse_knowledgec` |
| TA0008 | Lateral Movement | `detect_lateral_movement` (PsExec / WMIExec / WinRM / SMB) |
| **TA0009** | **Collection** | **Partial** — parsers present (`parse_fsevents`, `extract_mft_timeline`) but no scoped Collection detection rule yet; **deferred to Phase 2** |
| TA0010 | Exfiltration | `detect_exfiltration`, `correlate_download_to_execution` |
| **TA0011** | **Command and Control** | **Partial** — `detect_dns_tunneling` (DNS query logs: T1071.004, T1568.002, T1572, added in v0.6.1) and `grep_shell_history_for_c2` (T1071) give log- and process-side indicators. Full PCAP-based C2 detection is **deferred to Phase 2** |
| TA0040 | Impact | `detect_ransomware_behavior` (mass-rename + shadow-copy delete + ransom notes) |

Coverage = **10 / 12** tactics actively detected by scoped rules. Two tactics are **partial** and are not claimed as covered: Collection (parsers present, no scoped rule yet) and Command and Control (DNS-log and shell-history indicators only; PCAP-based detection is roadmap — see [Roadmap](./roadmap.md)). `match_sigma_rules` adds cross-tactic corroboration from the 11-rule Sigma pack (credential access, defense evasion, impact, initial access, lateral movement, persistence). 12/12 is not claimed. The per-technique T-ID mapping for each function is in the [MCP function catalog](./mcp-function-catalog.md).

Against the bundled ground truth — 11 cases (8 self-evaluation + 3 external-evaluation), 94 ground-truth findings — the `truth.json` files carry 102 MITRE technique references over 66 unique techniques. `scripts/eval/validate_ground_truth.py` checks that every `expected_dfir_mcp_function` named there is a registered tool; see [Evidence dataset](./dataset.md).

## See also

- [MCP function catalog](./mcp-function-catalog.md) — every native function with artifact, MITRE mapping and references
- [SIFT Workstation adapter layer](./sift-adapter-layer.md) — the 25 adapters, binary resolution, contract
- [Operator guide](./operator-guide.md) — install, requirements, running your own evidence
- [Running on SIFT](./running-on-sift.md) — the primary host, step by step
- [Evidence dataset](./dataset.md) — the bundled and external cases
