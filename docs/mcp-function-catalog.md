# MCP function catalog

This page is the reference for every function on the Agentic-DFIR MCP surface: what artifact it reads, what it is for, which MITRE ATT&CK tactics and techniques it speaks to, and which published reference its logic follows. The surface is 73 read-only tools — 48 native pure-Python forensic functions documented entry by entry below, plus 25 SIFT Workstation tool adapters that are documented in [SIFT Workstation adapter layer](./sift-adapter-layer.md). Every function is **read-only**, schema-validated, and grounded in a published reference. Anything not in this catalog cannot be called by the agent — that is the architectural guarantee.

Since v0.5.0 the surface has had two layers behind one boundary: the native functions ship with the `dfir_mcp` package and need nothing installed beyond it; the SIFT adapters wrap Volatility 3, MFTECmd, EvtxECmd, PECmd, RECmd, AmcacheParser, YARA and Plaso behind the same typed, audited, read-only boundary. Functions added between v0.6.1 and v1.1.0, which earlier revisions of this catalog listed in a separate appendix, are filed under their platform here.

A common question about any AI-assisted DFIR tool is "where does the detection logic come from — was it made up?" The answer for Agentic-DFIR is no: every function follows a specific published reference, listed inline below. If you find a discrepancy between a reference and the implementation, open an issue tagged `accuracy`.

The registry is the arbiter for names and input schemas. Enumerate it with:

```bash
PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src \
  python3 -c "from dfir_mcp import list_tools; [print(t['name']) for t in list_tools()]"
```

---

## Quick navigation

| Platform | Functions | Section |
|---|:---:|---|
| Windows (13) + Windows AD (1) | 14 | [Windows](#windows), [Windows AD](#windows-ad) |
| macOS | 5 | [macOS](#macos) |
| Cross-platform (network) | 1 | [Cross-platform (network)](#cross-platform-network) |
| Linux | 6 | [Linux](#linux) |
| Linux + macOS | 2 | [Linux + macOS shared](#linux--macos-shared) |
| Cross-platform | 20 | [Cross-platform](#cross-platform) |
| **Native total** | **48** | |
| SIFT Workstation adapters | 25 | [SIFT Workstation adapter layer](./sift-adapter-layer.md#whats-exposed-25-adapters) |
| **Grand total MCP surface** | **73** | |

---

## Windows

### `get_amcache`
**Artifact:** `Windows\AppCompat\Programs\Amcache.hve` (sidecar CSV)
**Purpose:** Execution evidence. Every binary that has run on the host is recorded here, including SHA-1, file metadata, and first-execution timestamp.
**MITRE:** TA0002 (Execution)
**References:**
- Eric Zimmerman — [`AmcacheParser`](https://github.com/EricZimmerman/AmcacheParser) (de facto field reference)
- SANS FOR500 — *Windows Forensic Analysis* (Day 2: Application Execution Artifacts)

### `parse_prefetch`
**Artifact:** `C:\Windows\Prefetch\*.pf`
**Purpose:** Boot-time and execution timeline. Each `.pf` records up to 8 most-recent run timestamps + file paths the binary touched. Reads the native header and, when present, a PECmd sidecar JSON.
**MITRE:** TA0002
**References:**
- Microsoft Docs — *[Prefetch File Format](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)* (overview)
- libyal — [`libscca`](https://github.com/libyal/libscca) (canonical structure documentation)
- SANS FOR500 — Day 2

### `parse_shimcache`
**Artifact:** `SYSTEM` hive → `AppCompatCache` value
**Purpose:** Application Compatibility Cache. Records every executable the user has *navigated to or launched*, even if it never ran (T1218 LOLBin reconnaissance). Survives binary deletion.
**MITRE:** TA0002, TA0007 (Discovery)
**References:**
- Mandiant — *[Caching Out: The Value of Shimcache](https://www.mandiant.com/resources/blog/caching-out-the-val)*
- SANS FOR508 — *Advanced Incident Response*

### `parse_shellbags`
**Artifact:** `NTUSER.DAT` (BagMRU + Bags subkey)
**Purpose:** Folder access history per user — including external drives, network shares, and now-deleted folders.
**MITRE:** TA0007, TA0009 (Collection)
**References:**
- Eric Zimmerman — [`Shellbags Explorer`](https://ericzimmerman.github.io/)
- forensics.wiki — *[Shell Items](https://forensics.wiki/shell_item/)* (community reference)
- SANS FOR500 — Day 4 (User Activity)

### `extract_mft_timeline`
**Artifact:** `$MFT` (NTFS Master File Table)
**Purpose:** Filesystem-level timeline. Critical for **timestomp detection** (T1070.006) — `$SI` (Standard Information) vs `$FN` (File Name) timestamp comparison.
**MITRE:** TA0005 (Defense Evasion), TA0009
**References:**
- Eric Zimmerman — [`MFTECmd`](https://ericzimmerman.github.io/)
- libyal — [`libfsntfs`](https://github.com/libyal/libfsntfs)
- SANS FOR500 — Day 3 (Filesystem Forensics)
- Trustwave SpiderLabs — *[$SI vs $FN Detection](https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/)*

### `list_scheduled_tasks`
**Artifact:** `\Windows\System32\Tasks\` XML + `Microsoft-Windows-TaskScheduler/Operational.evtx`
**Purpose:** Persistence via scheduled tasks (T1053.005). A top-3 persistence mechanism in commodity malware (per the CrowdStrike Global Threat Report).
**MITRE:** TA0003 (Persistence)
**References:**
- MITRE ATT&CK — [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- Microsoft Docs — *Task Scheduler XML Schema*
- CrowdStrike — *2024 Global Threat Report* (T1053 prevalence)

### `analyze_usb_history`
**Artifacts:** `SYSTEM` hive → `USBSTOR`, `MountedDevices`, `setupapi.dev.log`
**Purpose:** Every USB removable device ever inserted, with first/last connect timestamps and serial numbers. Critical for IP-KVM / insider-threat investigation.
**MITRE:** TA0001 (Initial Access), TA0009
**References:**
- SANS — *[Forensics 101: Acquiring an Image](https://www.sans.org/blog/forensics-101-acquiring-an-image-with-ftk-imager/)* (general DFIR ref)
- libyal — `liburse`
- SANS FOR500 — Day 4

### `analyze_event_logs`
**Artifact:** `*.evtx` files (Security, System, Application, Sysmon), consumed as a pre-extracted JSON export (`events_json`)
**Purpose:** Windows event log analysis with a rule pack; returns triggered alerts grouped by severity. Surfaces clearing events (T1070.001), service installations, account creation. Raw `.evtx` files are reached through the `sift_evtxecmd_parse` adapter.
**MITRE:** TA0005, TA0006, TA0008
**References:**
- Microsoft Docs — *[Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)*
- JPCERT/CC — *[Detecting Lateral Movement through Tracking Event Logs](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)*
- Florian Roth — *[Sigma rules](https://github.com/SigmaHQ/sigma)* (rule corpus the IOCs are drawn from)

### `analyze_windows_logons`
**Artifact:** Security EVTX (4624 / 4625 / 4634 / 4647 / 4648 / 4672)
**Purpose:** Logon-type analysis — distinguishes interactive (type 2), network (type 3), RDP (type 10), and explicit-credential (type 9 / 4648).
**MITRE:** TA0006, TA0008
**References:**
- Microsoft Docs — *[Audit Logon Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events)*
- JPCERT/CC — *Detecting Lateral Movement* (event-ID matrix per technique)

### `detect_lateral_movement`
**Inputs:** Windows logon events + process tree
**Purpose:** Pattern-based detection of PsExec (service install + 4672), WMIExec (`wmiprvse.exe → cmd.exe`), WinRM (5985/5986 + WSMan provider), SMB admin shares (T1021.002).
**MITRE:** TA0008
**References:**
- JPCERT/CC — *Detecting Lateral Movement through Tracking Event Logs* (the canonical reference for this category)
- MITRE ATT&CK — T1021.002, T1047, T1021.006
- F-Secure / WithSecure — *[Lateral Movement field manual](https://blog.f-secure.com/lateral-movement-techniques/)*

### `detect_brute_force_rdp`
**Artifact:** Security EVTX (4625 with logon type 10)
**Purpose:** RDP-specific brute force detection. Distinguishes credential stuffing, password spray, and single-account targeting based on source-IP and user-name patterns.
**MITRE:** TA0006 (T1110.001 / T1110.003)
**References:**
- Microsoft Defender for Identity — *[RDP Brute Force Detection Logic](https://docs.microsoft.com/en-us/defender-for-identity/)*
- BSI (German Federal IT) — *[Detecting RDP Brute Force](https://www.bsi.bund.de/EN/Home/home_node.html)*

### `detect_persistence`
**Artifacts:** Run keys, services, scheduled tasks, WMI subscriptions
**Purpose:** Cross-mechanism persistence enumeration with anomaly scoring (recently created entries in user-writable paths get higher scores).
**MITRE:** TA0003 (T1547, T1543, T1053, T1546)
**References:**
- MITRE ATT&CK — Persistence tactic page (every sub-technique)
- Microsoft Sysinternals — *[Autoruns reference](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)*

### `parse_registry_hive`
**Artifact:** Any registry hive — `SOFTWARE`, `SYSTEM`, `SAM`, `NTUSER.DAT`, etc.
**Purpose:** Read-only registry hive value extraction via the python-registry parser. Extracts a single value (`value_name`) or all values under a key (`key`, forward or backslash separators, leading backslash optional; `limit` default 100, max 1000). Never writes; the hive path is canonicalized via `_safe_resolve`. Added in v0.5.4 to close the generic-hive gap that the NIST CFReDS Hacking Case exposed.
**MITRE:** Supports host/user attribution (RegisteredOwner, NetworkCards, ShutdownTime, account names) rather than a single tactic.
**References:**
- [`python-registry`](https://github.com/williballenthin/python-registry) (parser)
- NIST CFReDS — *Hacking Case* official answers (the ground-truth questions this function serves)

---

## Windows AD

### `analyze_kerberos_events`
**Artifact:** Domain controller Security EVTX (4768 / 4769 / 4770 / 4771)
**Purpose:** Kerberos attack detection — Kerberoasting (RC4 ticket request), AS-REP Roasting (no pre-auth), Golden / Silver Ticket residue.
**MITRE:** TA0006 (T1558.003 Kerberoasting, T1558.004 AS-REP Roasting)
**References:**
- Sean Metcalf (adsecurity.org) — *[Detecting Kerberoasting](https://adsecurity.org/?p=3458)*
- Microsoft — *[Securing Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)*
- SpecterOps — *[Rubeus](https://github.com/GhostPack/Rubeus)* (offensive tool whose footprint is detected)

---

## macOS

### `parse_unified_log`
**Artifact:** `log show --style ndjson` output
**Purpose:** macOS unified log parser with rule pack — TCC bypass attempts, SSH auth failures, Gatekeeper / quarantine, XProtect detections, suspicious launchd loads.
**MITRE:** TA0001, TA0005, TA0006
**References:**
- Apple Developer — *[Unified Logging Reference](https://developer.apple.com/documentation/os/logging)*
- Mandiant — *[macos-UnifiedLogs research](https://github.com/mandiant/macos-UnifiedLogs)* (rules adapted from this corpus)
- Sarah Edwards — *[Mac4n6 Unified Log talks](https://www.mac4n6.com/)*
- SANS FOR518 — *Mac & iOS Forensic Analysis*

### `parse_knowledgec`
**Artifact:** `~/Library/Application Support/Knowledge/knowledgeC.db` (SQLite)
**Purpose:** macOS CoreDuet activity database — app usage, Safari history, in-focus times. Cocoa-epoch (NSDate) → ISO 8601 conversion.
**MITRE:** TA0007, TA0009
**References:**
- Sarah Edwards — *[KnowledgeC.db forensic value](https://www.mac4n6.com/blog/2018/8/5/knowledge-is-power-using-the-knowledgecdb-database-on-macos-and-ios-to-determine-precise-user-and-application-usage)*
- Mandiant — KnowledgeC schema documentation
- SANS FOR518

### `parse_fsevents`
**Artifact:** `/.fseventsd/` (root-only)
**Purpose:** macOS filesystem event stream. Records create / rename / delete / modify operations on every mounted volume (T1070.004 indicators).
**MITRE:** TA0005, TA0009
**References:**
- Apple — *[FSEvents Programming Guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/)*
- Nicole Ibrahim — *[FSEvents in DFIR](https://www.nicoleibrahim.com/blog/)*

### `parse_launchd_plist`
Added in v0.4.
**Artifact:** `*.plist` in any of 5 standard launchd paths
**Purpose:** Surfaces persistence indicators — `RunAtLoad=true` in user-writable path, executable in `/tmp/`, aggressive `KeepAlive`, label masquerading.
**MITRE:** TA0003 (T1543.001 LaunchDaemon, T1543.004 LaunchAgent)
**References:**
- Apple Developer — *[Daemons and Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)*
- Patrick Wardle — *The Art of Mac Malware* vol. 1 (persistence corpus)
- Objective-See — *[KnockKnock](https://objective-see.com/products/knockknock.html)* (open-source persistence enumerator)

### `parse_macos_quarantine`
Added in v0.6.1.
**Artifact:** `com.apple.LaunchServices.QuarantineEventsV2` SQLite at `~/Library/Preferences/`
**Purpose:** Download provenance — links a file on disk to the URL, agent app, and timestamp that introduced it. The Gatekeeper attribute trail. Flags non-browser downloaders and pastesite / raw-IP / darknet origin URLs.
**MITRE:** T1204 (User Execution download chain attribution)
**References:**
- Sarah Edwards — *macOS QuarantineV2 schema reverse engineering* (`mac4n6.com`)
- Apple — *LaunchServices Quarantine attribute documentation*

---

## Cross-platform (network)

### `detect_dns_tunneling`
Added in v0.6.1.
**Artifact:** DNS query log (BIND9 `query.log`, dnsmasq syslog, or a generic FQDN-extraction fallback) — NXDOMAIN-heavy, TXT-heavy, or `*.tld` queries
**Purpose:** TA0011 (C2) entry point. Iodine / dnscat2 / DNScat-B signature detection + Shannon entropy per subdomain label (`entropy_threshold`, default 3.8) + abnormally long labels (`long_label_threshold`, default 50; DNS max is 63) + per-parent-domain query volume in a sliding window (`volume_threshold` 50 in `volume_window_seconds` 300) + rare TXT/NULL/CNAME record types.
**MITRE:** T1071.004 (Application Layer Protocol — DNS), T1568.002 (Dynamic Resolution — DGA), T1572 (Protocol Tunneling)
**References:**
- Yarrin & Andersson (2009) — *Iodine* protocol whitepaper
- iagox86 — *dnscat2* design notes
- SANS FOR572 — *Advanced Network Forensics* (DNS exfiltration detection with high-entropy subdomains)
- RFC 1035, RFC 3833

---

## Linux

### `parse_auditd_log`
Added in v0.4.
**Artifact:** `/var/log/audit/audit.log`
**Purpose:** Kernel-level syscall audit. Filter by syscall, key, executable. The single most authoritative DFIR data source on Linux.
**MITRE:** TA0002, TA0006, TA0004
**References:**
- Red Hat — *[RHEL Security Guide ch. 7 — System Auditing](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)*
- `auditd(8)`, `audit.rules(7)` man pages
- SANS FOR577 — *Linux Incident Response & Threat Hunting*
- Hal Pomeranz — *[Linux Memory Forensics & auditd talks](https://github.com/halpomeranz/lmg)*

### `parse_systemd_journal`
Added in v0.4.
**Artifact:** `journalctl -o json --no-pager` output
**Purpose:** Unified system log — services, kernel, user sessions. Successor to traditional syslog on modern distros (RHEL 7+, Ubuntu 16.04+).
**MITRE:** TA0006, TA0008, TA0003
**References:**
- `systemd.journal-fields(7)`
- freedesktop.org — *[Journal Export Format](https://www.freedesktop.org/wiki/Software/systemd/export/)*
- SANS FOR577

### `analyze_unix_auth`
**Artifact:** `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL family)
**Purpose:** SSH, sudo, and PAM events. Brute-force, sudo-not-in-sudoers, su escalation, key-based vs password auth distinction.
**MITRE:** TA0006, TA0004
**References:**
- `pam(8)`, `sshd_config(5)` man pages
- SANS FOR577
- Hal Pomeranz — *Linux IR* talks (auth log forensics chapter)

### `parse_linux_cron_jobs`
Added in v0.6.1.
**Artifact:** `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, `/var/spool/cron/*`, `/etc/anacrontab`
**Purpose:** Scheduled-task persistence enumeration with attacker-pattern flagging — curl/wget-pipe-shell, base64 decode, eval, raw-IP URLs, darknet TLDs, netcat listeners, bash `/dev/tcp` redirects, `/tmp/*.sh`, `@reboot` triggers.
**MITRE:** T1053.003 (Cron), T1059.004 (Unix Shell), T1546 (Event Triggered Execution)
**Schema:** `evidence_root` (default `/`; point it at the mounted image root), `flagged_only` (default false), pagination via `cursor` + `limit` (default 500).
**References:**
- `crontab(5)`, `anacrontab(5)` man pages
- Red Hat — *RHEL Security Guide ch. 7*
- SANS FOR577

### `parse_linux_text_log`
Added in v0.7.1.
**Artifact:** Apache/nginx combined access log, syslog (RFC 3164), `/var/log/messages`, `/var/log/secure`, auditd dispatcher text mode
**Purpose:** Auto-detects log format from line shape, parses structured records (`max_records` default 5000, max 100000), applies 10 suspicious-content patterns plus a scanner-user-agent meta-rule.
**MITRE:** T1003.008 (`/etc/shadow` read), T1190 (path traversal + SQLi), T1505.003 (webshell patterns), T1105 (remote download to shell), T1071.001 (netcat), T1046 (scanner invocation), T1222.002 (dangerous chmod), T1059.004 (reverse-shell oneliners), T1213.002 (database credential use), T1595.002 (scanner UA observed)
**References:**
- Apache `mod_log_config` — combined log format
- RFC 3164 — *The BSD syslog Protocol*
- auditd dispatcher text-mode output (`/etc/audisp/audispd.conf`)

### `parse_linux_shell_history`
Added in v0.7.1.
**Artifact:** bash/zsh history files (with `HISTTIMEFORMAT` epoch comment lines if enabled)
**Purpose:** Per-command attacker-pattern detection — sensitive file reads, world-writable execs, netcat listeners, reverse-shell oneliners, SSH key persistence, history clearing, cron mutation, base64 obfuscation, database credential use, scanner invocation.
**MITRE:** T1059.004 (Unix Shell), T1003.008 (Credentials from Files), T1098.004 (SSH Authorized Keys), T1070.003 (Clear Command History), T1053.003 (Cron), T1027 (Obfuscated Files), T1046 (Network Service Discovery), T1071.001 (Application Layer Protocol)
**References:**
- `bash(1)` — `HISTTIMEFORMAT` semantics
- MITRE ATT&CK — T1070.003, T1098.004, T1059.004
- Hal Pomeranz — *Linux IR* (history forensics)

---

## Linux + macOS shared

### `parse_bash_history`
Added in v0.4.
**Artifact:** `~/.bash_history`, `~/.zsh_history`
**Purpose:** Shell history with attacker-pattern detection — encoded payloads, reverse shells, SSH key insertion, history clearing (T1070.003), kernel-module load.
**MITRE:** TA0002 (T1059.004 Unix Shell), TA0005 (T1070.003), TA0003 (T1098.004), TA0001 (T1105 Ingress Tool Transfer)
**References:**
- MITRE ATT&CK — T1059.004, T1070.003, T1098.004
- SANS FOR577 — *Linux IR*
- Atomic Red Team — `T1059.004` test corpus (matched by the pattern set)

### `grep_shell_history_for_c2`
Added in v0.6.0 (supply-chain IOC sweep).
**Artifact:** Shell history files — `.zsh_history`, `.bash_history`, `.python_history`
**Purpose:** Searches shell history for known C2 domains and supply-chain post-install reconnaissance / exfiltration commands (litellm.cloud, pastebin and similar). Accepts `extra_patterns` (additional regexes) and `limit` (default 200, max 5000).
**MITRE:** T1071 (Application Layer Protocol), T1059
**References:**
- MITRE ATT&CK — T1071, T1059

---

## Cross-platform

### `get_process_tree`
**Input:** process listing CSV from any OS (`tasklist /v /fo csv`, `ps -ef`, Sysmon/EDR export, etc.)
**Purpose:** Parent-child reasoning. Surfaces orphan processes, suspicious parents (`winword.exe → powershell.exe → cmd.exe`), and living-off-the-land patterns (PowerShell spawning cmd/wscript, cmd spawning three or more children).
**MITRE:** TA0002
**References:** SANS FOR508, MITRE ATT&CK T1059, Microsoft Sysmon (event-ID 1)

### `parse_browser_history`
**Input:** Chrome / Firefox / Safari / Edge SQLite history
**Purpose:** URL visits + download metadata across major browsers. Cross-OS because the SQLite schemas are identical regardless of host OS.
**MITRE:** TA0009 (T1185 Browser Session Hijacking indicators)
**References:**
- Hindsight — *[Chrome forensic tool](https://github.com/obsidianforensics/hindsight)*
- Magnet AXIOM forensic field guide — *Browser Artifacts*

### `analyze_downloads`
**Inputs:** browser history + filesystem (Mark-of-the-Web on Windows / quarantine xattrs on macOS)
**Purpose:** Downloaded-file provenance + MOTW analysis (T1553.005 — Mark-of-the-Web Bypass).
**MITRE:** TA0005, TA0009
**References:** MITRE ATT&CK T1553.005, Microsoft *Smart App Control* docs

### `correlate_download_to_execution`
**Inputs:** download records × execution evidence (Amcache / Prefetch / unified-log / auditd)
**Purpose:** "User downloaded X at T+0; X executed at T+N" correlation. Bridges Initial Access → Execution.
**MITRE:** TA0001 → TA0002 chain
**References:** SANS FOR508 case-study chapter on download-to-execution

### `detect_exfiltration`
**Inputs:** filesystem events (FSEvents / MFT) + network event log
**Purpose:** Bulk-archive creation followed by outbound transfer. Tunable thresholds.
**MITRE:** TA0010 (T1041 C2 Channel Exfil, T1567 Exfil Over Web Service)
**References:** MITRE ATT&CK Exfiltration tactic, Mandiant *M-Trends* report (annual exfil pattern catalog)

### `detect_credential_access`
**Inputs:** processes + Sysmon events
**Purpose:** LSASS-dumping (Mimikatz, comsvcs.dll LOLBin, ProcDump), SAM/NTDS extraction, registry credential paths.
**MITRE:** TA0006 (T1003.001 LSASS Memory, T1003.003 NTDS, T1003.002 Security Account Manager)
**References:**
- Microsoft — *[Mitigating Pass-the-Hash and Other Credential Theft](https://www.microsoft.com/en-us/download/details.aspx?id=36036)*
- SpecterOps — *[Mimikatz internals](https://posts.specterops.io/)*

### `detect_ransomware_behavior`
**Inputs:** processes + filesystem
**Purpose:** Mass-rename pattern, shadow-copy deletion (`vssadmin delete shadows`), ransom note write.
**MITRE:** TA0040 (T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery)
**References:**
- CISA — *[#StopRansomware Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)* (joint advisories with vendor TTP catalogs)

### `detect_defense_evasion`
**Inputs:** events + processes + MFT
**Purpose:** Event-log clearing (1102 / 104), timestomping ($SI/$FN), security-tool disable.
**MITRE:** TA0005 (T1070.001 Clear Logs, T1070.006 Timestomp, T1562.001 Disable Tools)
**References:** MITRE ATT&CK Defense Evasion tactic

### `detect_discovery`
**Input:** processes
**Purpose:** Burst detection of recon commands (`whoami / net user / nltest / Get-ADUser` etc.) within a small time window — flags scripted enumeration.
**MITRE:** TA0007 (T1087 Account Discovery, T1018 Remote System Discovery)
**References:** BloodHound team — *[BloodHound](https://github.com/BloodHoundAD/BloodHound)* attack-graph corpus

### `detect_privilege_escalation`
**Inputs:** logons + privilege events
**Purpose:** Cross-platform PrivEsc — Windows token manipulation (4672, 4674), Linux setuid syscall correlation.
**MITRE:** TA0004 (T1068, T1134, T1548)

### `analyze_web_access_log`
**Input:** Apache / Nginx / IIS access log (CLF or combined log format)
**Purpose:** SQLi, LFI, SSRF, Log4Shell, RCE, webshell-call signature matching.
**MITRE:** TA0001 (T1190 Exploit Public-Facing App)
**References:**
- OWASP — *[Top 10](https://owasp.org/Top10/)*
- Florian Roth — *[Web Shell signature collection](https://github.com/Neo23x0/signature-base)*
- Apache mod_security CRS rule corpus

### `detect_webshell`
**Inputs:** webroot directory listing + content heuristics
**Purpose:** Webshell detection via filename heuristics + content patterns + age anomaly (file written long after deployment).
**MITRE:** TA0003 (T1505.003 Web Shell)
**References:**
- Florian Roth — *[Web Shell signature-base](https://github.com/Neo23x0/signature-base/tree/master/yara)*
- MITRE ATT&CK — *[T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)*

### `correlate_events`
**Inputs:** `hypothesis_id`, `usb_events`, `logon_events`, `proximity_seconds` (default 600)
**Purpose:** Hypothesis-tied proximity join (USB insertion ↔ logon). Surfaces contradictions as `UNRESOLVED` rather than smoothing them over. Kept for backward compatibility; `correlate_timeline` is the general engine.
**Reference:** dfir-corr design notes ([`dfir_corr/README.md`](../dfir_corr/README.md)) + [Architecture](./architecture.md)

### `correlate_timeline`
**Inputs:** `events` (any list of event dicts), optional `rules`, `window_seconds` (default 300)
**Purpose:** Multi-source time-proximity correlation engine, DuckDB-backed for large datasets. Joins N artifact streams within a configurable window on shared actor or target.
**Reference:** DuckDB for in-process analytics + correlation rule pack ([`dfir_corr/correlation-rules.yaml`](../dfir_corr/correlation-rules.yaml))

### `detect_credential_file_access`
Added in v0.6.0 (supply-chain IOC sweep).
**Input:** `home_root` — a user home directory
**Purpose:** Reports atime/mtime/ctime for credential files (SSH / AWS / GCP / Azure / kubeconfig / `.env`) under the home directory — sudden access right after a suspicious package install is a strong supply-chain exfiltration signal.
**MITRE:** T1552 (Unsecured Credentials)

### `scan_pth_files_for_supply_chain_iocs`
Added in v0.6.0 (supply-chain IOC sweep).
**Input:** a Python `site-packages` tree
**Purpose:** Scans for `.pth` files with known-malicious basenames or suspicious content (the litellm 2026-03 pattern and generic `.pth`-based persistence).
**MITRE:** T1195.002 (Compromise Software Supply Chain), T1547 (Boot or Logon Autostart Execution)

### `detect_nodejs_install_hooks`
Added in v0.6.0 (supply-chain IOC sweep).
**Input:** a directory tree containing `package.json` files
**Purpose:** Extracts `preinstall` / `postinstall` / `install` scripts — a primary npm supply-chain vector (eslint-scope 2018, ua-parser-js 2021, node-ipc 2022).
**MITRE:** T1195.002, T1059.007 (JavaScript)

### `detect_pypi_typosquatting`
Added in v0.6.0 (supply-chain IOC sweep).
**Input:** a Python `site-packages` tree
**Purpose:** Flags entries whose names are Levenshtein distance 1–2 from high-value PyPI packages, indicating possible typosquatting.
**MITRE:** T1195.002

### `detect_python_backdoor_persistence`
Added in v0.6.0 (supply-chain IOC sweep).
**Input:** home directories
**Purpose:** Checks known backdoor persistence locations (the litellm `~/.config/sysmon` / `sysmon.py` pattern, systemd user services, macOS LaunchAgents, Linux cron) abused by supply-chain attacks.
**MITRE:** T1547, T1053.003, T1543

### `match_sigma_rules`
Added in v1.1.0 with Sigma pack v1; pack v2 (11 rules) shipped in v1.2.0.
**Input:** `event_log_path` — a parsed JSONL event log (one JSON event per line, under the evidence root); optional `limit` (default 200, max 2000)
**Purpose:** Scans the events against the consolidated Sigma detection pack in [`dfir_sigma/`](../dfir_sigma/README.md) and returns signature matches with their MITRE ATT&CK tags. Use it to corroborate a finding with a known detection pattern — an HID/keyboard USB insertion (T1200) or a suspicious scheduled task (T1053.005). Rules are general patterns, not case answers.
**MITRE:** Cross-tactic — the tags come from the matched rules (DCSync, Golden Ticket, Kerberoasting, AS-REP roasting, event-log clearing, ransomware shadow deletion, HID device insertion, remote execution, suspicious scheduled task, user account creation, webshell creation).
**References:**
- SigmaHQ — *[Sigma rule specification](https://github.com/SigmaHQ/sigma)*
- [`dfir_sigma/README.md`](../dfir_sigma/README.md) — the pack and its versioning

---

## What is **not** on the surface

To make the boundary explicit, here are functions a general-purpose agent might want, that **do not exist** on the Agentic-DFIR surface:

| Forbidden function | Why excluded |
|---|---|
| `execute_shell` / `system` / `spawn_process` | Architectural — destructive verb |
| `eval` / `exec_python` | Architectural — code-execution escape |
| `write_file` / `delete_file` | Architectural — evidence-tampering risk |
| `mount` / `umount` | Architectural — modifies host state |
| `network_egress` / `curl` / `wget` | Out-of-scope — agent does not touch network |
| `kill_process` / `terminate` | Out-of-scope — Phase 3 (agentic SOC) with human approval gate; see [Roadmap](./roadmap.md) |
| `volatility_summary` | Never shipped as a free-form summary. Memory analysis is reached only through the 12 typed `sift_vol3_*` adapters |
| `parse_evtx` (raw EVTX, native) | Native path is `analyze_event_logs` on pre-extracted JSON; raw EVTX is reached through the typed `sift_evtxecmd_parse` adapter |
| `duckdb_timeline_correlate` (raw SQL) | Replaced by typed `correlate_timeline` for safety |

The negative set is asserted by tests: `tests/test_mcp_surface.py::test_destructive_functions_are_not_exposed` checks the forbidden names, and `tests/test_mcp_bypass.py::test_surface_is_exact_positive_and_negative_set` asserts both the exact positive set (all 73 names) and the negative set (`execute_shell`, `write_file`, `mount`, `umount`, `eval`, `exec_python`, `network_egress`, `delete_file`, `system`, `spawn_process`, `kill_process`). If any of the above appear on the surface, those tests fail.

---

## Operator notes

- All functions accept paths **relative to** `DFIR_EVIDENCE_ROOT` (default `/mnt/evidence`). `_safe_resolve` resolves the path under that root and raises `PathTraversalAttempt` for anything that resolves outside it (`..` traversal, absolute escapes such as `/etc/passwd`), for null bytes, for empty paths, and for paths longer than 1024 characters. The check runs before any file is opened.
- Output is JSON-serializable. Cursors / pagination via `cursor` + `limit` arguments where the underlying artifact can be huge.
- Every successful call appends an entry to the run's `audit.jsonl` (written next to the run output by `dfir_agent`) with SHA-256 chaining (see [Architecture](./architecture.md)). Verify a chain with `python -m dfir_audit verify <audit.jsonl>`.
- Functions that hit a missing artifact return `{"error": "file_not_found", "path": "..."}` (several add a `hint`, e.g. the sidecar command to run) instead of raising — this lets the agent revise its hypothesis rather than crash.
- The advertised JSON Schema is enforced: `call_tool()` validates arguments against each function's `inputSchema` before dispatch, so malformed arguments cannot bypass the documented surface.

For extending the surface, see [`CONTRIBUTING.md`](../CONTRIBUTING.md). New functions must be (1) typed (Pydantic / JSON schema), (2) read-only (`_safe_resolve` for any path arg), (3) covered by a bypass test, and (4) referenced to a published source.

## See also

- [SIFT Workstation adapter layer](./sift-adapter-layer.md) — the 25 `sift_*` adapters, binary resolution and the adapter contract
- [Platform support](./platform-support.md) — analysis-target matrix, functions by platform, MITRE ATT&CK coverage
- [Architecture](./architecture.md) — the read-only MCP boundary and the audit chain
- [Threat model](./threat-model.md) — what the boundary defends against
- [dfir-mcp package README](../dfir_mcp/README.md) — server, stdio transport, registry
- [Sigma pack](../dfir_sigma/README.md) — the rules behind `match_sigma_rules`
