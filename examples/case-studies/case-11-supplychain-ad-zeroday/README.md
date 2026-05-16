# Case Study 11 — Supply-Chain Entry → AD Certificate Services Abuse → Lateral Movement

**Scenario class:** The "HOW DID THEY GET DOMAIN ADMIN" investigation — trojanized signed vendor binary + ESC8 + DCSync + Golden Ticket
**Evidence:** bundled across `examples/sample-evidence-realistic/disk/` (supplychain-security-events.json, supplychain-processes.csv, supplychain-network.json)
**Functions used:** `get_process_tree`, `analyze_windows_logons`,
  `analyze_kerberos_events`, `detect_lateral_movement`,
  `detect_credential_access`, `detect_persistence`,
  `detect_defense_evasion`, `detect_exfiltration`
**Reproduce:** Case 01 ships in the bundled demo; Case 11 is exercised by direct MCP invocation. See "How to invoke" at the end of this page.

## Why this case matters

Case 05 covered AD compromise from a **stolen credential** (SSH key → SMB
brute force → Kerberoasting). That is the "outside attacker who phished
or cracked their way in" pattern.

Case 11 covers a different and increasingly common attack class:
**software supply-chain compromise**, where the attacker never touches
the front door. Instead, a signed binary from a trusted vendor is
trojanized upstream and lands inside the perimeter as a normal software
update.

After foothold, the attacker abuses **Active Directory Certificate
Services (ADCS)** — specifically the **ESC8** misconfiguration where
the certificate Web Enrollment endpoint accepts NTLM authentication.
Combined with a **PetitPotam** coercion (CVE-2021-36942) to force the
domain controller's machine account to authenticate to a relay, the
attacker obtains a certificate for `DC01$`, then uses Kerberos PKINIT
+ S4U2self to impersonate a Domain Admin.

The full chain is reconstructed entirely from public references:

- **SolarWinds SUNBURST** (CISA AA20-352A, December 2020) — trojanized
  signed update payload via legitimate vendor channel.
- **APT29 / Cozy Bear** TTP — low-and-slow C2 beaconing with cadence
  designed to evade SIEM thresholds.
- **ESC8** (SpecterOps "Certified Pre-Owned", June 2021) — NTLM relay
  to ADCS HTTP enrollment endpoint.
- **PetitPotam** (CVE-2021-36942) — MS-EFSRPC abuse to coerce machine
  account authentication.
- **BloodHound** attack-path mapping — `AddMember` / `DCSync` /
  `GenericAll` graph traversal.
- **AdminSDHolder** abuse (Microsoft KB 232199) — SDProp re-applies the
  attacker's ACL every 60 minutes to every protected admin group.
- **Golden Ticket** (MITRE T1558.001) — forged TGT signed with the
  KRBTGT NTLM hash extracted via DCSync.

> **case-05 vs case-11 — explicit differentiation:** no shared host,
> IP, account, timestamp, or domain. case-05 = `corp.local` /
> 2026-03-15 / brute-force-then-Kerberoast. case-11 =
> `ent.example.local` / 2026-04-21 / trojanized-vendor-then-ESC8.

## Attack reconstruction (bundled evidence)

```
─── TIME-1 (Day 0, supply-chain foothold) ────────────────────────────
02:14:08  VeloLink-Agent.exe (PID 4012) starts as SYSTEM service          ← trojanized signed binary
02:14:53  └─ rundll32.exe loads VeloLink.SecureCore.dll, ExecutePolicy    ← T1055 process injection
02:15:30     └─ svchost.exe child process (-k netsvcs VeloLinkUpdater)
02:18:11        First C2 beacon: 10.50.10.40 → 198.51.100.62              ← T1071.001 / APT29-style cadence
                (telemetry-velolink-cdn.com, 412 bytes recv, every ~8min)

─── TIME-2 (Day 0, ESC8: NTLM relay → ADCS) ──────────────────────────
02:42:01  PetitPotam.exe -d ENT.EXAMPLE.LOCAL ANONYMOUS                   ← T1187 forced auth
02:42:01  ntlmrelayx.py -t http://CA01/certsrv --adcs --template DomainController
02:42:04  4624 type-3: DC01$ → CA01 from 10.50.10.40 (relay landed)
02:42:07  Certificate issued for DC01$ (ADCS 4886/4887 NOT centralized → GAP)
02:42:32  4768: TGT for DC01$ with PKINIT (PreAuth=16, AES256)            ← T1649
          └─ IpAddress=10.50.10.40 (anomalous — DC01 should auth from 10.50.10.10)
02:43-45  Three more 4768 PKINIT events for DC01$ from different sources
          → users_with_scattered_tgts triggers (>3 distinct IPs)

─── TIME-3 (Day 0, DA impersonation + DCSync) ────────────────────────
03:05:14  Rubeus.exe s4u /impersonateuser:domadmin /msdsspn:cifs/DC01    ← T1550.003
03:05:14  4624 type 9 (NewCredentials) on DC01 — Subject:DC01$ → domadmin
03:05:48  PsExec \\DC01 -u domadmin (PID 4420)                            ← T1021.002
03:06:21  PsExec \\FS-DATA-02 -u domadmin (lateral 2)
03:07:15  wmiexec.py -hashes :8846f7eaee... domadmin@WS-FIN-09             ← T1550.002 overpass-the-hash
03:08:42  ntdsutil "ac in ntds" "ifm" "create full c:\temp\ntds"           ← T1003.003 NTDS dump
03:09:05  mimikatz lsadump::dcsync /user:krbtgt                            ← T1003.006 KRBTGT theft
03:09:30  mimikatz sekurlsa::logonpasswords                                ← T1003.001
03:11:14  dsacls AdminSDHolder /G "ENT\svc-velolink:GA"                    ← T1098.005 SDProp persistence

─── TIME-4 (Day 1, persistence + cleanup) ────────────────────────────
09:11:37  4768 for krbtgt (PreAuth=0, RC4)                                 ← T1558.001 Golden Ticket
09:12:08  schtasks /create /tn MicrosoftEdgeUpdateCore /tr update.dll      ← persistence cover
09:15:00  wevtutil cl Security / System / Application (3×)                 ← T1070.001 log clearing
09:15:00  EventID 1102 self-emitted on MGMT-VELO-01 (ironic giveaway)
```

## Per-function detection output

### `get_process_tree` — supply-chain foothold

```
PID 4012  VeloLink-Agent.exe                          (SYSTEM)
  └─ PID 4088  rundll32.exe VeloLink.SecureCore.dll   ← vendor binary as parent of rundll32 = anomaly
       └─ PID 4112  svchost.exe -k netsvcs VeloLinkUpdater
            ├─ PID 4188  PetitPotam.exe               ← coercion tool
            ├─ PID 4192  ntlmrelayx.py --adcs         ← ESC8 relay
            ├─ PID 4256  Rubeus.exe asktgt /certificate:dc01.pfx
            ├─ PID 4318  Rubeus.exe s4u /impersonateuser:domadmin
            ├─ PID 4420  PsExec \\DC01 -u domadmin
            ├─ PID 4488  PsExec \\FS-DATA-02 -u domadmin
            └─ PID 4552  python wmiexec.py -hashes :xxxx
```

**Why vendor-binary-as-rundll32-parent matters:** signed vendor binaries
should call into their own subprocesses (updater, telemetry), not load
arbitrary DLLs via the LOLBin rundll32. This is the same pattern that
made SUNBURST detectable in retrospect.

### `analyze_windows_logons` — type-9 NewCredentials on DC

```
events_examined: 22
by_logon_type:
  "5 (Service)":            1   ← initial VeloLink service boot
  "3 (Network)":            4   ← PSExec/WMI landings on DC/FS/WS + relay
  "9 (NewCredentials)":     1   ← DC01: Subject=DC01$ → impersonating
                                  domadmin via Kerberos PKINIT (S4U2self)
  "10 (RemoteInteractive)": 1   ← persistence RDP next day

failure_count: 0  explicit_cred_count: 0  unique_remote_source_ips: 1
```

**Why type-9 on a DC is a smoking gun:** logon type 9 (NewCredentials)
is `RunAs /netonly`-equivalent — it executes locally with one identity
while presenting different credentials over the network. Type-9 on a
DC with Subject=`DC01$` and Target=a domain admin almost never has a
legitimate explanation. The PKINIT auth-package on this event ties it
back to the cert obtained via ESC8. Note `explicit_cred_count=0`: the
attacker did not use the classic 4648 explicit-cred logon route
(that's case-05's signature) — they used PKINIT, which is invisible
to that counter and visible only via the type-9 + 4768/PKINIT
combination.

### `analyze_kerberos_events` — PKINIT anomaly + Golden Ticket

```
events_examined: 22  max_severity: high

scattered_tgts (DC01$ requested TGTs from 4 distinct sources in 3 min):
  user: dc01$
  source_count: 4
  sources: ["10.50.10.40", "10.50.20.52", "10.50.30.7", "10.50.40.89"]

asrep_roasting_candidates (Golden Ticket side-channel):
  {user: "krbtgt", source_ip: "10.50.10.40",
   ts: "2026-04-22 09:11:37.226",
   interpretation: "TGT with no pre-auth — AS-REP Roasting"}
  ← krbtgt user with PreAuth=0 = forged TGT artefact, not legitimate AS-REP roasting
```

**Why this is the case-11 detection breakthrough:** scattered_tgts > 3
is the only generic Kerberos check that catches ESC8 today — once
DC01$ has been certified, the attacker uses that ticket from wherever
they like, so the source IPs scatter while the user stays constant.

### `detect_lateral_movement` — fan-out from supply-chain host

```
remote_admin_tool_hits: 3
  {tool: "psexec",  pid: 4420, cmdline: "PsExec.exe \\\\DC01 -u domadmin ..."}
  {tool: "psexec",  pid: 4488, cmdline: "PsExec.exe \\\\FS-DATA-02 -u domadmin ..."}
  {tool: "wmiexec", pid: 4552, cmdline: "wmiexec.py -hashes :8846f7eaee... WS-FIN-09"}

network_logon_count: 5   suspicious_pairs: 2

summary_by_tool: {"psexec": 2, "wmiexec": 1}
```

The two `suspicious_pairs` are the two `domadmin@10.50.10.40 → psexec`
launches that fired within 60 s of their preceding 4624 type-3 logon
on the target host (`DC01`, `FS-DATA-02`). The wmiexec landing on
`WS-FIN-09` proxies through Kerberos and arrives at the target on a
slightly larger delta — it is captured in `remote_admin_tool_hits`
but not paired by the 60 s proximity heuristic.

### `detect_credential_access` — DCSync + ntdsutil + mimikatz

```
findings: 3  max_severity: critical
by_technique: {T1003: 3}

🚨 ntdsutil.exe "ac in ntds" "ifm" "create full c:\temp\ntds"   T1003.003
🚨 mimikatz lsadump::dcsync /user:ent.example.local\krbtgt      T1003.006
🚨 mimikatz sekurlsa::logonpasswords                            T1003.001
```

*(PetitPotam + ntlmrelayx + Rubeus do not match `detect_credential_access`'s
LSASS-centric T1003 patterns; they surface via `get_process_tree` flags
and the F-SC-003/F-SC-004 narrative below. The ESC8 chain is the
case-11 detection-gap callout, not a built-in technique signature.)*

### `detect_persistence` — AdminSDHolder + scheduled task

`detect_persistence` auto-scans registry Run keys, Windows services,
and the scheduled-task store inside the evidence root. Neither
AdminSDHolder ACL changes (DSA directory-service object) nor `schtasks.exe`-emitted
tasks land in those three sources, so both mechanisms surface via the
process tree (`supplychain-processes.csv`) and are reported as
narrative findings F-SC-010 and the persistence half of F-SC-011:

```
(narrative — visible in get_process_tree output, not detect_persistence)

🚨 PID 4780  dsacls.exe CN=AdminSDHolder,...  /G "ENT\svc-velolink:GA"   T1098.005
   └─ SDProp re-applies this ACE every 60 min to all                ← self-healing
      protected admin groups (Domain Admins, Enterprise Admins,
      etc.). Removing one access grant will NOT remove the attacker.

🚨 PID 4830  schtasks /create /tn MicrosoftEdgeUpdateCore /tr        T1053.005
              rundll32 C:\ProgramData\velolink\update.dll
   └─ Disguised as Edge updater; runs daily as SYSTEM.
```

**Why this is a detection-gap callout:** AdminSDHolder is the single
most under-monitored AD persistence vector. Detecting it requires
either DS Object Access auditing (4662) on the AdminSDHolder
container, or process-tree analysis of `dsacls.exe` / `ldifde.exe`
invocations as in case-11. The current `detect_persistence` function
does not parse 4662 events; that work is tracked post-SANS.

### `detect_defense_evasion` — log clearing on initial-access host

```
findings: 4  max_severity: critical

🚨 EventID 1102 self-emitted on MGMT-VELO-01          T1070.001
   └─ rule: event_log_cleared, channel: Security
🚨 wevtutil.exe cl Security                           T1070.001
🚨 wevtutil.exe cl System                             T1070.001
🚨 wevtutil.exe cl Application                        T1070.001

Note: cleared only on MGMT-VELO-01 (initial-access host) — the
attacker missed the DCs and file servers. The DC trail survives.
```

## Detection gaps the case-11 walkthrough exposes

Three gaps are intentionally embedded so reviewers see what the agent
does NOT currently catch — and where SOC engineering should invest:

| Gap | Why it matters | Mitigation |
|-----|----------------|------------|
| ADCS 4886/4887 not centralized | The cert issuance is the pivotal moment but the event lives only on CA01 local log. Without forwarding, agent sees only the downstream PKINIT 4768 anomaly. | Forward `Microsoft-Windows-CertificationAuthority/Operational` to SIEM; alert on 4887 from non-DC source IPs. |
| ADCS Web Enrollment accepts NTLM | The CVE-free root cause of ESC8. Microsoft KB5005413 added the EPA enforcement registry switch, but it is off by default on pre-2022 CAs. | Enable Extended Protection for Authentication (EPA) on `certsrv`; remove HTTP, enforce HTTPS-only with channel binding. |
| Type-9 logon not standardly alerted | Most SIEM rules focus on type-3/4624 and type-10 RDP. Type-9 (NewCredentials) is rare in benign traffic and almost always interesting on a DC. | Add a high-fidelity Sigma rule: `event_id=4624 AND logon_type=9 AND host=domain_controller`. |

## Complete narrative for the incident report

> On 2026-04-21 at 02:14 UTC, the attacker's payload landed on host
> `MGMT-VELO-01` (10.50.10.40) — an internal management server for
> the `VeloLink` IT-asset SaaS platform. The trigger was a routine
> vendor agent update; the update payload (`VeloLink-Agent.exe` and
> the `VeloLink.SecureCore.dll` module) carried a valid code-signature
> from `VeloLink Software CA`, indicating the compromise happened
> upstream of the customer environment — a software supply-chain
> intrusion in the SolarWinds SUNBURST mould.
>
> Within four minutes of launch, the trojanized DLL had spawned a
> child `svchost.exe` and was beaconing to `198.51.100.62`
> (`telemetry-velolink-cdn.com`) on an ~8-minute cadence with traffic
> volumes calibrated to slip under SIEM thresholds.
>
> Twenty-eight minutes later, the attacker pivoted to the Active
> Directory environment. They executed `PetitPotam.exe` to coerce the
> machine account `DC01$` to authenticate via MS-EFSRPC, and
> simultaneously ran `ntlmrelayx.py --adcs --template
> DomainController` to relay that authentication to the `CA01`
> Certificate Authority's HTTP Web Enrollment endpoint
> (`/certsrv/certfnsh.asp`). The CA — which had not been hardened
> against ESC8 — issued a certificate for `DC01$` under the
> `DomainController` template. `Rubeus.exe asktgt` requested a TGT
> using PKINIT with that certificate, and a second `Rubeus.exe s4u`
> call performed Service-for-User-to-self impersonation, producing a
> service ticket as `domadmin` for any service of the attacker's
> choosing.
>
> The Kerberos log shows the smoking gun: `EventID 4768` for
> `DC01$` arriving from `10.50.10.40` instead of `10.50.10.10`,
> with `TicketEncryptionType=0x12` and `PreAuthType=16` — the
> cert-based PKINIT signature. The same machine account received TGTs
> from four different source IPs within three minutes, tripping the
> `scattered_tgts > 3` detector.
>
> Armed with `domadmin` impersonation, the attacker performed
> hands-on lateral movement at 03:05–03:07: `PsExec` to `DC01` and
> `FS-DATA-02`, `wmiexec` overpass-the-hash to `WS-FIN-09`. On the
> DC they executed `ntdsutil ifm create full` to dump the entire AD
> database and ran `mimikatz lsadump::dcsync /user:krbtgt` to
> extract the KRBTGT NTLM hash — both belt-and-suspenders credential
> theft of the highest possible value.
>
> Persistence was layered: `dsacls.exe` granted
> `ENT\svc-velolink:GenericAll` over the `AdminSDHolder` container,
> which the SDProp process will re-apply to every protected admin
> group every 60 minutes — a self-healing privilege grant that no
> reactive ACL cleanup will eliminate. A scheduled task disguised as
> `MicrosoftEdgeUpdateCore` was created to re-run the trojanized
> module daily.
>
> The following morning at 09:11, a forged `Golden Ticket` for the
> KRBTGT user was used — the request landed as a `4768` with
> `PreAuthType=0` and RC4 encryption, an artefact pattern that
> doubles as an AS-REP-roasting trigger on the analyser. Three
> `wevtutil cl` commands cleared the Security, System, and
> Application logs on MGMT-VELO-01 at 09:15, generating one final
> `EventID 1102` before the host went quiet — but the attacker
> missed the DC and the file server, where the trail persists.
>
> Findings F-SC-001 through F-SC-012 reference the audit entries.
> Evidence SHA-256 hashes verified pre/post analysis.

## What makes this case important

Before case-11, the case library demonstrated detection on:

- attacker who **brute-forces in** (case-05)
- attacker who **phishes in** (case-04)
- attacker who **exploits the web tier and pivots** (case-06)
- attacker who **buys credentials and deploys ransomware** (case-07)

Case-11 demonstrates detection on **the supply-chain attacker who is
already inside before anyone realises a perimeter was breached**. The
investigation flips: instead of asking "who got in", the analyst asks
"which trusted binary did they ride in on" and "which AD
misconfiguration let them walk to Domain Admin".

The MCP function surface stays unchanged. What changes is the
evidence-narrative the analyst constructs from the same primitive
events — `4624`, `4768`, `4769`, process tree, network flows — when
the entry point is a signed vendor update rather than a stolen
password.

---

## How to invoke this case directly

```bash
# From the repo root
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src"
export DART_EVIDENCE_ROOT="$PWD/examples/sample-evidence-realistic"

python3 - <<'PY'
import csv, json
from pathlib import Path
from dart_mcp import call_tool

ROOT = Path("examples/sample-evidence-realistic")

# Load processes & network as in-memory lists for functions that
# expect parsed input (detect_lateral_movement / detect_credential_access
# / detect_defense_evasion / detect_exfiltration).
procs = []
with (ROOT / "disk/supplychain-processes.csv").open() as f:
    for row in csv.DictReader(f):
        procs.append({
            "pid": row["PID"], "ppid": row["ParentPID"],
            "Image": row["Image"], "CommandLine": row["CommandLine"],
            "start_ts": row["StartTime"], "user": row["User"],
        })

events = json.loads((ROOT / "disk/supplychain-security-events.json").read_text())
logons = [
    {"event_id": 4624,
     "user": e.get("user") or e.get("TargetUserName"),
     "logon_type": e.get("logon_type") or 0,
     "source_ip": e.get("source_ip") or e.get("IpAddress"),
     "ts": e.get("ts") or e.get("TimeCreated")}
    for e in events
    if e.get("event_id") == 4624 or e.get("EventID") == 4624
]
net = json.loads((ROOT / "disk/supplychain-network.json").read_text())

# ── Detections ────────────────────────────────────────────────────
r = call_tool('get_process_tree', {'process_csv': 'disk/supplychain-processes.csv'})
print('get_process_tree:', r['process_count'], 'procs in tree')

r = call_tool('analyze_windows_logons',
              {'security_events_json': 'disk/supplychain-security-events.json'})
print('analyze_windows_logons:', r['events_examined'], 'events,',
      r['by_logon_type'].get('9 (NewCredentials)', 0), 'type-9 NewCredentials')

r = call_tool('analyze_kerberos_events',
              {'security_events_json': 'disk/supplychain-security-events.json'})
print('analyze_kerberos_events:',
      r['stats']['scattered_tgt_users'], 'scattered_tgts user(s),',
      r['stats']['asrep_roasting_count'], 'as-rep (golden-ticket side-channel)')

r = call_tool('detect_lateral_movement', {'processes': procs, 'logons': logons})
print('detect_lateral_movement:',
      len(r['remote_admin_tool_hits']), 'remote-admin tools,',
      len(r['suspicious_pairs']), 'suspicious pairs')

r = call_tool('detect_credential_access', {'processes': procs})
print('detect_credential_access:',
      len(r.get('findings', [])), 'findings ({} max severity)'.format(r.get('max_severity')))

r = call_tool('detect_defense_evasion', {
    'events_json': 'disk/supplychain-security-events.json',
    'processes': procs})
print('detect_defense_evasion:',
      len(r.get('findings', [])), 'findings ({} max severity)'.format(r.get('max_severity')))

r = call_tool('detect_exfiltration', {'network_events': net})
print('detect_exfiltration:',
      len(r.get('signals', [])), 'signals ({} max severity)'.format(r.get('max_severity')))
PY
```

Expected output (deterministic on the bundled evidence):

```
get_process_tree:           21 procs in tree
analyze_windows_logons:     22 events, 1 type-9 NewCredentials
analyze_kerberos_events:    1 scattered_tgts user(s), 1 as-rep (golden-ticket side-channel)
detect_lateral_movement:    3 remote-admin tools, 2 suspicious pairs
detect_credential_access:   3 findings (critical max severity)
detect_defense_evasion:     4 findings (critical max severity)
detect_exfiltration:        1 signals (medium max severity)
```

Each function returns a typed dict; the printed values above are the
headline counts a SOC analyst looks at first. The full structured
output (with `source.path`, `source.sha256`, individual hit details,
MITRE technique IDs, severity, timestamps) is in the returned dict —
see [docs/accuracy-report.md](../../docs/accuracy-report.md) for the
full schema and measured recall/FPR.
