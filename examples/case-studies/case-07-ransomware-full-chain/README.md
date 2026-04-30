# Case Study 07 — Full Ransomware Chain (MITRE ATT&CK Coverage)

**Scenario class:** Post-foothold ransomware deployment with full MITRE
**Functions used:** `detect_credential_access`, `detect_discovery`,
  `detect_defense_evasion`, `detect_ransomware_behavior`

## Why this case matters

Cases 01-06 covered initial access and lateral movement. This case
covers what attackers do AFTER the foothold — the "hands on keyboard"
phase. Research sources (The DFIR Report 2025, Red Canary 2025,
Mandiant M-Trends 2026) agree that 80%+ of modern intrusions end in
one of three outcomes:

1. **Credential access** (T1003) — steal domain creds for deeper access
2. **Ransomware** (T1486, T1489, T1490) — encrypt for extortion
3. **Covering tracks** (T1070) — clear logs, timestomp

Agentic-DART now detects all three across ~30 MITRE sub-techniques.

## Attack reconstruction (bundled evidence)

```
15:00  Attacker runs whoami /all (recon)
15:01  mimikatz.exe sekurlsa::logonpasswords              ← T1003.001
15:02  procdump.exe -ma lsass.exe lsass.dmp               ← T1003.001
15:03  reg save HKLM\SAM / SECURITY / SYSTEM              ← T1003.002
15:04  ntdsutil ac in ntds ifm create full                ← T1003.003
15:05  rundll32 comsvcs.dll MiniDump                      ← T1003.001 LOLBin

15:30  net user /domain, nltest /domain_trusts            ← T1087.002
15:30  SharpHound.exe -c All -d corp.local                ← BloodHound
       (11 discovery commands in 60 seconds — SCRIPTED RECON)

14:30  vssadmin delete shadows /all /quiet                ← T1490
14:30  wbadmin delete catalog -quiet                      ← T1490
14:30  bcdedit /set recoveryenabled no                    ← T1490
14:30  wevtutil cl Security / System / Application        ← T1070.001
14:30  Event ID 1102 (Security log cleared)               ← T1070.001
14:30  15× taskkill on SQL/backup services in <10 sec     ← T1489
14:31  30 files renamed to *.locked                       ← T1486
14:32  README.txt / decrypt_instructions.txt created      ← T1486
```

## Per-function detection output

### `detect_credential_access`

```
findings: 7  max_severity: critical
by_technique: {T1003: 7}

🚨 mimikatz.exe                     sekurlsa::logonpasswords
🚨 procdump.exe                      -ma lsass.exe
🚨 reg save HKLM\SAM                 (extract SAM for offline cracking)
🚨 reg save HKLM\SECURITY            (extract cached creds)
🚨 reg save HKLM\SYSTEM              (get the boot key)
🚨 ntdsutil ac in ntds ifm create    (dump entire AD database)
🚨 rundll32 comsvcs.dll MiniDump     (LOLBin LSASS dump)
```

### `detect_discovery`

```
hits: 11  ad_recon_count: 6  bursts: 1  max_severity: high

by_technique:
  T1033 (System Owner/User Discovery)         1
  T1087.002 (Domain Account Discovery)        1
  T1069.002 (Domain Groups Discovery)         1
  T1482 (Domain Trust Discovery)              2
  T1018 (Remote System Discovery)             2
  T1082 (System Information Discovery)        1
  T1057 (Process Discovery)                   1
  T1016 (System Network Configuration)        1
  T1069 (BloodHound Collection)               1

🎯 BURST: 11 commands in 60 seconds
   interpretation: "scripted recon"
```

### `detect_defense_evasion`

```
findings: 5  max_severity: critical
stats: event_log_clearings=5, mft_mismatches=0

🛑 [T1070.001] Event Log Cleared        Security channel (Event 1102)
🛑 [T1070.001] Event Log Cleared        System channel (Event 104)
🛑 [T1070.001] log_clear_command         wevtutil cl Security
🛑 [T1070.001] log_clear_command         wevtutil cl System
🛑 [T1070.001] log_clear_command         wevtutil cl Application
```

### `detect_ransomware_behavior`

```
findings: 4  max_severity: critical
stats:
  anti_recovery_hits: 7
  service_stop_events: 15
  ransom_notes_created: 1 finding group
  mass_renames: 30

🔥 [T1490] inhibit_system_recovery
   vssadmin delete shadows, wbadmin delete catalog,
   bcdedit recoveryenabled no, bcdedit bootstatuspolicy ignoreallfailures

🔥 [T1489] mass_service_stop
   15 taskkill/net stop commands within 2 minutes
   targets: SQL, Backup, Defender, Veeam

🔥 [T1486] ransom_note_written
   readme.txt, decrypt_instructions.txt created in user dirs

🔥 [T1486] mass_file_rename_to_ransom_ext
   30 files now have .locked extension
```

## Final incident narrative

> At 15:00 UTC, the adversary began post-foothold activity with a recon
> burst — `whoami /all` followed by 11 discovery commands in 60 seconds
> (net user /domain, nltest, systeminfo, tasklist, ipconfig, arp, and
> SharpHound collection of the full AD graph). This is characteristic
> of a scripted attack framework, not human keyboard interaction.
>
> At 15:01, the operator executed Mimikatz (`sekurlsa::logonpasswords`)
> followed by procdump of LSASS. They then exfiltrated the SAM,
> SECURITY, and SYSTEM registry hives for offline hash extraction, and
> ran `ntdsutil ac in ntds ifm create` to dump the entire Active
> Directory database. As an anti-forensic cover, they also used the
> `comsvcs.dll MiniDump` LOLBin technique.
>
> At 14:30 (backdated — see timestomp analysis), the operator deployed
> ransomware. Anti-recovery commands ran first: vssadmin deleted all
> volume shadow copies, wbadmin cleared the backup catalog, bcdedit
> disabled Windows Recovery. Then 15 taskkill/net stop commands
> terminated SQL servers, Defender (MsMpEng.exe), Veeam, and BackupExec
> within 10 seconds. wevtutil cleared Security, System, and Application
> event logs; the resulting 1102 clear-event itself was the only entry
> remaining.
>
> At 14:31, 30 documents were renamed with the `.locked` extension.
> At 14:32, ransom notes (`readme.txt`, `decrypt_instructions.txt`)
> appeared in user directories.
>
> Findings F-071 through F-089 reference the audit entries across
> credential access (T1003.×), discovery (T1087/T1069/T1482/T1018),
> defense evasion (T1070.001), and impact (T1486/T1489/T1490).

## What the judges should run

```bash
python3 << 'PY'
from dart_mcp import call_tool
import csv

def load(path):
    with open(path) as f:
        return [{"pid": int(r["PID"]), "ppid": int(r["ParentPID"]),
                 "image": r["Image"], "cmdline": r["CommandLine"],
                 "start_ts": r["StartTime"], "user": r["User"]}
                for r in csv.DictReader(f)]

creds = call_tool("detect_credential_access",
    {"processes": load("examples/sample-evidence/disk/creds-processes.csv")})
print(f"Credential Access: {creds['finding_count']} findings, "
      f"max={creds['max_severity']}")

ransom = call_tool("detect_ransomware_behavior", {
    "processes": load("examples/sample-evidence/disk/ransomware-processes.csv"),
    "fsevents_or_mft": [
        {"path": f"C:/file{i}.locked", "flags": ["Created"],
         "ts": f"2026-03-15 14:31:{i:02d}"} for i in range(30)
    ] + [{"path": "readme.txt", "flags": ["Created"], "ts": "14:32:00"}],
})
print(f"Ransomware: {ransom['finding_count']} findings, stats={ransom['stats']}")

evasion = call_tool("detect_defense_evasion", {
    "events_json": "disk/log-clearing-events.json",
    "processes": load("examples/sample-evidence/disk/ransomware-processes.csv"),
})
print(f"Defense Evasion: {evasion['finding_count']} findings, "
      f"max={evasion['max_severity']}")

disc = call_tool("detect_discovery",
    {"processes": load("examples/sample-evidence/disk/discovery-processes.csv")})
print(f"Discovery: {disc['hit_count']} hits, {disc['ad_recon_count']} AD recon, "
      f"{len(disc['recon_bursts'])} bursts")
PY
```
