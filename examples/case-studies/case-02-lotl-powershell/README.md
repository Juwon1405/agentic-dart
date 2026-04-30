# Case Study 02 — Living-Off-the-Land (LOTL) PowerShell Attack

**Scenario class:** LOTL attack using signed Windows binaries to evade AV
**Evidence:** bundled in `examples/sample-evidence/` alongside Case 01
**Detection path:** process tree → event logs → persistence → correlate

## The attack pattern

LOTL attacks use **legitimate, signed Windows binaries** (powershell.exe,
cmd.exe, wscript.exe, certutil.exe) to perform malicious actions. No
custom malware. Traditional AV misses this pattern because every binary
is signed by Microsoft.

The diagnostic is in the **process tree shape and command-line content**:
- `powershell.exe` spawning `cmd.exe` is unusual for benign workflows
- `cmd.exe` spawning 3+ children within seconds indicates scripting
- Encoded PowerShell (`-enc`) is rare in legitimate use
- `IEX (New-Object Net.WebClient).DownloadString(...)` = download-and-exec

## How Agentic-DART walks this case

### Iteration 1 — Process tree reconstruction

`get_process_tree("disk/processes.csv")` returns the tree rooted at
explorer.exe. The agent surfaces **3 flags**:

| Rule | Parent | Child | Severity |
|------|--------|-------|----------|
| `powershell_spawns_shell` | powershell.exe (4812) | cmd.exe (4820) | medium |
| `powershell_spawns_shell` | powershell.exe (4812) | wscript.exe (4824) | medium |
| `cmd_spawns_many_children` | cmd.exe (4820) | net, net, reg (3 children) | low |

Combined, these are high-confidence LOTL indicators.

### Iteration 2 — Event log corroboration

`analyze_event_logs("disk/events.json")` finds:

- **Critical (1):** EventID 10 — LSASS access with GrantedAccess=0x1FFFFF (credential dumping)
- **High (1):** EventID 4104 — PowerShell download-and-execute pattern
- **Medium (2):** EventID 7045 (service install), EventID 4698 (scheduled task created)

### Iteration 3 — Persistence detection

`detect_persistence()` returns **3 HIGH-severity** findings:

- Registry Run key "SecurityUpdate" → `powershell -w hidden -c IEX(DownloadString(...))`
- Service "RemoteHandsHelper" → `C:\Users\analyst\AppData\Local\Temp\rhh.exe` (Temp path!)
- Scheduled task "RemoteHandsSync" (from Case 01)

### Iteration 4 — Cross-source correlation

`correlate_timeline(events=[...], window_seconds=300)` via DuckDB:

- **Cross-source hits:** 3 correlations between PowerShell script block and
  LSASS access (same actor, 2-minute window)
- **IP-KVM → logon pattern:** 1 hit (Case 01 reinforces Case 02 attribution)

### Result

Attack narrative assembled from 4 different evidence sources, all linked
by `dart-audit trace`:

```
IP-KVM inserted (Case 01)
  → Logon as analyst (3 min later)
  → explorer → powershell -enc (encoded command)
  → powershell → cmd (LOTL)
  → cmd → net user / net localgroup / reg add (account creation + persistence)
  → credential dumping via lsass access
  → persistence via service install + Run key
```

## What the judges should run

```bash
# Test each new function on its own
python3 -c "from dart_mcp import call_tool; import json; \
  print(json.dumps(call_tool('get_process_tree', {'process_csv': 'disk/processes.csv'})['flags'], indent=2))"

python3 -c "from dart_mcp import call_tool; import json; \
  r = call_tool('analyze_event_logs', {'events_json': 'disk/events.json'}); \
  print(json.dumps(r['alerts_by_severity'], indent=2))"

python3 -c "from dart_mcp import call_tool; import json; \
  r = call_tool('detect_persistence', {}); \
  print(json.dumps(r['by_mechanism'], indent=2))"
```

All return real data from the bundled evidence tree in <1 second.
