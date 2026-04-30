# Case Study 03 — macOS Remote-Admin Infection + Exfiltration

**Scenario class:** macOS insider threat, unsigned "remote admin" app + staged exfil
**Evidence:** bundled at `examples/sample-evidence/mac/`
**Functions used:** `parse_unified_log`, `parse_knowledgec`, `parse_fsevents`
**Platform proof:** this case runs identically on Linux and macOS

## The attack pattern

A user downloads an "IT helper" app that is actually a remote administration
tool. The macOS-specific signals:

- **TCC denial** — the app tried to take a screenshot without authorization
- **Gatekeeper translocation** — macOS moved the app to a quarantine path
  (a benign-but-suspicious signal)
- **launchd daemon** dropped in `~/Library/LaunchAgents` (persistence)
- **XProtect signature match** on a second-stage binary in `/private/tmp/`
- **SSH brute-force** from external IP against the same machine

The staged exfiltration leaves telltale FSEvents: create + delete of
archive files in `/var/folders/.../TemporaryItems/`.

## Agentic-DART walkthrough

### Iteration 1 — UnifiedLog ingestion

`parse_unified_log('mac/private/var/db/diagnostics/unifiedlog.ndjson')` on
the bundled evidence returns **7 alerts**:

| Severity | Rule | Notes |
|---|---|---|
| high | `xprotect_detection` | MACOS.ATTACKWARE.C in `/private/tmp/stage2.bin` |
| high | `tcc_bypass_attempt` | RemoteAdmin denied ScreenCapture |
| high | `launchd_daemon_load` | `~/Library/LaunchAgents/com.remotehands.helper.plist` |
| medium | `gatekeeper_override` | App translocation event |
| medium (x3) | `ssh_auth_failure` | Brute force from 203.0.113.42 |

### Iteration 2 — Corroborate with KnowledgeC

`parse_knowledgec('mac/Users/jbang/Library/Application Support/Knowledge/knowledgeC.db')`
returns user activity:

- `com.apple.Terminal` — 3 focus events during the attack window
- `com.apple.Safari` — 1 brief session (drop site?)
- Device transitioned locked → unlocked at 14:22 (matches IP-KVM window
  from Case 01 — potential Case 01 + Case 03 linkage!)

### Iteration 3 — FSEvents for file-op reconstruction

`parse_fsevents('mac/fsevents.csv')` surfaces **5 suspicious paths**:

| Path | Flags | Diagnostic |
|---|---|---|
| `/private/tmp/stage2.bin` | Created, Modified | Dropped second stage |
| `/private/tmp/stage2.bin` | Removed | Cleanup after exec |
| `/var/folders/.../exfil.zip` | Created, Modified | Staged exfil |
| `/var/folders/.../exfil.zip` | Removed | Cleanup |
| `/Users/Shared/tools/mimikatz-mac` | Created | Credential dumper |

The create-then-remove pattern in `/var/folders/` is the hallmark of
staged exfiltration — the file exists just long enough to be read by
an uploader, then removed.

### Iteration 4 — Cross-source correlation (via DuckDB)

```python
events = [
    {"ts": "2026-03-15 14:19:10", "source": "unifiedlog", "type": "tcc_deny",
     "actor": "/Applications/RemoteAdmin.app/..."},
    {"ts": "2026-03-15 14:22:00", "source": "knowledgec", "type": "device_unlock",
     "actor": "jbang"},
    {"ts": "2026-03-15 14:25:40", "source": "unifiedlog", "type": "xprotect",
     "target": "/private/tmp/stage2.bin"},
    {"ts": "2026-03-15 14:25:45", "source": "fsevents", "type": "file_create",
     "target": "/private/tmp/stage2.bin"},
]
call_tool("correlate_timeline", {"events": events, "window_seconds": 600})
```

Returns cross-source correlations linking the TCC denial → device unlock →
XProtect detection → FSEvents creation — a complete attack chain across
3 macOS data sources.

## What the judges should run

```bash
# macOS quickstart (works on Linux too)
bash examples/demo-run.sh

# Exercise each macOS function
python3 -c "
from dart_mcp import call_tool
import json

for name, args in [
    ('parse_unified_log', {'unifiedlog_json': 'mac/private/var/db/diagnostics/unifiedlog.ndjson'}),
    ('parse_knowledgec',  {'knowledgec_db': 'mac/Users/jbang/Library/Application Support/Knowledge/knowledgeC.db'}),
    ('parse_fsevents',    {'fsevents_csv': 'mac/fsevents.csv'}),
]:
    r = call_tool(name, args)
    if name == 'parse_unified_log':
        print(f'{name}: alerts={r[\"alerts_by_severity\"]}')
    elif name == 'parse_knowledgec':
        print(f'{name}: top_apps={r[\"top_apps_by_event_count\"][:3]}')
    elif name == 'parse_fsevents':
        print(f'{name}: suspicious={r[\"suspicious_path_count\"]}')
"
```
