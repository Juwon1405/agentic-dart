# Running Agentic-DART on macOS

Agentic-DART is a pure Python 3.10+ project. The SANS SIFT Workstation is the
reference deployment target, but Agentic-DART **runs identically on macOS** — no
Linux-specific dependencies, no Docker required.

## 5-minute quickstart

```bash
# 1. Prerequisites (Python 3.10 or newer)
python3 --version    # 3.10.x, 3.11.x, 3.12.x all work

# If your system Python is older, install via Homebrew:
# brew install python@3.12

# 2. Clone
git clone https://github.com/Juwon1405/agentic-dart.git
cd agentic-dart

# 3. Install DuckDB (required by correlate_timeline)
pip3 install duckdb
# If you see "externally-managed-environment" on macOS 12.3+:
pip3 install duckdb --break-system-packages
# OR use a venv (cleaner):
# python3 -m venv .venv && source .venv/bin/activate && pip install duckdb

# 4. Run the bundled demo
export DART_EVIDENCE_ROOT="$PWD/examples/sample-evidence"
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"
bash examples/demo-run.sh
```

Expected output (identical on Linux and macOS):

```
[dart-agent] iterations: 5
[dart-agent] findings: 2
[dart-agent] audit chain: chain verified: 3 entries
[demo] PASS — "ToolNotFound: 'execute_shell' is not exposed by dart-mcp"
```

## Analyzing a real macOS system with Agentic-DART

Agentic-DART has three MCP functions specifically for macOS artifacts:

| Function | Source | How to produce input |
|---|---|---|
| `parse_unified_log` | `/private/var/db/diagnostics/*.tracev3` | `log show --style ndjson --start '2026-01-01' > unifiedlog.ndjson` |
| `parse_knowledgec` | `~/Library/Application Support/Knowledge/knowledgeC.db` | Direct SQLite read (read-only URI) — or CSV sidecar |
| `parse_fsevents` | `/.fseventsd/` binary journal | [FSEventsParser](https://github.com/dlcowen/FSEventsParser) — `FSEParser.py -c parsed -o out -s /.fseventsd` |

### Example: live triage of your own Mac

```bash
# 1. Capture current UnifiedLog to the evidence tree
mkdir -p /tmp/triage-evidence/mac/private/var/db/diagnostics
log show --style ndjson --last 24h \
  > /tmp/triage-evidence/mac/private/var/db/diagnostics/unifiedlog.ndjson

# 2. Point Agentic-DART at it
export DART_EVIDENCE_ROOT=/tmp/triage-evidence
cd ~/agentic-dart
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"

# 3. Run just the macOS function
python3 -c "
from dart_mcp import call_tool
import json
r = call_tool('parse_unified_log',
              {'unifiedlog_json': 'mac/private/var/db/diagnostics/unifiedlog.ndjson'})
print(json.dumps(r['alerts_by_severity'], indent=2))
for a in r['alerts'][:10]:
    print(f'[{a[\"severity\"]:8s}] {a[\"rule_id\"]}: {a[\"message\"][:100]}')
"
```

## macOS-specific gotchas

### SIP (System Integrity Protection) blocks some raw reads

`/private/var/db/diagnostics/` has read restrictions in normal user mode.
Two options:

1. **Run as root / with `sudo`** for the `log show` export step only
   (not for Agentic-DART itself — Agentic-DART should never run as root).
2. **Analyze offline** — copy the evidence to a user-writable directory
   before invoking Agentic-DART.

### KnowledgeC.db is locked while `cfprefsd` holds it open

If you want to analyze your own live KnowledgeC, either:

- **Quit your user session and analyze from recovery / another user account**, or
- **Use the sidecar-CSV path** — export via `sqlite3` from a copy:
  ```bash
  cp ~/Library/Application\ Support/Knowledge/knowledgeC.db /tmp/kc.db
  sqlite3 /tmp/kc.db -header -csv \
    "SELECT ZSTREAMNAME AS stream, ZVALUESTRING AS bundle_id,
            datetime(ZSTARTDATE+978307200,'unixepoch') AS start_time,
            datetime(ZENDDATE+978307200,'unixepoch') AS end_time
     FROM ZOBJECT ORDER BY ZSTARTDATE DESC LIMIT 10000" \
    > /tmp/kc.csv
  # Then place alongside the .db in your evidence tree:
  mv /tmp/kc.csv /path/to/evidence/mac/.../knowledgeC.csv
  ```

### FSEvents requires FSEventsParser (not bundled)

`/.fseventsd/*.gz` files are in a proprietary binary format. Use
[FSEventsParser](https://github.com/dlcowen/FSEventsParser) to produce a
CSV that Agentic-DART's `parse_fsevents` consumes.

## Developing Agentic-DART on macOS

Everything works the same as Linux:

```bash
# Run tests
python3 tests/test_audit_chain.py
python3 tests/test_mcp_surface.py
python3 tests/test_mcp_bypass.py
python3 tests/test_agent_self_correction.py

# Measure accuracy
python3 scripts/measure_accuracy.py

# Inspect audit chain
python3 -m dart_audit verify examples/out/find-evil-ref-01/audit.jsonl
python3 -m dart_audit trace  examples/out/find-evil-ref-01/audit.jsonl F-013
```

## Known differences vs. SIFT/Linux

| Aspect | Linux/SIFT | macOS |
|---|---|---|
| Python install | `apt install python3` | `brew install python@3.12` |
| pip behavior | Straightforward | May need `--break-system-packages` on 12.3+ |
| Evidence tree location | `/mnt/evidence/` typical | anywhere (user-writable dir) |
| Native tool integration | MFTECmd via `mono` | Skip — use sidecar CSV approach |
| macOS artifact analysis | Only with exported input | Can capture live with `log show` |

Agentic-DART is, architecturally, just a Python library. It runs anywhere Python 3.10+
does.
