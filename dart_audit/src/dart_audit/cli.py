"""dart-audit CLI — operations on JSONL audit logs.

Usage:
  python -m dart_audit verify  <audit.jsonl>
  python -m dart_audit lookup  <audit.jsonl> <audit_id>
  python -m dart_audit trace   <audit.jsonl> <finding_id>
  python -m dart_audit summary <audit.jsonl>

'lookup' returns the full entry for a single audit_id.
'trace' walks the chain and emits every entry that produced the given
finding_id — this is the "3 clicks from finding to raw evidence" path.
"""
import json
import sys
from pathlib import Path
from . import AuditLogger


def _load(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def cmd_verify(path):
    ok, msg = AuditLogger.verify(path)
    print(msg)
    return 0 if ok else 1


def cmd_lookup(path, audit_id):
    for entry in _load(path):
        if entry.get("audit_id") == audit_id:
            print(json.dumps(entry, indent=2, sort_keys=True))
            return 0
    print(f"not found: audit_id={audit_id}", file=sys.stderr)
    return 2


def cmd_trace(path, finding_id):
    matches = [e for e in _load(path) if finding_id in (e.get("finding_ids") or [])]
    if not matches:
        print(f"no entries reference finding_id={finding_id}", file=sys.stderr)
        return 2
    print(json.dumps({
        "finding_id": finding_id,
        "entry_count": len(matches),
        "entries": matches,
    }, indent=2, sort_keys=True))
    return 0


def cmd_summary(path):
    entries = list(_load(path))
    tools = {}
    iters = {}
    for e in entries:
        tools[e.get("tool_name", "?")] = tools.get(e.get("tool_name", "?"), 0) + 1
        iters[e.get("iteration", 0)] = iters.get(e.get("iteration", 0), 0) + 1
    ok, verify_msg = AuditLogger.verify(path)
    print(json.dumps({
        "path": str(path),
        "entry_count": len(entries),
        "chain_verified": ok,
        "chain_message": verify_msg,
        "by_tool": tools,
        "by_iteration": iters,
        "findings_referenced": sorted({
            fid for e in entries for fid in (e.get("finding_ids") or [])}),
    }, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, path, *rest = argv
    dispatch = {
        "verify":  lambda: cmd_verify(path),
        "lookup":  lambda: cmd_lookup(path, rest[0]) if rest else (print("need audit_id", file=sys.stderr) or 2),
        "trace":   lambda: cmd_trace(path, rest[0])  if rest else (print("need finding_id", file=sys.stderr) or 2),
        "summary": lambda: cmd_summary(path),
    }
    if cmd not in dispatch:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return dispatch[cmd]()


if __name__ == "__main__":
    raise SystemExit(main())
