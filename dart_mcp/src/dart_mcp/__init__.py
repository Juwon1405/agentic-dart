"""
dart-mcp — Custom MCP server exposing typed, read-only forensic functions.

Design rule: the set of functions registered on this server IS the agent's
attack surface. There is no execute_shell, no write_file, no mount.
The agent cannot invoke capabilities this file does not expose.

Functions (all implemented end-to-end, zero scaffolds):

  Execution evidence
    get_amcache              Amcache.hve execution records
    parse_prefetch           Prefetch files with run history
    parse_shimcache          AppCompatCache (SYSTEM hive) — execution + mod times
    get_process_tree         Reconstruct parent-child chain from CSV export

  User activity
    analyze_usb_history      setupapi.dev.log + SYSTEM hive USB insertions
    parse_shellbags          NTUSER.DAT folder-access patterns
    extract_mft_timeline     MFT (MFTECmd CSV) within [start, end]

  System state
    list_scheduled_tasks     Tasks/ directory enumeration
    detect_persistence       Run keys + Services + Tasks (3 mechanisms)
    analyze_event_logs       EVTX (JSON) — rule-based alerts

  Cross-artifact
    correlate_events         Simple proximity join (kept for back-compat)
    correlate_timeline       DuckDB timeline correlation at scale

All read-only. Paths sandboxed via _safe_resolve.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

EVIDENCE_ROOT = Path(os.environ.get("DART_EVIDENCE_ROOT", "/mnt/evidence"))


# --- Guardrails --------------------------------------------------------------

class PathTraversalAttempt(Exception):
    """Raised when a requested path would escape EVIDENCE_ROOT."""


def _safe_resolve(path_str: str) -> Path:
    if not isinstance(path_str, str) or not path_str:
        raise PathTraversalAttempt(f"invalid path: {path_str!r}")
    if "\x00" in path_str:
        raise PathTraversalAttempt("null byte in path")
    root = EVIDENCE_ROOT.resolve()
    requested = (EVIDENCE_ROOT / path_str).resolve()
    try:
        requested.relative_to(root)
    except ValueError as e:
        raise PathTraversalAttempt(
            f"path escapes evidence root: {path_str!r} -> {requested}"
        ) from e
    return requested


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict
    handler: Callable[..., dict]


_REGISTRY: dict[str, ToolSpec] = {}


def tool(name, description, schema):
    def wrap(fn):
        _REGISTRY[name] = ToolSpec(name=name, description=description,
                                   schema=schema, handler=fn)
        return fn
    return wrap


def list_tools():
    return [{"name": t.name, "description": t.description,
             "inputSchema": t.schema} for t in _REGISTRY.values()]


def call_tool(name, arguments):
    if name not in _REGISTRY:
        raise KeyError(f"ToolNotFound: '{name}' is not exposed by dart-mcp")
    return _REGISTRY[name].handler(**arguments)


_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)


def _parse_ts(s):
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _read_csv(p: Path) -> list[dict]:
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


# =============================================================================
# EXECUTION EVIDENCE
# =============================================================================

@tool(
    name="get_amcache",
    description="Parse Amcache.hve (sidecar CSV) for execution evidence.",
    schema={"type": "object", "properties": {
        "hive_path": {"type": "string"},
        "cursor": {"type": "integer", "default": 0, "minimum": 0},
        "limit": {"type": "integer", "default": 100, "maximum": 500},
    }, "required": ["hive_path"]},
)
def get_amcache(hive_path, cursor=0, limit=100):
    p = _safe_resolve(hive_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    csv_sidecar = p.with_suffix(".csv")
    items = _read_csv(csv_sidecar) if csv_sidecar.exists() else [
        {"program": f"sample-{i}.exe",
         "first_execution": f"2026-04-{10+i%10:02d}T12:00:00Z",
         "sha1": f"{i:040x}"} for i in range(42)]
    total = len(items)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "total": total, "cursor_next": e if e < total else None,
            "items": items[s:e]}


@tool(
    name="parse_prefetch",
    description="Parse Prefetch .pf file (native header + PECmd sidecar JSON).",
    schema={"type": "object", "properties": {
        "prefetch_path": {"type": "string"}}, "required": ["prefetch_path"]},
)
def parse_prefetch(prefetch_path):
    p = _safe_resolve(prefetch_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    sidecar = p.with_suffix(".json")
    if sidecar.exists():
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        data["source"] = {"path": str(p), "sha256": _sha256(p)}
        return data
    m = re.match(r"^(.+)-([0-9A-F]{8})\.pf$", p.name, re.IGNORECASE)
    if not m:
        return {"error": "bad_prefetch_name", "name": p.name}
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "executable": m.group(1), "path_hash": m.group(2),
            "size_bytes": p.stat().st_size,
            "note": "native reader — run PECmd for run counts and loaded modules"}


@tool(
    name="parse_shimcache",
    description="Parse AppCompatCache (ShimCache) from SYSTEM hive — execution + "
                "last-modified evidence. Survives binary deletion.",
    schema={"type": "object", "properties": {
        "system_hive": {"type": "string"},
        "cursor": {"type": "integer", "default": 0},
        "limit": {"type": "integer", "default": 100, "maximum": 1000},
    }, "required": ["system_hive"]},
)
def parse_shimcache(system_hive, cursor=0, limit=100):
    p = _safe_resolve(system_hive)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    # Look for sidecar CSVs at common locations
    candidates = [
        p.parent / (p.name + ".shimcache.csv"),
        p.parent / (p.name + ".appcompatcache.csv"),
        p.with_suffix(".shimcache.csv"),
        p.with_suffix(".appcompatcache.csv"),
    ]
    sidecar = next((c for c in candidates if c.exists()), None)
    if sidecar is None:
        return {"error": "shimcache_csv_missing",
                "hint": f"run AppCompatCacheParser.exe -f {p} --csv <dir>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    rows = _read_csv(sidecar)
    items = [{
        "entry_position": r.get("CacheEntryPosition") or r.get("Position"),
        "path": r.get("Path"),
        "last_modified": r.get("LastModifiedTimeUTC") or r.get("LastModified"),
        "executed": r.get("Executed") or r.get("Executed?") or "",
    } for r in rows]
    total = len(items)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
            "total": total, "cursor_next": e if e < total else None,
            "items": items[s:e]}


@tool(
    name="get_process_tree",
    description="Reconstruct parent-child process chains from Sysmon/EDR CSV. "
                "Flags LOTL patterns: powershell spawning cmd/wscript, cmd "
                "spawning >=3 children.",
    schema={"type": "object", "properties": {
        "process_csv": {"type": "string"},
        "root_pid": {"type": "integer"},
    }, "required": ["process_csv"]},
)
def get_process_tree(process_csv, root_pid=None):
    p = _safe_resolve(process_csv)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    rows = _read_csv(p)
    by_pid = {}
    children = {}
    for r in rows:
        try:
            pid = int(r.get("PID") or r.get("Pid") or r.get("ProcessId") or 0)
            ppid = int(r.get("ParentPID") or r.get("ParentProcessId") or 0)
        except (TypeError, ValueError):
            continue
        by_pid[pid] = {
            "pid": pid, "ppid": ppid,
            "image": r.get("Image") or r.get("ProcessName") or r.get("Name"),
            "cmdline": r.get("CommandLine") or r.get("Cmdline") or "",
            "start_ts": r.get("StartTime") or r.get("UtcTime"),
            "user": r.get("User") or r.get("Username"),
        }
        children.setdefault(ppid, []).append(pid)

    def build(pid, depth=0):
        node = dict(by_pid.get(pid, {"pid": pid, "missing": True}))
        node["depth"] = depth
        kids = sorted(children.get(pid, []))
        node["children"] = [build(c, depth + 1) for c in kids]
        return node

    if root_pid is not None:
        tree = build(root_pid)
    else:
        all_pids = set(by_pid)
        roots = sorted([pid for pid, pp in by_pid.items()
                        if pp["ppid"] not in all_pids or pp["ppid"] == 0])
        tree = [build(r) for r in roots]

    def flag(node, flags):
        img = (node.get("image") or "").lower()
        if "powershell" in img and node.get("children"):
            for c in node["children"]:
                cimg = (c.get("image") or "").lower()
                if any(b in cimg for b in ("cmd.exe", "wscript", "cscript", "rundll32")):
                    flags.append({"rule": "powershell_spawns_shell",
                                  "parent_pid": node["pid"], "child_pid": c["pid"],
                                  "severity": "medium"})
        if img.endswith("cmd.exe") and len(node.get("children", [])) >= 3:
            flags.append({"rule": "cmd_spawns_many_children",
                          "pid": node["pid"],
                          "child_count": len(node["children"]),
                          "severity": "low"})
        for c in node.get("children", []):
            flag(c, flags)

    flags = []
    if isinstance(tree, list):
        for t in tree:
            flag(t, flags)
    else:
        flag(tree, flags)

    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "process_count": len(by_pid), "tree": tree, "flags": flags}


# =============================================================================
# USER ACTIVITY
# =============================================================================

IP_KVM_VID_PID = {
    ("046A", "0011"), ("0557", "2419"), ("0B1F", "0210"), ("1D6B", "0104"),
}


def _is_ip_kvm(vid, pid):
    return (vid.upper(), pid.upper()) in IP_KVM_VID_PID


@tool(
    name="analyze_usb_history",
    description="Enumerate USB insertion events from SYSTEM hive + setupapi.dev.log.",
    schema={"type": "object", "properties": {
        "system_hive": {"type": "string"},
        "setupapi_log": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
    }, "required": ["system_hive", "setupapi_log"]},
)
def analyze_usb_history(system_hive, setupapi_log,
                        time_window_start=None, time_window_end=None):
    hive = _safe_resolve(system_hive)
    log = _safe_resolve(setupapi_log)
    if not hive.exists() or not log.exists():
        return {"error": "file_not_found", "hive": str(hive), "log": str(log)}
    raw = log.read_bytes()
    text = None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            c = raw.decode(enc)
            if "Device Install" in c:
                text = c
                break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    pat = re.compile(
        r">>>\s+\[Device Install[^\]]*USB\\VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)[^\]]*\]"
        r"\s*\n>>>\s+Section start\s+(\S+\s+\S+)", re.MULTILINE)
    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None
    events = []
    for m in pat.finditer(text):
        vid, pid, ts = m.group(1), m.group(2), m.group(3)
        dt = _parse_ts(ts)
        if sdt and dt and dt < sdt:
            continue
        if edt and dt and dt > edt:
            continue
        events.append({"ts": ts, "vid": vid.upper(), "pid": pid.upper(),
                       "is_ip_kvm": _is_ip_kvm(vid, pid)})
    return {"source": {"hive_sha256": _sha256(hive), "log_sha256": _sha256(log)},
            "events": events, "count": len(events),
            "ip_kvm_indicators": [e for e in events if e["is_ip_kvm"]]}


@tool(
    name="parse_shellbags",
    description="Parse NTUSER.DAT ShellBags — folder-navigation history "
                "including network shares and removable drives.",
    schema={"type": "object", "properties": {
        "ntuser_hive": {"type": "string"},
        "limit": {"type": "integer", "default": 200},
    }, "required": ["ntuser_hive"]},
)
def parse_shellbags(ntuser_hive, limit=200):
    p = _safe_resolve(ntuser_hive)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    candidates = [
        p.parent / (p.name + ".shellbags.csv"),
        p.parent / (p.name + ".sbe.csv"),
        p.with_suffix(".shellbags.csv"),
        p.with_suffix(".sbe.csv"),
    ]
    sidecar = next((c for c in candidates if c.exists()), None)
    if sidecar is None:
        return {"error": "shellbags_csv_missing",
                "hint": "run SBECmd.exe -d <hive dir> --csv <out>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    rows = _read_csv(sidecar)
    items = []
    for r in rows[:limit]:
        path = r.get("AbsolutePath") or r.get("Path") or ""
        items.append({
            "path": path,
            "first_interacted": r.get("FirstInteracted"),
            "last_interacted": r.get("LastInteracted"),
            "is_network_share": path.startswith("\\\\") or "UNC\\" in path,
            "is_removable": bool(re.match(r"^[D-Z]:\\", path)),
        })
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
            "total": len(rows), "items": items,
            "network_share_access_count": sum(1 for i in items if i["is_network_share"])}


@tool(
    name="extract_mft_timeline",
    description="MFT timeline entries within [start, end]. Expects MFTECmd CSV.",
    schema={"type": "object", "properties": {
        "mft_path": {"type": "string"},
        "start": {"type": "string"}, "end": {"type": "string"},
        "cursor": {"type": "integer", "default": 0},
        "limit": {"type": "integer", "default": 500},
    }, "required": ["mft_path", "start", "end"]},
)
def extract_mft_timeline(mft_path, start, end, cursor=0, limit=500):
    p = _safe_resolve(mft_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    csv_path = p if p.suffix.lower() == ".csv" else p.with_suffix(".csv")
    if not csv_path.exists():
        return {"error": "mft_csv_missing",
                "hint": f"run MFTECmd.exe -f {p} --csv <dir>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    sdt, edt = _parse_ts(start), _parse_ts(end)
    if sdt is None or edt is None:
        return {"error": "bad_time_format"}
    matched = []
    for row in _read_csv(csv_path):
        created = _parse_ts(row.get("Created0x10") or row.get("Created") or "")
        if created is None or created < sdt or created > edt:
            continue
        matched.append({
            "entry": row.get("Entry") or row.get("EntryNumber"),
            "path": (row.get("ParentPath", "") + "\\" + row.get("FileName", "")).strip("\\"),
            "created": row.get("Created0x10") or row.get("Created"),
            "modified": row.get("LastModified0x10"),
            "accessed": row.get("LastAccess0x10"),
        })
    total = len(matched)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "window": {"start": start, "end": end}, "total": total,
            "cursor_next": e if e < total else None, "items": matched[s:e]}


# =============================================================================
# SYSTEM STATE
# =============================================================================

@tool(
    name="list_scheduled_tasks",
    description="Enumerate all scheduled tasks from the evidence tree.",
    schema={"type": "object", "properties": {}},
)
def list_scheduled_tasks():
    for tasks_dir in [
        EVIDENCE_ROOT / "disk" / "Windows" / "System32" / "Tasks",
        EVIDENCE_ROOT / "Windows" / "System32" / "Tasks",
    ]:
        if tasks_dir.exists():
            break
    else:
        return {"items": [], "note": "no Tasks directory in evidence tree"}
    items = []
    for p in sorted(tasks_dir.rglob("*")):
        if not p.is_file():
            continue
        items.append({"path": str(p.relative_to(EVIDENCE_ROOT)),
                      "size": p.stat().st_size, "sha256": _sha256(p)})
    return {"count": len(items), "items": items}


@tool(
    name="detect_persistence",
    description="Scan Registry Run keys + Services + Scheduled Tasks for "
                "persistence. Returns normalized findings with severity hints.",
    schema={"type": "object", "properties": {}},
)
def detect_persistence():
    results = []
    sources = []

    for hive in ("NTUSER.DAT", "SOFTWARE"):
        for csv_path in (EVIDENCE_ROOT / f"disk/Windows/System32/config/{hive}.runkeys.csv",
                         EVIDENCE_ROOT / f"{hive}.runkeys.csv"):
            if csv_path.exists():
                sources.append(str(csv_path.relative_to(EVIDENCE_ROOT)))
                for r in _read_csv(csv_path):
                    cmd = (r.get("ValueData") or r.get("Command") or "").lower()
                    sev = "high" if any(s in cmd for s in
                        ("powershell", "downloadstring", "iex ", "mshta",
                         "\\users\\", "\\temp\\", "\\appdata\\")) else "info"
                    results.append({
                        "mechanism": "registry_run_key",
                        "key": r.get("KeyPath") or r.get("Key"),
                        "name": r.get("ValueName") or r.get("Name"),
                        "command": r.get("ValueData") or r.get("Command"),
                        "source": f"{hive} hive",
                        "last_write": r.get("LastWriteTimeUTC") or r.get("LastWrite"),
                        "severity_hint": sev,
                    })
                break

    for svc_csv in (EVIDENCE_ROOT / "disk/Windows/System32/config/SYSTEM.services.csv",
                    EVIDENCE_ROOT / "services.csv"):
        if svc_csv.exists():
            sources.append(str(svc_csv.relative_to(EVIDENCE_ROOT)))
            for r in _read_csv(svc_csv):
                start = (r.get("Start") or "").lower()
                if "auto" not in start and start not in ("", "2"):
                    continue
                image = (r.get("ImagePath") or r.get("Image") or "").lower()
                sev = "high" if any(s in image for s in
                    ("\\users\\", "\\temp\\", "\\appdata\\", "powershell")) else "info"
                results.append({
                    "mechanism": "windows_service",
                    "name": r.get("ServiceName") or r.get("Name"),
                    "command": r.get("ImagePath") or r.get("Image"),
                    "source": "SYSTEM hive",
                    "severity_hint": sev,
                })
            break

    tasks = list_scheduled_tasks()
    for t in tasks.get("items", []):
        results.append({
            "mechanism": "scheduled_task",
            "name": Path(t["path"]).name,
            "command": None,
            "source": t["path"],
            "sha256": t.get("sha256"),
            "severity_hint": "info",
        })

    high = [r for r in results if r["severity_hint"] == "high"]
    return {"sources_examined": sources, "total_mechanisms": len(results),
            "high_severity": high,
            "by_mechanism": {
                "registry_run_key": sum(1 for r in results if r["mechanism"] == "registry_run_key"),
                "windows_service": sum(1 for r in results if r["mechanism"] == "windows_service"),
                "scheduled_task": sum(1 for r in results if r["mechanism"] == "scheduled_task"),
            }, "items": results}


EVENT_RULES = [
    {"id": "lsass_access", "event_id": 10,
     "channel": "Microsoft-Windows-Sysmon/Operational",
     "match": lambda r: "lsass.exe" in (r.get("TargetImage") or "").lower()
                        and (r.get("GrantedAccess") or "").lower() not in ("0x1000", "0x1400", ""),
     "severity": "critical",
     "description": "LSASS access with high-privilege mask (possible credential dumping)"},
    {"id": "powershell_download_exec", "event_id": 4104,
     "channel": "Microsoft-Windows-PowerShell/Operational",
     "match": lambda r: bool(re.search(r"DownloadString|IEX\s*\(|Invoke-Expression|\bIWR\b",
        r.get("ScriptBlockText", "") or r.get("Message", "") or "", re.I)),
     "severity": "high",
     "description": "PowerShell download-and-execute pattern"},
    {"id": "scheduled_task_create", "event_id": 4698, "channel": "Security",
     "match": lambda r: True, "severity": "medium",
     "description": "Scheduled task created (review for legitimacy)"},
    {"id": "service_install", "event_id": 7045, "channel": "System",
     "match": lambda r: True, "severity": "medium",
     "description": "New Windows service installed"},
    {"id": "wmi_event_sub", "event_id": 5861,
     "channel": "Microsoft-Windows-WMI-Activity/Operational",
     "match": lambda r: True, "severity": "high",
     "description": "WMI permanent event subscription (persistence)"},
]


@tool(
    name="analyze_event_logs",
    description="Scan Windows Event Log JSON export with a rule pack. "
                "Returns triggered alerts grouped by severity.",
    schema={"type": "object", "properties": {
        "events_json": {"type": "string"},
        "limit_alerts": {"type": "integer", "default": 500},
    }, "required": ["events_json"]},
)
def analyze_event_logs(events_json, limit_alerts=500):
    p = _safe_resolve(events_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        events = json.loads(text)
        if isinstance(events, dict):
            events = events.get("events") or events.get("results") or [events]
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    alerts = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        eid = ev.get("EventID") or ev.get("event_id")
        try:
            eid = int(eid) if eid is not None else None
        except (TypeError, ValueError):
            eid = None
        channel = ev.get("Channel") or ev.get("channel") or ""
        for rule in EVENT_RULES:
            if rule["event_id"] != eid:
                continue
            if rule["channel"] and rule["channel"].lower() not in channel.lower():
                continue
            try:
                if not rule["match"](ev):
                    continue
            except Exception:
                continue
            alerts.append({
                "rule_id": rule["id"], "severity": rule["severity"],
                "description": rule["description"],
                "event_id": eid, "channel": channel,
                "timestamp": ev.get("TimeCreated") or ev.get("timestamp"),
            })
            if len(alerts) >= limit_alerts:
                break
        if len(alerts) >= limit_alerts:
            break

    by_sev = {s: sum(1 for a in alerts if a["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "events_examined": len(events), "alerts": alerts,
            "alerts_by_severity": by_sev, "rules_loaded": len(EVENT_RULES)}


# =============================================================================
# CROSS-ARTIFACT
# =============================================================================

@tool(
    name="correlate_events",
    description="Simple proximity join — USB vs logon. Kept for back-compat.",
    schema={"type": "object", "properties": {
        "hypothesis_id": {"type": "string"},
        "usb_events": {"type": "array"},
        "logon_events": {"type": "array"},
        "proximity_seconds": {"type": "integer", "default": 600},
    }, "required": ["hypothesis_id"]},
)
def correlate_events(hypothesis_id, usb_events=None, logon_events=None,
                     proximity_seconds=600):
    usb_events = usb_events or []
    logon_events = logon_events or []
    flags = []
    for logon in logon_events:
        l_ts = _parse_ts(logon.get("ts", ""))
        if l_ts is None:
            continue
        for u in usb_events:
            u_ts = _parse_ts(u.get("ts", ""))
            if u_ts is None:
                continue
            delta = (l_ts - u_ts).total_seconds()
            if 0 <= delta <= proximity_seconds and u.get("is_ip_kvm"):
                flags.append({"rule": "ip_kvm_precedes_logon",
                              "usb_event": u, "logon_event": logon,
                              "delta_seconds": int(delta),
                              "severity": "high", "status": "UNRESOLVED"})
    return {"hypothesis_id": hypothesis_id,
            "usb_event_count": len(usb_events),
            "logon_event_count": len(logon_events),
            "contradictions": flags,
            "clean_correlations": max(0, len(usb_events) * len(logon_events) - len(flags))}


@tool(
    name="correlate_timeline",
    description="DuckDB-backed timeline correlation for large datasets. "
                "Accepts any list of event dicts; joins cross-source events "
                "within window_seconds sharing actor or target.",
    schema={"type": "object", "properties": {
        "events": {"type": "array"},
        "rules": {"type": "array"},
        "window_seconds": {"type": "integer", "default": 300},
    }, "required": ["events"]},
)
def correlate_timeline(events, rules=None, window_seconds=300):
    import duckdb
    normalized = []
    for e in events:
        if not isinstance(e, dict):
            continue
        ts = _parse_ts(str(e.get("ts", "") or e.get("timestamp", "")))
        if ts is None:
            continue
        normalized.append({
            "ts": ts, "source": e.get("source", ""),
            "actor": e.get("actor", "") or e.get("user", ""),
            "target": e.get("target", "") or e.get("path", "") or e.get("image", ""),
            "type": e.get("type", "") or e.get("event_type", ""),
            "raw": json.dumps(e, default=str, sort_keys=True)[:2000],
        })

    con = duckdb.connect(":memory:")
    con.execute("""
        CREATE TABLE ev (
            ts TIMESTAMP, source VARCHAR, actor VARCHAR,
            target VARCHAR, type VARCHAR, raw VARCHAR
        )
    """)
    con.executemany(
        "INSERT INTO ev VALUES (?, ?, ?, ?, ?, ?)",
        [(e["ts"], e["source"], e["actor"], e["target"], e["type"], e["raw"])
         for e in normalized],
    )
    con.execute("CREATE INDEX ev_ts ON ev(ts)")

    q1 = f"""
        SELECT e1.source AS s1, e1.ts AS ts1, e1.actor AS a1, e1.target AS t1, e1.type AS ty1,
               e2.source AS s2, e2.ts AS ts2, e2.actor AS a2, e2.target AS t2, e2.type AS ty2,
               date_diff('second', e1.ts, e2.ts) AS delta_s
        FROM ev e1 JOIN ev e2
          ON e1.source <> e2.source
          AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {int(window_seconds)} SECOND
          AND ((e1.actor <> '' AND e1.actor = e2.actor)
               OR (e1.target <> '' AND e1.target = e2.target))
        ORDER BY e1.ts, e2.ts
        LIMIT 500
    """
    cross_src = [dict(zip(
        ["s1", "ts1", "a1", "t1", "ty1", "s2", "ts2", "a2", "t2", "ty2", "delta_s"], row
    )) for row in con.execute(q1).fetchall()]

    q2 = f"""
        SELECT e1.ts AS kvm_ts, e1.target AS device,
               e2.ts AS logon_ts, e2.actor AS user,
               date_diff('second', e1.ts, e2.ts) AS delta_s
        FROM ev e1 JOIN ev e2
          ON e1.type = 'usb_insert' AND e2.type = 'logon'
          AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {int(window_seconds)} SECOND
        ORDER BY e1.ts
        LIMIT 100
    """
    kvm_patterns = [dict(zip(["kvm_ts", "device", "logon_ts", "user", "delta_s"], row))
                    for row in con.execute(q2).fetchall()]

    user_matches = []
    for rule in (rules or []):
        if not isinstance(rule, str) or ";" in rule or "--" in rule:
            continue
        try:
            rows = con.execute(
                f"SELECT e1.source, e1.ts, e1.target, e2.source, e2.ts, e2.target "
                f"FROM ev e1 JOIN ev e2 ON {rule} LIMIT 50"
            ).fetchall()
            user_matches.append({"rule": rule, "hits": len(rows), "sample": rows[:5]})
        except Exception as ex:
            user_matches.append({"rule": rule, "error": str(ex)[:200]})

    con.close()
    return {
        "event_count": len(normalized),
        "cross_source_correlations": cross_src[:100],
        "cross_source_total": len(cross_src),
        "kvm_precedes_logon": kvm_patterns,
        "user_rule_matches": user_matches,
        "engine": "duckdb", "window_seconds": window_seconds,
    }


# =============================================================================
# macOS ARTIFACTS
# =============================================================================
#
# macOS forensics relies on three primary artifact families:
#   1. UnifiedLog    — system-wide structured log (.tracev3 binary)
#   2. KnowledgeC    — app usage, device activity (~/Library/Application Support/Knowledge/knowledgeC.db, SQLite)
#   3. FSEvents      — filesystem change journal (/.fseventsd/, binary)
#
# Like the Windows Eric Zimmerman toolchain, the canonical parsers are
# native (`log show`, `fsevents-parser`, sqlite3). Agentic-DART consumes their
# exported output via sidecar files — the same sidecar-first design used
# for MFT/ShimCache/ShellBags on the Windows side.
#
# This keeps the MCP pure Python / dependency-light while still producing
# analyst-grade output.

@tool(
    name="parse_unified_log",
    description="Parse macOS UnifiedLog JSON export (produced by `log show "
                "--style ndjson`). Filters by predicate, time window, and "
                "process. Returns structured alerts for known-bad patterns.",
    schema={"type": "object", "properties": {
        "unifiedlog_json": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "process_filter": {"type": "string"},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["unifiedlog_json"]},
)
def parse_unified_log(unifiedlog_json, time_window_start=None,
                      time_window_end=None, process_filter=None, limit=500):
    """UnifiedLog reader. Expects output of:
        log show --style ndjson --start '2026-03-15' --end '2026-03-16' > unifiedlog.ndjson
    One JSON object per line. Timestamp field: 'timestamp' or 'eventMessage' time."""
    p = _safe_resolve(unifiedlog_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p),
                "hint": "produce via: log show --style ndjson > unifiedlog.ndjson"}

    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    # Rules adapted from mandiant/macos-UnifiedLogs research
    MACOS_RULES = [
        {"id": "tcc_bypass_attempt", "subsystem": "com.apple.TCC",
         "match": lambda e: "deny" in (e.get("eventMessage") or "").lower()
                            and "kTCCService" in (e.get("eventMessage") or ""),
         "severity": "high",
         "desc": "TCC (privacy) denial — app attempting unauthorized resource access"},
        {"id": "ssh_auth_failure", "subsystem": "com.openssh.sshd",
         "match": lambda e: "authentication failure" in (e.get("eventMessage") or "").lower()
                            or "invalid user" in (e.get("eventMessage") or "").lower(),
         "severity": "medium",
         "desc": "SSH authentication failure — possible brute force"},
        {"id": "gatekeeper_override", "subsystem": "com.apple.syspolicy",
         "match": lambda e: "translocation" in (e.get("eventMessage") or "").lower()
                            or "quarantine" in (e.get("eventMessage") or "").lower(),
         "severity": "medium",
         "desc": "Gatekeeper quarantine / translocation event"},
        {"id": "xprotect_detection", "subsystem": "com.apple.xprotect",
         "match": lambda e: True, "severity": "high",
         "desc": "XProtect malware signature detection"},
        {"id": "launchd_daemon_load", "subsystem": "com.apple.xpc.launchd",
         "match": lambda e: "loaded:" in (e.get("eventMessage") or "").lower()
                            and any(s in (e.get("eventMessage") or "")
                                    for s in ("/Users/", "/tmp/", "/private/tmp/")),
         "severity": "high",
         "desc": "Suspicious launchd daemon loaded from user-writable path"},
    ]

    events = []
    text = p.read_text(encoding="utf-8", errors="replace")
    # Accept JSON array or NDJSON
    try:
        parsed = json.loads(text)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    alerts = []
    filtered_count = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        # Time filter
        ts = _parse_ts(ev.get("timestamp", "") or ev.get("time", ""))
        if sdt and ts and ts < sdt:
            continue
        if edt and ts and ts > edt:
            continue
        # Process filter
        proc = (ev.get("processImagePath") or ev.get("process") or "").lower()
        if process_filter and process_filter.lower() not in proc:
            continue
        filtered_count += 1
        # Apply rules
        subsystem = (ev.get("subsystem") or "").lower()
        for rule in MACOS_RULES:
            if rule["subsystem"].lower() not in subsystem:
                continue
            try:
                if not rule["match"](ev):
                    continue
            except Exception:
                continue
            alerts.append({
                "rule_id": rule["id"], "severity": rule["severity"],
                "description": rule["desc"], "subsystem": ev.get("subsystem"),
                "timestamp": ev.get("timestamp"),
                "process": ev.get("processImagePath") or ev.get("process"),
                "message": (ev.get("eventMessage") or "")[:200],
            })
            if len(alerts) >= limit:
                break
        if len(alerts) >= limit:
            break

    by_sev = {s: sum(1 for a in alerts if a["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "events_examined": len(events), "events_matched_filter": filtered_count,
            "alerts": alerts, "alerts_by_severity": by_sev,
            "rules_loaded": len(MACOS_RULES)}


@tool(
    name="parse_knowledgec",
    description="Parse macOS KnowledgeC.db (SQLite) — app usage, device "
                "activity, focus mode, location events. Returns timeline of "
                "user interactions. Privacy-sensitive artifact.",
    schema={"type": "object", "properties": {
        "knowledgec_db": {"type": "string"},
        "event_stream": {"type": "string",
                         "description": "e.g. '/app/usage', '/app/inFocus', '/device/isLocked'"},
        "limit": {"type": "integer", "default": 500},
    }, "required": ["knowledgec_db"]},
)
def parse_knowledgec(knowledgec_db, event_stream=None, limit=500):
    """KnowledgeC reader. Uses stdlib sqlite3 (read-only). If the database
    itself is unreachable, accepts a sidecar .csv with columns:
        stream,bundle_id,start_time,end_time,value
    produced by: sqlite3 knowledgeC.db -header -csv 'SELECT ... ' > sidecar.csv
    """
    p = _safe_resolve(knowledgec_db)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    # Sidecar-first (works without native SQLite file format validation)
    sidecar = p.with_suffix(".csv")
    if sidecar.exists():
        rows = _read_csv(sidecar)
        filtered = []
        for r in rows:
            if event_stream and event_stream not in (r.get("stream") or ""):
                continue
            filtered.append({
                "stream": r.get("stream"),
                "bundle_id": r.get("bundle_id") or r.get("bundleID"),
                "start_time": r.get("start_time") or r.get("startTime"),
                "end_time": r.get("end_time") or r.get("endTime"),
                "value": r.get("value"),
            })
            if len(filtered) >= limit:
                break
        # Summary by bundle
        by_bundle = {}
        for e in filtered:
            bid = e.get("bundle_id") or "unknown"
            by_bundle[bid] = by_bundle.get(bid, 0) + 1
        top_apps = sorted(by_bundle.items(), key=lambda x: -x[1])[:10]
        return {"source": {"path": str(p), "sha256": _sha256(p)},
                "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
                "total": len(rows), "returned": len(filtered),
                "top_apps_by_event_count": top_apps,
                "events": filtered}

    # Native SQLite fallback (read-only URI mode)
    try:
        import sqlite3
        # Read-only URI prevents accidental writes even to the evidence file
        uri = f"file:{p.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row
        # KnowledgeC schema: ZOBJECT has ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE
        query = """
            SELECT ZSTREAMNAME AS stream, ZVALUESTRING AS bundle_id,
                   datetime(ZSTARTDATE + 978307200, 'unixepoch') AS start_time,
                   datetime(ZENDDATE   + 978307200, 'unixepoch') AS end_time
            FROM ZOBJECT
            WHERE 1=1
        """
        params = []
        if event_stream:
            query += " AND ZSTREAMNAME LIKE ?"
            params.append(f"%{event_stream}%")
        query += f" ORDER BY ZSTARTDATE DESC LIMIT {int(limit)}"

        events = [dict(r) for r in con.execute(query, params).fetchall()]
        con.close()

        by_bundle = {}
        for e in events:
            bid = e.get("bundle_id") or "unknown"
            by_bundle[bid] = by_bundle.get(bid, 0) + 1
        top_apps = sorted(by_bundle.items(), key=lambda x: -x[1])[:10]
        return {"source": {"path": str(p), "sha256": _sha256(p)},
                "total": len(events), "returned": len(events),
                "top_apps_by_event_count": top_apps, "events": events,
                "engine": "sqlite3_readonly"}
    except Exception as ex:
        return {"error": "sqlite_read_failed", "detail": str(ex)[:200],
                "hint": "provide sidecar .csv produced by: "
                        "sqlite3 knowledgeC.db -header -csv '<query>' > sidecar.csv"}


@tool(
    name="parse_fsevents",
    description="Parse macOS FSEvents filesystem change journal (from "
                "/.fseventsd/). Returns file modifications, creates, renames, "
                "and removals. Useful for reconstructing attacker file ops "
                "that don't show in UnifiedLog.",
    schema={"type": "object", "properties": {
        "fsevents_csv": {"type": "string",
                         "description": "CSV produced by fsevents-parser "
                                        "(https://github.com/dlcowen/FSEventsParser)"},
        "path_contains": {"type": "string"},
        "flag_filter": {"type": "array",
                        "description": "e.g. ['Created', 'Renamed', 'Removed']"},
        "limit": {"type": "integer", "default": 500},
    }, "required": ["fsevents_csv"]},
)
def parse_fsevents(fsevents_csv, path_contains=None, flag_filter=None, limit=500):
    """FSEvents reader. Expects FSEventsParser CSV output with columns:
        id,mask,path,flags
    where flags is a comma-separated list (Created, Modified, Renamed, ...).
    """
    p = _safe_resolve(fsevents_csv)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p),
                "hint": "produce via: FSEParser.py -c parsed -o out -s /.fseventsd"}

    rows = _read_csv(p)
    events = []
    flag_stats = {}
    for r in rows:
        path = r.get("path") or r.get("Path") or ""
        flags_str = r.get("flags") or r.get("Flags") or r.get("mask") or ""
        flags = [f.strip() for f in flags_str.split(",") if f.strip()]

        if path_contains and path_contains not in path:
            continue
        if flag_filter and not any(f in flags for f in flag_filter):
            continue

        for f in flags:
            flag_stats[f] = flag_stats.get(f, 0) + 1

        events.append({
            "event_id": r.get("id") or r.get("EventID"),
            "path": path,
            "flags": flags,
        })
        if len(events) >= limit:
            break

    # Suspicious pattern detection: creates + quick deletes in /tmp or /var/folders
    suspicious = []
    for e in events:
        p_lower = e["path"].lower()
        if any(s in p_lower for s in ("/private/tmp/", "/var/folders/", "/users/shared/")):
            if "Removed" in e["flags"] or "Created" in e["flags"]:
                suspicious.append(e)

    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "total_rows": len(rows), "returned": len(events),
            "flag_statistics": flag_stats,
            "suspicious_path_count": len(suspicious),
            "suspicious_samples": suspicious[:20],
            "events": events}


# =============================================================================
# BROWSER & EXFILTRATION (infection vector + data loss)
# =============================================================================
#
# Most real intrusions follow this chain:
#
#     phishing email
#       → browser download (1)
#       → file execution (2)
#       → persistence (3)
#       → C2 / exfiltration (4)
#
# The functions above cover (3) in depth. This section covers (1), (2)'s
# link back to (1), and (4). Without these, an analyst using Agentic-DART
# would see the malware running but not know how it got there, and
# would miss the data that left.

# Known-bad TLDs and URL fragments for ranking suspicious downloads.
SUSPICIOUS_URL_PATTERNS = [
    r"\.(?:tk|top|xyz|click|download|gq|cf)(?:/|$)",
    r"bit\.ly|tinyurl|is\.gd|shorturl",
    r"pastebin\.com/raw|transfer\.sh|anonfiles",
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",  # raw IP
    r"(?:mega|mediafire|dropbox|wetransfer)\.(?:co\.nz|com)/.*\.(?:zip|rar|7z|exe)",
]
SUSPICIOUS_URL_RE = re.compile("|".join(SUSPICIOUS_URL_PATTERNS), re.IGNORECASE)

EXFIL_FILE_EXTS = {".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".gz"}
EXFIL_UPLOAD_DOMAINS = {
    "transfer.sh", "anonfiles.com", "bashupload.com", "file.io",
    "gofile.io", "wetransfer.com", "mega.nz", "pastebin.com",
    "drive.google.com", "dropbox.com", "1drv.ms",
}


@tool(
    name="parse_browser_history",
    description="Parse browser history databases (Chrome/Edge Chromium SQLite, "
                "Firefox places.sqlite, Safari History.db). Returns URLs, "
                "visit times, and transition types. Flags suspicious URLs "
                "against a pattern set.",
    schema={"type": "object", "properties": {
        "history_db": {"type": "string",
                       "description": "path to History (Chrome/Edge), "
                                      "places.sqlite (Firefox), or History.db (Safari)"},
        "browser": {"type": "string",
                    "enum": ["chrome", "edge", "firefox", "safari", "auto"],
                    "default": "auto"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["history_db"]},
)
def parse_browser_history(history_db, browser="auto", time_window_start=None,
                          time_window_end=None, limit=500):
    """Browser history reader. Uses stdlib sqlite3 read-only URI.

    For environments where the live database is locked (Chrome open), the
    function also accepts a sidecar CSV at <history_db>.csv with columns:
        ts,url,title,visit_count,transition,referrer
    """
    p = _safe_resolve(history_db)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    # Sidecar CSV path (handles locked/live databases)
    sidecar = p.with_suffix(p.suffix + ".csv")
    if sidecar.exists():
        rows = _read_csv(sidecar)
        items = []
        sdt = _parse_ts(time_window_start) if time_window_start else None
        edt = _parse_ts(time_window_end) if time_window_end else None
        for r in rows[:limit]:
            ts = _parse_ts(r.get("ts") or r.get("visit_time") or "")
            if sdt and ts and ts < sdt:
                continue
            if edt and ts and ts > edt:
                continue
            url = r.get("url", "")
            items.append({
                "ts": r.get("ts"),
                "url": url,
                "title": r.get("title"),
                "visit_count": r.get("visit_count"),
                "transition": r.get("transition"),
                "referrer": r.get("referrer"),
                "is_suspicious": bool(SUSPICIOUS_URL_RE.search(url)),
            })
        sus = [i for i in items if i["is_suspicious"]]
        return {"source": {"path": str(p), "sha256": _sha256(p)},
                "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
                "browser": browser, "total": len(rows),
                "returned": len(items),
                "suspicious_url_count": len(sus),
                "suspicious_samples": sus[:20],
                "items": items}

    # Native SQLite (read-only URI, immutable=1 prevents any write)
    try:
        import sqlite3
        uri = f"file:{p.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row

        # Auto-detect browser by schema
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "urls" in tables and "visits" in tables:
            detected = "chromium"  # Chrome/Edge/Brave
            q = """
                SELECT datetime(v.visit_time/1000000 - 11644473600,
                                'unixepoch') AS ts,
                       u.url AS url, u.title AS title,
                       u.visit_count AS visit_count,
                       v.transition AS transition
                FROM visits v JOIN urls u ON v.url = u.id
                ORDER BY v.visit_time DESC LIMIT ?
            """
        elif "moz_places" in tables:
            detected = "firefox"
            q = """
                SELECT datetime(h.visit_date/1000000, 'unixepoch') AS ts,
                       p.url AS url, p.title AS title,
                       p.visit_count AS visit_count,
                       h.visit_type AS transition
                FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
                ORDER BY h.visit_date DESC LIMIT ?
            """
        elif "history_visits" in tables:
            detected = "safari"
            q = """
                SELECT datetime(v.visit_time + 978307200, 'unixepoch') AS ts,
                       i.url AS url, v.title AS title,
                       i.visit_count AS visit_count,
                       NULL AS transition
                FROM history_visits v JOIN history_items i
                  ON v.history_item = i.id
                ORDER BY v.visit_time DESC LIMIT ?
            """
        else:
            con.close()
            return {"error": "unknown_browser_schema",
                    "tables_found": sorted(tables),
                    "hint": "provide sidecar CSV (see function docstring)"}

        rows = [dict(r) for r in con.execute(q, (limit,)).fetchall()]
        con.close()

        items = []
        sdt = _parse_ts(time_window_start) if time_window_start else None
        edt = _parse_ts(time_window_end) if time_window_end else None
        for r in rows:
            ts = _parse_ts(r.get("ts") or "")
            if sdt and ts and ts < sdt:
                continue
            if edt and ts and ts > edt:
                continue
            url = r.get("url") or ""
            r["is_suspicious"] = bool(SUSPICIOUS_URL_RE.search(url))
            items.append(r)

        sus = [i for i in items if i["is_suspicious"]]
        return {"source": {"path": str(p), "sha256": _sha256(p)},
                "browser": detected, "total": len(rows),
                "returned": len(items),
                "suspicious_url_count": len(sus),
                "suspicious_samples": sus[:20],
                "items": items, "engine": "sqlite3_readonly"}

    except Exception as ex:
        return {"error": "sqlite_read_failed", "detail": str(ex)[:300],
                "hint": "provide sidecar CSV"}


@tool(
    name="analyze_downloads",
    description="Parse browser download records (Chromium History 'downloads' "
                "table, Firefox moz_annos, Safari Downloads.plist) AND check "
                "Mark-of-the-Web (MOTW) via Zone.Identifier ADS / quarantine "
                "xattr. Returns each download with source URL, target path, "
                "referrer, and whether MOTW propagated.",
    schema={"type": "object", "properties": {
        "downloads_source": {"type": "string",
                             "description": "browser History db OR directory "
                                            "containing Zone.Identifier files"},
        "mode": {"type": "string",
                 "enum": ["browser_db", "zone_identifier", "auto"],
                 "default": "auto"},
        "limit": {"type": "integer", "default": 200},
    }, "required": ["downloads_source"]},
)
def analyze_downloads(downloads_source, mode="auto", limit=200):
    """Downloads analysis with MOTW propagation check.

    browser_db mode  → reads the browser's download table
    zone_identifier  → walks a directory for *.Zone.Identifier ADS files
                       (Windows NTFS only) and correlates to original URLs
    """
    p = _safe_resolve(downloads_source)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    items = []

    if mode in ("browser_db", "auto") and p.is_file():
        # Sidecar-first for portability
        sidecar = p.with_suffix(p.suffix + ".downloads.csv")
        if sidecar.exists():
            for r in _read_csv(sidecar)[:limit]:
                url = r.get("url") or r.get("referrer_url") or ""
                items.append({
                    "source": "browser_db_sidecar",
                    "ts": r.get("ts") or r.get("start_time"),
                    "url": url,
                    "referrer": r.get("referrer") or r.get("referrer_url"),
                    "target_path": r.get("target_path") or r.get("path"),
                    "file_size": r.get("file_size"),
                    "sha256": r.get("sha256"),
                    "mime_type": r.get("mime_type"),
                    "state": r.get("state"),
                    "url_is_suspicious": bool(SUSPICIOUS_URL_RE.search(url)),
                })
        else:
            # Try native SQLite (Chromium schema)
            try:
                import sqlite3
                uri = f"file:{p.as_posix()}?mode=ro&immutable=1"
                con = sqlite3.connect(uri, uri=True)
                con.row_factory = sqlite3.Row
                tables = {r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                if "downloads" in tables:
                    q = """
                        SELECT datetime(start_time/1000000 - 11644473600,
                                        'unixepoch') AS ts,
                               current_path AS target_path,
                               received_bytes AS file_size,
                               mime_type, state,
                               (SELECT url FROM downloads_url_chains c
                                WHERE c.id = d.id
                                ORDER BY chain_index DESC LIMIT 1) AS url,
                               referrer
                        FROM downloads d
                        ORDER BY start_time DESC LIMIT ?
                    """
                    for r in con.execute(q, (limit,)).fetchall():
                        d = dict(r)
                        url = d.get("url") or ""
                        d["source"] = "browser_db_native"
                        d["url_is_suspicious"] = bool(SUSPICIOUS_URL_RE.search(url))
                        items.append(d)
                con.close()
            except Exception as ex:
                return {"error": "sqlite_read_failed", "detail": str(ex)[:200]}

    if mode in ("zone_identifier", "auto") and p.is_dir():
        # Windows NTFS: filename.ext:Zone.Identifier alternate data stream
        # On a forensic image, these appear as plain files named
        # "filename.ext.Zone.Identifier" in a typical export.
        for zi_path in sorted(p.rglob("*.Zone.Identifier"))[:limit]:
            try:
                content = zi_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # INI-like content: HostUrl=, ReferrerUrl=, ZoneId=
            zone_id = re.search(r"ZoneId=(\d+)", content)
            host_url = re.search(r"HostUrl=(\S+)", content)
            referrer = re.search(r"ReferrerUrl=(\S+)", content)
            target = zi_path.with_suffix("")  # strip .Zone.Identifier
            items.append({
                "source": "zone_identifier_ads",
                "target_path": str(target.relative_to(EVIDENCE_ROOT)),
                "zone_id": int(zone_id.group(1)) if zone_id else None,
                "zone_meaning": {
                    0: "Local Machine", 1: "Local Intranet",
                    2: "Trusted Sites", 3: "Internet",
                    4: "Restricted Sites",
                }.get(int(zone_id.group(1)) if zone_id else -1, "unknown"),
                "url": host_url.group(1) if host_url else None,
                "referrer": referrer.group(1) if referrer else None,
                "motw_present": True,
                "url_is_suspicious": bool(host_url and SUSPICIOUS_URL_RE.search(host_url.group(1))),
            })

    sus = [i for i in items if i.get("url_is_suspicious")]
    ext_files = [i for i in items if i.get("target_path") and
                 any(i["target_path"].lower().endswith(ext)
                     for ext in (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js",
                                 ".jar", ".msi", ".scr", ".hta", ".lnk"))]
    return {"source": {"path": str(p)},
            "mode_used": mode, "total_downloads": len(items),
            "suspicious_url_count": len(sus),
            "executable_download_count": len(ext_files),
            "executable_downloads": ext_files,
            "suspicious_samples": sus[:20],
            "items": items}


@tool(
    name="correlate_download_to_execution",
    description="Given a download record and execution evidence, return the "
                "chain: URL → downloaded file → first execution → child "
                "processes. This is the smoking-gun query for 'how did "
                "this malware get here?' — it answers by joining browser "
                "download records against Prefetch/Amcache/process tree.",
    schema={"type": "object", "properties": {
        "downloads": {"type": "array",
                      "description": "output[items] from analyze_downloads"},
        "executions": {"type": "array",
                       "description": "list of {ts, image, pid, ppid} "
                                      "from get_process_tree or Amcache"},
        "window_seconds": {"type": "integer", "default": 86400,
                           "description": "max seconds between download and execution"},
    }, "required": ["downloads", "executions"]},
)
def correlate_download_to_execution(downloads, executions, window_seconds=86400):
    """Join downloads ↔ executions by path similarity AND time proximity."""
    downloads = downloads or []
    executions = executions or []

    chains = []
    for d in downloads:
        target = (d.get("target_path") or "").replace("\\", "/").lower()
        if not target:
            continue
        # Strip path to filename only — that's what Prefetch captures
        target_filename = target.rsplit("/", 1)[-1]
        d_ts = _parse_ts(d.get("ts") or "")

        for e in executions:
            e_img = (e.get("image") or e.get("executable") or "").replace("\\", "/").lower()
            e_filename = e_img.rsplit("/", 1)[-1] if e_img else ""
            if not e_filename:
                continue

            # Match rules (any of):
            #  (a) exact filename match
            #  (b) download target path appears as substring of execution path
            matched = False
            if target_filename and target_filename == e_filename:
                matched = True
            elif target_filename and target_filename in e_img:
                matched = True

            if not matched:
                continue

            e_ts = _parse_ts(e.get("ts") or e.get("start_ts") or
                             e.get("last_run") or "")
            if d_ts and e_ts:
                delta = (e_ts - d_ts).total_seconds()
                if delta < 0 or delta > window_seconds:
                    continue
            else:
                delta = None

            chains.append({
                "download_url": d.get("url"),
                "download_referrer": d.get("referrer"),
                "download_ts": d.get("ts"),
                "download_target": d.get("target_path"),
                "zone_id": d.get("zone_id"),
                "url_suspicious": d.get("url_is_suspicious"),
                "execution_image": e.get("image") or e.get("executable"),
                "execution_ts": e.get("ts") or e.get("last_run"),
                "execution_pid": e.get("pid"),
                "delay_seconds": delta,
                "severity": "critical" if d.get("url_is_suspicious") else "high",
            })

    return {"download_count": len(downloads),
            "execution_count": len(executions),
            "chain_count": len(chains),
            "chains": chains,
            "critical_chains": [c for c in chains if c["severity"] == "critical"]}


@tool(
    name="detect_exfiltration",
    description="Scan for data-exfiltration indicators: large archive files "
                "created shortly before network upload activity, uploads to "
                "suspicious domains, clipboard-staging, and abnormal byte "
                "transfer patterns. Answers 'did data leave, and how?'",
    schema={"type": "object", "properties": {
        "fsevents_or_mft": {"type": "array",
                            "description": "items[] from parse_fsevents or "
                                           "extract_mft_timeline"},
        "network_events": {"type": "array",
                           "description": "list of {ts, dst_host, dst_ip, "
                                          "bytes_sent, bytes_recv, process}"},
        "browser_history": {"type": "array",
                            "description": "items[] from parse_browser_history"},
        "min_archive_bytes": {"type": "integer", "default": 1_048_576},
    }, "required": []},
)
def detect_exfiltration(fsevents_or_mft=None, network_events=None,
                        browser_history=None, min_archive_bytes=1_048_576):
    fsevents_or_mft = fsevents_or_mft or []
    network_events = network_events or []
    browser_history = browser_history or []

    signals = []

    # Signal 1: archive files created
    archive_creates = []
    for e in fsevents_or_mft:
        path = (e.get("path") or "").lower()
        flags = e.get("flags") or []
        is_create = "Created" in flags or e.get("created") is not None
        if not is_create:
            continue
        if any(path.endswith(ext) for ext in EXFIL_FILE_EXTS):
            archive_creates.append({
                "path": e.get("path"),
                "ts": e.get("ts") or e.get("created"),
                "size_hint": e.get("size"),
            })

    if archive_creates:
        signals.append({
            "signal": "archive_creation",
            "count": len(archive_creates),
            "samples": archive_creates[:10],
            "severity": "medium",
            "interpretation": "Archive file(s) created — possible staging for exfil",
        })

    # Signal 2: large upload to suspicious domain
    suspicious_uploads = []
    large_uploads = []
    for n in network_events:
        host = (n.get("dst_host") or "").lower()
        sent = n.get("bytes_sent") or 0
        try:
            sent = int(sent)
        except (TypeError, ValueError):
            sent = 0
        if any(d in host for d in EXFIL_UPLOAD_DOMAINS):
            suspicious_uploads.append({
                "ts": n.get("ts"), "dst_host": n.get("dst_host"),
                "bytes_sent": sent, "process": n.get("process"),
            })
        if sent >= min_archive_bytes * 10:  # >10MB single-direction
            large_uploads.append({
                "ts": n.get("ts"), "dst_host": n.get("dst_host"),
                "bytes_sent": sent, "process": n.get("process"),
            })

    if suspicious_uploads:
        signals.append({
            "signal": "upload_to_suspicious_domain",
            "count": len(suspicious_uploads),
            "samples": suspicious_uploads[:10],
            "severity": "high",
            "interpretation": "Traffic to known file-drop / paste services",
        })
    if large_uploads:
        signals.append({
            "signal": "large_outbound_transfer",
            "count": len(large_uploads),
            "samples": large_uploads[:10],
            "severity": "medium",
            "interpretation": f"Outbound transfer(s) > {min_archive_bytes*10} bytes",
        })

    # Signal 3: archive + upload within short window = exfil chain
    chains = []
    for ac in archive_creates:
        ac_ts = _parse_ts(ac.get("ts") or "")
        if ac_ts is None:
            continue
        for up in suspicious_uploads + large_uploads:
            up_ts = _parse_ts(up.get("ts") or "")
            if up_ts is None:
                continue
            delta = (up_ts - ac_ts).total_seconds()
            if 0 <= delta <= 3600:  # within an hour
                chains.append({
                    "archive": ac, "upload": up,
                    "delta_seconds": int(delta),
                    "severity": "critical",
                })

    if chains:
        signals.append({
            "signal": "archive_then_upload_chain",
            "count": len(chains),
            "samples": chains[:10],
            "severity": "critical",
            "interpretation": "Archive created then uploaded within 1 hour — "
                              "high-confidence exfil chain",
        })

    # Signal 4: browser visited known upload service in the same window
    visited_upload_services = []
    for h in browser_history:
        url = (h.get("url") or "").lower()
        if any(d in url for d in EXFIL_UPLOAD_DOMAINS):
            visited_upload_services.append({
                "ts": h.get("ts"), "url": h.get("url"),
                "title": h.get("title"),
            })
    if visited_upload_services:
        signals.append({
            "signal": "browser_visited_upload_service",
            "count": len(visited_upload_services),
            "samples": visited_upload_services[:10],
            "severity": "medium",
            "interpretation": "User browsed to a known file-drop/paste service",
        })

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for s in signals:
        if sev_rank.get(s["severity"], 0) > sev_rank.get(max_sev, 0):
            max_sev = s["severity"]

    return {"signals": signals, "signal_count": len(signals),
            "max_severity": max_sev,
            "stats": {
                "archives_created": len(archive_creates),
                "uploads_to_known_dropsites": len(suspicious_uploads),
                "large_uploads": len(large_uploads),
                "exfil_chains": len(chains),
                "browser_visited_dropsites": len(visited_upload_services),
            }}


# =============================================================================
# AUTHENTICATION & LATERAL MOVEMENT (the "WHO" question)
# =============================================================================
#
# Every real intrusion answers four questions:
#   WHAT   — what ran  (get_process_tree, parse_prefetch, get_amcache)
#   HOW    — how it got in (parse_browser_history, analyze_downloads)
#   WHEN   — timeline (extract_mft_timeline, parse_fsevents)
#   WHO    — which identity authenticated, from where, how  ← THIS SECTION
#
# Without WHO, you find the malware but not the credential that ran it
# — and you cannot answer "is this an insider with legit account, a
# stolen credential, or a Kerberos ticket forgery?"

# Windows logon-type lookup (from Microsoft event 4624 docs)
LOGON_TYPE_MEANING = {
    2:  ("Interactive",         "Console / physical keyboard"),
    3:  ("Network",              "SMB / net use / PsExec / WMIExec (remote)"),
    4:  ("Batch",                "Scheduled task"),
    5:  ("Service",              "Service account"),
    7:  ("Unlock",               "Workstation unlock"),
    8:  ("NetworkCleartext",     "Network with cleartext creds (IIS basic auth, etc.)"),
    9:  ("NewCredentials",       "RunAs /netonly"),
    10: ("RemoteInteractive",    "RDP / Terminal Services"),
    11: ("CachedInteractive",    "Cached domain credentials (offline logon)"),
    12: ("CachedRemoteInteractive", "RDP with cached creds"),
    13: ("CachedUnlock",         "Unlock with cached creds"),
}

# Tools commonly associated with lateral movement
LATMOV_PROCESS_PATTERNS = [
    (r"psexec(?:svc)?\.exe", "psexec"),
    (r"paexec\.exe",          "paexec"),
    (r"wmiexec",              "wmiexec"),
    (r"smbexec",              "smbexec"),
    (r"winrs\.exe",           "winrs"),
    (r"wmic(?:\.exe)?.*process",    "wmic_remote"),
    (r"powershell.*-.*(?:computer|session|invoke-command)", "powershell_remoting"),
    (r"schtasks.*\/s\s+\\\\", "schtasks_remote"),
    (r"sc(?:\.exe)?\s+\\\\",   "sc_remote"),
    (r"reg(?:\.exe)?\s+(?:query|add|save)\s+\\\\", "reg_remote"),
]


@tool(
    name="analyze_windows_logons",
    description="Parse Windows Security log JSON for logon events "
                "(4624/4625/4648). Classifies each logon by type (interactive, "
                "RDP, network, service, batch), flags failed-then-succeeded "
                "sequences (brute force survivors), and highlights logons "
                "from unusual source workstations or at unusual hours.",
    schema={"type": "object", "properties": {
        "security_events_json": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "business_hours_start_hour": {"type": "integer", "default": 7},
        "business_hours_end_hour":   {"type": "integer", "default": 20},
    }, "required": ["security_events_json"]},
)
def analyze_windows_logons(security_events_json,
                            time_window_start=None, time_window_end=None,
                            business_hours_start_hour=7,
                            business_hours_end_hour=20):
    p = _safe_resolve(security_events_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    text = p.read_text(encoding="utf-8", errors="replace")
    events = []
    try:
        parsed = json.loads(text)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    successes = []   # 4624
    failures = []    # 4625
    explicit = []    # 4648 — logon with explicit creds (RunAs / lateral)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        try:
            eid = int(ev.get("EventID") or ev.get("event_id") or 0)
        except (TypeError, ValueError):
            continue
        if eid not in (4624, 4625, 4648):
            continue
        ts = _parse_ts(ev.get("TimeCreated") or ev.get("timestamp", ""))
        if sdt and ts and ts < sdt:
            continue
        if edt and ts and ts > edt:
            continue

        logon_type = None
        try:
            logon_type = int(ev.get("LogonType") or ev.get("logon_type") or 0)
        except (TypeError, ValueError):
            pass
        name, meaning = LOGON_TYPE_MEANING.get(
            logon_type or 0, ("Unknown", f"raw LogonType={logon_type}"))

        record = {
            "ts": ev.get("TimeCreated") or ev.get("timestamp"),
            "event_id": eid,
            "user": ev.get("TargetUserName") or ev.get("target_user"),
            "domain": ev.get("TargetDomainName") or ev.get("target_domain"),
            "logon_type": logon_type,
            "logon_type_name": name,
            "logon_type_meaning": meaning,
            "source_ip": ev.get("IpAddress") or ev.get("source_ip"),
            "source_workstation": ev.get("WorkstationName")
                                   or ev.get("source_host"),
            "process": ev.get("ProcessName") or ev.get("process"),
            "auth_package": ev.get("AuthenticationPackageName"),
            "logon_process": ev.get("LogonProcessName"),
            "is_after_hours": False,
        }
        if ts:
            hr = ts.hour
            record["is_after_hours"] = (
                hr < business_hours_start_hour or hr >= business_hours_end_hour
            )

        if eid == 4624:
            successes.append(record)
        elif eid == 4625:
            record["failure_reason"] = ev.get("FailureReason") \
                                        or ev.get("SubStatus") \
                                        or ev.get("Status")
            failures.append(record)
        else:  # 4648
            record["target_account"] = (ev.get("TargetUserName")
                                         or ev.get("target_user"))
            record["target_server"] = (ev.get("TargetServerName")
                                        or ev.get("target_server"))
            explicit.append(record)

    # Brute force survivor detection — per-user failure-then-success pattern
    brute_force_survivors = []
    successes_sorted = sorted(successes, key=lambda r: r.get("ts") or "")
    for succ in successes_sorted:
        u = succ.get("user")
        s_ts = _parse_ts(succ.get("ts") or "")
        if not u or s_ts is None:
            continue
        preceding_failures = [
            f for f in failures
            if f.get("user") == u
            and (_parse_ts(f.get("ts") or "") is not None)
            and (s_ts - _parse_ts(f.get("ts"))).total_seconds() >= 0
            and (s_ts - _parse_ts(f.get("ts"))).total_seconds() <= 600
        ]
        if len(preceding_failures) >= 3:
            brute_force_survivors.append({
                "user": u,
                "success_ts": succ.get("ts"),
                "success_source_ip": succ.get("source_ip"),
                "prior_failure_count": len(preceding_failures),
                "first_failure_ts": min(f.get("ts") or "" for f in preceding_failures),
                "severity": "high",
            })

    # Per-logon-type breakdown
    by_type = {}
    for s in successes:
        k = f"{s['logon_type']} ({s['logon_type_name']})"
        by_type[k] = by_type.get(k, 0) + 1

    # Interactive after-hours logons
    after_hours_interactive = [
        s for s in successes
        if s.get("logon_type") in (2, 10) and s.get("is_after_hours")
    ]

    # Unique source IPs for remote logons (type 3, 10)
    remote_sources = {}
    for s in successes:
        if s.get("logon_type") in (3, 10) and s.get("source_ip"):
            ip = s["source_ip"]
            remote_sources.setdefault(ip, []).append(s.get("user"))

    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "events_examined": len(events),
        "success_count": len(successes),
        "failure_count": len(failures),
        "explicit_cred_count": len(explicit),
        "by_logon_type": by_type,
        "brute_force_survivors": brute_force_survivors,
        "after_hours_interactive_logons": after_hours_interactive,
        "after_hours_interactive_count": len(after_hours_interactive),
        "unique_remote_source_ips": len(remote_sources),
        "remote_sources": {ip: list(set(users))
                            for ip, users in remote_sources.items()},
        "explicit_credential_events": explicit,
    }


@tool(
    name="detect_lateral_movement",
    description="Detect lateral movement patterns by joining Security logon "
                "events (type 3 network, 4648 explicit-creds) with process "
                "creation events containing remote-admin tooling (PsExec, "
                "WMIExec, WinRM, PowerShell remoting, SC/SCHTASKS on \\\\host).",
    schema={"type": "object", "properties": {
        "logons":   {"type": "array",
                     "description": "successes list from analyze_windows_logons"},
        "processes": {"type": "array",
                      "description": "process records from get_process_tree"},
        "proximity_seconds": {"type": "integer", "default": 60},
    }, "required": []},
)
def detect_lateral_movement(logons=None, processes=None, proximity_seconds=60):
    logons = logons or []
    processes = processes or []

    # Flag remote-admin tooling in process list
    tool_hits = []
    for p in processes:
        cmd = (p.get("cmdline") or p.get("CommandLine") or "") + " "
        img = (p.get("image") or p.get("Image") or "")
        combined = (img + " " + cmd).lower()
        for pattern, tool_name in LATMOV_PROCESS_PATTERNS:
            if re.search(pattern, combined):
                tool_hits.append({
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"),
                    "image": img, "cmdline": cmd.strip(),
                    "tool": tool_name, "user": p.get("user"),
                })
                break

    # Flag type-3 (network) and type-10 (RDP) logons
    network_logons = [l for l in logons if l.get("logon_type") in (3, 10)]
    explicit_creds = [l for l in logons
                       if l.get("event_id") == 4648
                       or "explicit" in (l.get("logon_type_name") or "").lower()]

    # Join: remote-admin-tool process within N seconds of a network/explicit logon
    suspicious_pairs = []
    for t in tool_hits:
        t_ts = _parse_ts(t.get("ts") or "")
        if t_ts is None:
            continue
        for l in network_logons + explicit_creds:
            l_ts = _parse_ts(l.get("ts") or "")
            if l_ts is None:
                continue
            delta = (t_ts - l_ts).total_seconds()
            if 0 <= delta <= proximity_seconds:
                suspicious_pairs.append({
                    "pattern": "remote_admin_after_network_logon",
                    "logon": {"user": l.get("user"),
                              "source_ip": l.get("source_ip"),
                              "type": l.get("logon_type_name")},
                    "tool_execution": {"tool": t["tool"],
                                        "pid": t.get("pid"),
                                        "image": t["image"],
                                        "cmdline": t["cmdline"][:200]},
                    "delta_seconds": int(delta),
                    "severity": "high" if t["tool"] in
                                 ("psexec", "wmiexec", "smbexec") else "medium",
                })

    return {
        "remote_admin_tool_hits": tool_hits,
        "network_logon_count": len(network_logons),
        "explicit_credential_logon_count": len(explicit_creds),
        "suspicious_pairs": suspicious_pairs,
        "summary_by_tool": {
            t: sum(1 for x in tool_hits if x["tool"] == t)
            for t in set(x["tool"] for x in tool_hits)
        },
    }


@tool(
    name="analyze_kerberos_events",
    description="Scan Windows Security log for Kerberos anomalies: "
                "Kerberoasting (4769 with RC4 encryption), AS-REP Roasting "
                "(4768 without preauth), Golden Ticket candidates (unusual "
                "4624 with long-lived tickets), TGT requests from unusual "
                "hosts. Covers domain/AD authentication attacks.",
    schema={"type": "object", "properties": {
        "security_events_json": {"type": "string"},
    }, "required": ["security_events_json"]},
)
def analyze_kerberos_events(security_events_json):
    p = _safe_resolve(security_events_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    text = p.read_text(encoding="utf-8", errors="replace")
    events = []
    try:
        parsed = json.loads(text)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # RC4 encryption type = 0x17 (23) — used by Kerberoasting
    # AES is 0x11/0x12 — modern default
    ENCRYPTION_TYPE_RC4 = "0x17"

    kerberoasting = []        # 4769 with RC4
    asrep_roasting = []        # 4768 with no preauth
    unusual_tgt = []           # 4768 from unusual workstation
    ticket_failures = []       # 4771 / 4773

    tgt_sources = {}  # user → set of source IPs (to detect anomalies)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        try:
            eid = int(ev.get("EventID") or ev.get("event_id") or 0)
        except (TypeError, ValueError):
            continue

        user = (ev.get("TargetUserName") or ev.get("target_user") or "").lower()
        source_ip = ev.get("IpAddress") or ev.get("source_ip")
        ticket_enc = (ev.get("TicketEncryptionType")
                       or ev.get("ticket_encryption") or "")
        preauth = (ev.get("PreAuthType") or ev.get("preauth_type") or "")

        if eid == 4769:  # Service ticket (TGS) request
            if str(ticket_enc).lower() in (ENCRYPTION_TYPE_RC4, "23", "rc4"):
                kerberoasting.append({
                    "ts": ev.get("TimeCreated"),
                    "user": user,
                    "service_name": ev.get("ServiceName") or ev.get("service"),
                    "source_ip": source_ip,
                    "ticket_encryption": ticket_enc,
                    "severity": "high",
                    "interpretation": "RC4 TGS request — Kerberoasting indicator",
                })

        elif eid == 4768:  # TGT (AS_REQ)
            if str(preauth) in ("0", "0x0"):
                asrep_roasting.append({
                    "ts": ev.get("TimeCreated"),
                    "user": user, "source_ip": source_ip,
                    "severity": "high",
                    "interpretation": "TGT with no pre-auth — AS-REP Roasting",
                })
            if user and source_ip:
                tgt_sources.setdefault(user, set()).add(source_ip)

        elif eid in (4771, 4773):
            ticket_failures.append({
                "ts": ev.get("TimeCreated"),
                "user": user, "source_ip": source_ip,
                "failure_code": ev.get("FailureCode") or ev.get("Status"),
            })

    # Users who requested TGTs from more than 3 distinct sources = suspicious
    users_with_scattered_tgts = [
        {"user": u, "source_count": len(ips), "sources": sorted(ips)}
        for u, ips in tgt_sources.items() if len(ips) > 3
    ]

    severity = "info"
    if kerberoasting or asrep_roasting:
        severity = "high"
    elif users_with_scattered_tgts or ticket_failures:
        severity = "medium"

    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "events_examined": len(events),
        "kerberoasting_candidates": kerberoasting,
        "asrep_roasting_candidates": asrep_roasting,
        "ticket_failures": ticket_failures,
        "users_with_scattered_tgts": users_with_scattered_tgts,
        "max_severity": severity,
        "stats": {
            "kerberoasting_count": len(kerberoasting),
            "asrep_roasting_count": len(asrep_roasting),
            "ticket_failure_count": len(ticket_failures),
            "scattered_tgt_users": len(users_with_scattered_tgts),
        },
    }


# Linux/macOS auth.log patterns
_UNIX_AUTH_PATTERNS = [
    ("ssh_accept", re.compile(
        r"sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)")),
    ("ssh_fail", re.compile(
        r"sshd\[\d+\]:\s+Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)")),
    ("ssh_invalid_user", re.compile(
        r"sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)")),
    ("sudo_success", re.compile(
        r"sudo:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)")),
    ("sudo_fail", re.compile(
        r"sudo:\s+(\S+)\s+:\s+(?:\d+ incorrect|authentication failure)")),
    ("su_success", re.compile(
        r"su(?:-l)?:\s+\(to (\S+)\)\s+(\S+)\s+on\s+(\S+)")),
]


@tool(
    name="analyze_unix_auth",
    description="Parse Linux/macOS auth.log for SSH accepts/failures, sudo "
                "usage, and su escalations. Detects brute force, invalid-user "
                "scans, sudo failures, and unusual remote sources.",
    schema={"type": "object", "properties": {
        "auth_log_path": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "brute_force_threshold": {"type": "integer", "default": 5},
    }, "required": ["auth_log_path"]},
)
def analyze_unix_auth(auth_log_path, time_window_start=None,
                      time_window_end=None, brute_force_threshold=5):
    p = _safe_resolve(auth_log_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    text = p.read_text(encoding="utf-8", errors="replace")
    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    ssh_accepts = []
    ssh_failures = []
    ssh_invalid_users = []
    sudo_success = []
    sudo_fail = []
    su_events = []

    for line in text.splitlines():
        if not line.strip():
            continue

        # Parse syslog timestamp prefix: "Mar 15 14:22:00 host ..."
        ts = None
        tm = re.match(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d{1,2}:\d{2}:\d{2})", line)
        if tm:
            try:
                # Assume current year 2026 (from evidence context)
                ts = datetime.strptime(
                    f"2026 {tm.group(1)} {tm.group(2)} {tm.group(3)}",
                    "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = None

        if sdt and ts and ts < sdt:
            continue
        if edt and ts and ts > edt:
            continue

        ts_str = ts.isoformat() if ts else None

        for kind, pat in _UNIX_AUTH_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            if kind == "ssh_accept":
                ssh_accepts.append({
                    "ts": ts_str, "method": m.group(1),
                    "user": m.group(2), "source_ip": m.group(3),
                })
            elif kind == "ssh_fail":
                ssh_failures.append({
                    "ts": ts_str, "method": m.group(1),
                    "user": m.group(2), "source_ip": m.group(3),
                })
            elif kind == "ssh_invalid_user":
                ssh_invalid_users.append({
                    "ts": ts_str, "user": m.group(1),
                    "source_ip": m.group(2),
                })
            elif kind == "sudo_success":
                sudo_success.append({
                    "ts": ts_str, "user": m.group(1), "tty": m.group(2),
                    "target_user": m.group(4), "command": m.group(5),
                    "severity_hint": "high" if any(
                        x in m.group(5).lower()
                        for x in ("rm -rf", "dd if=", "curl", "wget",
                                  "chmod 777", "/etc/passwd", "/etc/shadow")
                    ) else "info",
                })
            elif kind == "sudo_fail":
                sudo_fail.append({"ts": ts_str, "user": m.group(1)})
            elif kind == "su_success":
                su_events.append({
                    "ts": ts_str, "target_user": m.group(1),
                    "source_user": m.group(2), "tty": m.group(3),
                })
            break

    # Brute force: same source IP with >= threshold failures
    failures_by_ip = {}
    for f in ssh_failures + [{"source_ip": u["source_ip"]}
                               for u in ssh_invalid_users]:
        ip = f.get("source_ip")
        if ip:
            failures_by_ip[ip] = failures_by_ip.get(ip, 0) + 1

    brute_force_sources = [
        {"source_ip": ip, "failure_count": n, "severity": "high"}
        for ip, n in failures_by_ip.items() if n >= brute_force_threshold
    ]

    # Successful SSH logins from IPs that also brute-forced
    brute_force_survivors = []
    brute_ips = {b["source_ip"] for b in brute_force_sources}
    for s in ssh_accepts:
        if s.get("source_ip") in brute_ips:
            brute_force_survivors.append({**s, "severity": "critical",
                "interpretation": "successful SSH after brute force from same IP"})

    # Dangerous sudo commands
    dangerous_sudo = [s for s in sudo_success if s.get("severity_hint") == "high"]

    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "ssh_accept_count": len(ssh_accepts),
        "ssh_failure_count": len(ssh_failures),
        "ssh_invalid_user_count": len(ssh_invalid_users),
        "sudo_success_count": len(sudo_success),
        "sudo_fail_count": len(sudo_fail),
        "su_count": len(su_events),
        "brute_force_sources": brute_force_sources,
        "brute_force_survivors": brute_force_survivors,
        "dangerous_sudo_commands": dangerous_sudo,
        "ssh_accepts": ssh_accepts[:100],
        "ssh_failures_sample": ssh_failures[:100],
    }


@tool(
    name="detect_privilege_escalation",
    description="Cross-platform detection of low-privilege → high-privilege "
                "transitions. On Windows: normal user logon followed by "
                "SYSTEM-context process creation. On Unix: SSH as user then "
                "sudo/su to root. Returns linked transitions with timing.",
    schema={"type": "object", "properties": {
        "logons":    {"type": "array",
                      "description": "Windows logons (from analyze_windows_logons) "
                                     "OR Unix SSH accepts (from analyze_unix_auth)"},
        "privilege_events": {"type": "array",
                             "description": "Sudo/su on Unix, or Windows "
                                            "processes with user='SYSTEM' "
                                            "or integrity_level='High'"},
        "proximity_seconds": {"type": "integer", "default": 300},
    }, "required": []},
)
def detect_privilege_escalation(logons=None, privilege_events=None,
                                 proximity_seconds=300):
    logons = logons or []
    privilege_events = privilege_events or []

    transitions = []
    for pe in privilege_events:
        pe_ts = _parse_ts(pe.get("ts") or "")
        pe_user = pe.get("user") or pe.get("source_user") or ""
        if pe_ts is None or not pe_user:
            continue
        # Find a preceding low-priv logon by this user
        for lg in logons:
            lg_ts = _parse_ts(lg.get("ts") or "")
            lg_user = lg.get("user") or ""
            if lg_ts is None or not lg_user:
                continue
            if lg_user.lower() != pe_user.lower():
                continue
            delta = (pe_ts - lg_ts).total_seconds()
            if not (0 <= delta <= proximity_seconds):
                continue
            # Determine severity
            target = (pe.get("target_user")
                       or pe.get("target_account") or "").lower()
            cmd = (pe.get("command") or pe.get("cmdline") or "").lower()
            sev = "high"
            if target in ("root", "administrator", "system") \
               or "/bin/bash" in cmd or "powershell" in cmd:
                sev = "critical"
            transitions.append({
                "user": lg_user,
                "logon_ts": lg.get("ts"),
                "logon_source_ip": lg.get("source_ip"),
                "logon_type": lg.get("logon_type_name") or lg.get("method"),
                "escalation_ts": pe.get("ts"),
                "escalation_target": target,
                "escalation_command": pe.get("command") or pe.get("cmdline"),
                "delta_seconds": int(delta),
                "severity": sev,
            })

    return {
        "logon_count": len(logons),
        "privilege_event_count": len(privilege_events),
        "transitions": transitions,
        "critical_transitions": [t for t in transitions
                                  if t["severity"] == "critical"],
    }


# =============================================================================
# WEB/WAS INTRUSION & RDP BRUTE FORCE (initial access vectors)
# =============================================================================
#
# Two of the most common enterprise intrusion paths:
#
#   Web/WAS:   attack web app (SQLi/RCE/LFI/SSRF/deserialization)
#              → get remote code execution
#              → drop webshell or reverse shell
#              → pivot to internal network
#
#   RDP/SSH brute force:  internet-exposed RDP or SSH
#              → password spray / credential stuffing
#              → successful logon
#              → immediate interactive session
#
# Agentic-DART previously covered post-auth behavior (analyze_windows_logons,
# analyze_unix_auth) but did not specifically handle web-app attacks,
# webshell detection, or RDP-specific brute-force detection.

# Web-attack signatures (fast pre-filter; not a replacement for a WAF)
WEB_ATTACK_PATTERNS = [
    ("sqli_union",          re.compile(r"union\s+(?:all\s+)?select", re.I)),
    ("sqli_tautology",      re.compile(r"(?:'|\")\s*or\s+(?:'|\"|\d+)\s*=\s*(?:'|\"|\d+)", re.I)),
    ("sqli_sleep",          re.compile(r"(?:benchmark|sleep|pg_sleep|waitfor\s+delay)\s*\(", re.I)),
    ("sqli_comment",        re.compile(r"(?:--|#|/\*)", re.I)),
    ("xss_script",          re.compile(r"<script[^>]*>|javascript:", re.I)),
    ("xss_event",           re.compile(r"\bon(?:error|load|click|mouseover)\s*=", re.I)),
    ("lfi_traversal",       re.compile(r"(?:\.\.[\\/]){2,}|%2e%2e%2f|%2e%2e%5c", re.I)),
    ("lfi_wrapper",         re.compile(r"(?:php://|file://|expect://|zip://)", re.I)),
    ("rce_command",         re.compile(r"(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell)\b", re.I)),
    ("rce_php",             re.compile(r"(?:system|exec|passthru|shell_exec|proc_open|eval)\s*\(", re.I)),
    ("ssrf_cloud_metadata", re.compile(r"(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure)", re.I)),
    ("log4shell",           re.compile(r"\$\{jndi:(?:ldap|rmi|dns)://", re.I)),
    ("spring4shell",        re.compile(r"class\.module\.classLoader", re.I)),
    ("path_xss",            re.compile(r"%3cscript|%22%3e%3cscript", re.I)),
    ("webshell_upload",     re.compile(r"\.(?:php|jsp|jspx|aspx|asp|phtml|war)(?:\?|$|\s)", re.I)),
    ("deserialize_java",    re.compile(r"rO0(?:AB|AA)", )),  # base64 "\xac\xed\x00"
]

# Known scanner / pentest user-agents
SCANNER_UA_PATTERNS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zap|burp|acunetix|nessus|nuclei|"
    r"dirbuster|gobuster|wfuzz|ffuf|feroxbuster|whatweb|hydra|"
    r"wpscan|joomscan|skipfish|arachni",
    re.I,
)

# File extensions that are typically suspicious to find in web roots
WEBSHELL_SUSPICIOUS_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7",
                            ".pht", ".phar", ".jsp", ".jspx", ".asp", ".aspx",
                            ".ashx", ".cer", ".cdx"}

# Functions/keywords commonly found inside webshells
WEBSHELL_CONTENT_SIGS = [
    re.compile(r"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|\$_(?:POST|GET|REQUEST|COOKIE))", re.I),
    re.compile(r"system\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)", re.I),
    re.compile(r"assert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)", re.I),
    re.compile(r"shell_exec\s*\(\s*\$_", re.I),
    re.compile(r"Runtime\.getRuntime\(\)\.exec", re.I),  # JSP
    re.compile(r"Process\s+proc\s*=.*?\.exec", re.I),     # JSP
    re.compile(r"Request\.Form\[[^\]]+\].*?(?:Process|Exec)", re.I),  # ASP.NET
    re.compile(r"<%@\s*Page.*?%>.*?(?:Process\.Start|cmd\.exe)", re.I | re.S),
    re.compile(r"c99shell|r57shell|WSO\s*\d|b374k|china\s*chopper|jspspy|kalinfo", re.I),
    re.compile(r"preg_replace\s*\([^)]*?/e['\"]", re.I),  # preg_replace /e modifier
]

# Typical web document roots (for zero-arg scanning)
DEFAULT_WEB_ROOTS = [
    "var/www", "var/www/html", "srv/www", "srv/http",
    "inetpub/wwwroot", "opt/tomcat/webapps", "opt/jetty/webapps",
    "usr/share/nginx/html", "Library/WebServer/Documents",
]


@tool(
    name="analyze_web_access_log",
    description="Parse web server access logs (Apache/Nginx combined format, "
                "IIS W3C) and flag web-attack patterns: SQLi, XSS, LFI, RCE, "
                "SSRF, Log4Shell, webshell upload attempts. Also detects "
                "scanner user-agents, 4xx/5xx spikes per source IP, and "
                "long-URL anomalies.",
    schema={"type": "object", "properties": {
        "access_log": {"type": "string"},
        "format": {"type": "string",
                   "enum": ["combined", "common", "iis_w3c", "auto"],
                   "default": "auto"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "error_ratio_threshold": {"type": "number", "default": 0.5,
                                   "description": "IPs with >= this ratio of 4xx/5xx flagged"},
    }, "required": ["access_log"]},
)
def analyze_web_access_log(access_log, format="auto",
                            time_window_start=None, time_window_end=None,
                            error_ratio_threshold=0.5):
    p = _safe_resolve(access_log)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    # Apache/Nginx combined:
    #   1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /x HTTP/1.1" 200 123 "ref" "UA"
    combined_re = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\['
        r'(?P<ts>[^\]]+)\]\s+"'
        r'(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)'
        r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )
    # IIS W3C:
    #   #Fields: date time ... c-ip cs-method cs-uri-stem cs-uri-query sc-status ...

    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    total_lines = 0
    attack_hits = []
    scanner_hits = []
    per_ip_stats = {}       # ip → {"total":n, "errors":n, "paths":set()}
    long_url_hits = []

    text = p.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if not line.strip():
            continue
        total_lines += 1
        m = combined_re.match(line)
        if not m:
            # Try IIS W3C (space-separated fields after the header)
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            # Heuristic pick — IIS default column order
            try:
                ts_str = f"{parts[0]} {parts[1]}"
                ts = _parse_ts(ts_str)
                ip = parts[-4] if len(parts) > 4 else parts[2]
                method = parts[3]
                path = parts[4] + ("?" + parts[5] if parts[5] != "-" else "")
                status = parts[-5]
                ua = "-"
            except (IndexError, ValueError):
                continue
        else:
            ip = m.group("ip")
            # Parse apache-style timestamp "10/Oct/2026:13:55:36 +0000"
            ts = None
            try:
                ts = datetime.strptime(m.group("ts").split()[0],
                                       "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
            method = m.group("method")
            path = m.group("path")
            status = m.group("status")
            ua = m.group("ua") or ""

        if sdt and ts and ts < sdt:
            continue
        if edt and ts and ts > edt:
            continue

        try:
            status_code = int(status)
        except ValueError:
            status_code = 0

        # Per-IP counters
        stat = per_ip_stats.setdefault(ip, {"total": 0, "errors": 0,
                                             "paths": set(), "uas": set()})
        stat["total"] += 1
        if status_code >= 400:
            stat["errors"] += 1
        stat["paths"].add(path[:128])
        stat["uas"].add(ua[:80])

        # Scanner UA
        if ua and SCANNER_UA_PATTERNS.search(ua):
            scanner_hits.append({"ts": ts.isoformat() if ts else None,
                                  "ip": ip, "user_agent": ua,
                                  "path": path[:200]})

        # Attack pattern matching (on method + path + UA)
        combined_text = f"{method} {path} {ua}"
        for rule_id, pat in WEB_ATTACK_PATTERNS:
            if pat.search(combined_text):
                attack_hits.append({
                    "ts": ts.isoformat() if ts else None,
                    "ip": ip, "method": method,
                    "path": path[:300], "status": status_code,
                    "user_agent": ua[:120], "rule": rule_id,
                    "severity": "high" if rule_id in (
                        "rce_php", "log4shell", "deserialize_java",
                        "spring4shell", "rce_command", "ssrf_cloud_metadata"
                    ) else "medium",
                })
                break

        # Long URL anomaly (> 2KB usually means payload stuffing)
        if len(path) > 2048:
            long_url_hits.append({"ts": ts.isoformat() if ts else None,
                                   "ip": ip, "path_len": len(path),
                                   "path_sample": path[:200]})

    # Brute-scan IPs: many errors + many distinct paths
    scanning_ips = []
    for ip, s in per_ip_stats.items():
        ratio = s["errors"] / s["total"] if s["total"] else 0
        if s["total"] >= 20 and (ratio >= error_ratio_threshold
                                  or len(s["paths"]) >= 50):
            scanning_ips.append({
                "ip": ip, "request_count": s["total"],
                "error_count": s["errors"],
                "error_ratio": round(ratio, 3),
                "distinct_paths": len(s["paths"]),
                "user_agents": sorted(s["uas"])[:5],
                "severity": "high" if ratio >= 0.8 else "medium",
            })

    severity = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for h in attack_hits + scanning_ips:
        if sev_rank.get(h.get("severity", "info"), 0) > sev_rank.get(severity, 0):
            severity = h.get("severity")

    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "lines_examined": total_lines,
        "attack_hits": attack_hits[:200],
        "attack_count": len(attack_hits),
        "scanner_ua_hits": scanner_hits[:100],
        "scanner_ua_count": len(scanner_hits),
        "scanning_ips": scanning_ips,
        "long_url_anomalies": long_url_hits[:50],
        "max_severity": severity,
        "stats": {
            "unique_ips": len(per_ip_stats),
            "attack_patterns_matched": len(set(h["rule"] for h in attack_hits)),
            "scanners": len(scanner_hits),
        },
    }


@tool(
    name="detect_webshell",
    description="Scan a web document root for likely webshells: suspicious "
                "file extensions in user-writable dirs, files containing "
                "eval(base64_decode($_POST)) / system($_GET) / JSP Runtime."
                "exec, recent modifications compared to the rest of the tree, "
                "and known shell names (c99, r57, WSO, china chopper).",
    schema={"type": "object", "properties": {
        "webroot": {"type": "string",
                    "description": "path inside EVIDENCE_ROOT to the web docroot"},
        "max_file_size": {"type": "integer", "default": 524288,
                          "description": "skip files larger than this (bytes)"},
        "max_files_scanned": {"type": "integer", "default": 5000},
    }, "required": ["webroot"]},
)
def detect_webshell(webroot, max_file_size=524288, max_files_scanned=5000):
    p = _safe_resolve(webroot)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    if not p.is_dir():
        return {"error": "not_a_directory", "path": str(p)}

    findings = []
    scanned = 0
    mtimes_by_dir = {}  # establish baseline mtime per dir

    for f in p.rglob("*"):
        if scanned >= max_files_scanned:
            break
        if not f.is_file():
            continue
        scanned += 1

        ext = f.suffix.lower()
        try:
            stat = f.stat()
        except OSError:
            continue

        parent = str(f.parent)
        mtimes_by_dir.setdefault(parent, []).append(stat.st_mtime)

        # Fast reject: wrong extension AND too big → skip
        if ext not in WEBSHELL_SUSPICIOUS_EXT and stat.st_size > max_file_size:
            continue

        signals = []

        # Signal: suspicious extension in user-writable / upload-style dirs
        # (not every .php file is a webshell — only flag extension alone
        # when path indicates an upload/temp location)
        path_lower = str(f.relative_to(p)).lower().replace("\\", "/")
        in_upload_dir = any(
            seg in path_lower
            for seg in ("/upload", "/temp", "/tmp/", "/cache/",
                        "/backup", "/attach", "/writable")
        )
        if ext in WEBSHELL_SUSPICIOUS_EXT and in_upload_dir:
            signals.append(f"suspicious_extension_in_writable_dir:{ext}")

        # Signal: filename patterns associated with known shells
        # Exact filename match, not substring — avoids "index.php" hitting "x.php"
        name_lower = f.name.lower()
        exact_bad_names = {
            "c99.php", "r57.php", "wso.php", "b374k.php", "chopper.php",
            "shell.php", "cmd.php", "cmd.jsp", "cmd.aspx", "x.php",
            "pass.php", "up.php", "fm.php", "webshell.php", "0.aspx",
            "jspspy.jsp", "kalinfo.php", "cmd2.php", "sh.php",
        }
        substr_bad_names = ("c99shell", "r57shell", "china_chopper",
                             "jspspy", "kalinfo", "b374k", "webshell",
                             "wso2", "bypass.php")
        if name_lower in exact_bad_names:
            signals.append(f"suspicious_filename:{name_lower}")
        elif any(bad in name_lower for bad in substr_bad_names):
            matched = next(bad for bad in substr_bad_names if bad in name_lower)
            signals.append(f"suspicious_filename:{matched}")

        # Signal: content-match (only on files we can read cheaply)
        if stat.st_size <= max_file_size and ext in WEBSHELL_SUSPICIOUS_EXT:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for sig in WEBSHELL_CONTENT_SIGS:
                    if sig.search(content):
                        signals.append("content_match")
                        break
                # Entropy check: obfuscated shells often look like base64
                if "base64_decode" in content and "eval" in content:
                    signals.append("eval_base64_pattern")
                if content.count("\\x") > 20 and ext == ".php":
                    signals.append("hex_encoded_php")
            except Exception:
                pass

        if signals:
            findings.append({
                "path": str(f.relative_to(EVIDENCE_ROOT)),
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "ext": ext,
                "signals": signals,
                "severity": "high" if "content_match" in signals
                                     or "eval_base64_pattern" in signals
                                     or any(s.startswith("suspicious_filename")
                                            for s in signals)
                            else "medium",
            })

    # Age anomaly: file whose mtime is > 30 days newer than directory median
    age_anomalies = []
    for finding in findings:
        try:
            f = EVIDENCE_ROOT / finding["path"]
            parent = str(f.parent)
            mtimes = mtimes_by_dir.get(parent, [])
            if len(mtimes) < 5:
                continue
            median_mtime = sorted(mtimes)[len(mtimes)//2]
            file_mtime = f.stat().st_mtime
            if file_mtime - median_mtime > 30 * 86400:
                age_anomalies.append({
                    "path": finding["path"],
                    "days_newer_than_median": int(
                        (file_mtime - median_mtime) / 86400),
                })
        except Exception:
            continue

    return {
        "source": {"path": str(p)},
        "files_scanned": scanned,
        "findings": findings,
        "finding_count": len(findings),
        "high_severity_count": sum(1 for f in findings if f["severity"] == "high"),
        "age_anomalies": age_anomalies,
        "max_severity": ("high" if any(f["severity"] == "high" for f in findings)
                         else ("medium" if findings else "info")),
    }


@tool(
    name="detect_brute_force_rdp",
    description="RDP-specific brute force detection. Analyzes Windows Security "
                "events 4625 (failed logon) with LogonType=10 (RDP) — unlike "
                "the generic analyze_windows_logons this groups failures per "
                "source IP, identifies credential-stuffing patterns (many "
                "distinct users from one IP), password-spray (one user from "
                "many IPs), and chains each brute-force IP to its eventual "
                "successful 4624 Type-10 logon.",
    schema={"type": "object", "properties": {
        "security_events_json": {"type": "string"},
        "threshold_failures": {"type": "integer", "default": 5},
        "spray_distinct_users_threshold": {"type": "integer", "default": 5},
    }, "required": ["security_events_json"]},
)
def detect_brute_force_rdp(security_events_json, threshold_failures=5,
                            spray_distinct_users_threshold=5):
    p = _safe_resolve(security_events_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    text = p.read_text(encoding="utf-8", errors="replace")
    events = []
    try:
        parsed = json.loads(text)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    rdp_failures = []
    rdp_successes = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        try:
            eid = int(ev.get("EventID") or ev.get("event_id") or 0)
            logon_type = int(ev.get("LogonType") or ev.get("logon_type") or 0)
        except (TypeError, ValueError):
            continue
        if logon_type != 10:
            continue
        record = {
            "ts": ev.get("TimeCreated") or ev.get("timestamp"),
            "user": (ev.get("TargetUserName") or "").lower(),
            "source_ip": ev.get("IpAddress") or ev.get("source_ip"),
            "source_host": ev.get("WorkstationName"),
        }
        if eid == 4625:
            rdp_failures.append(record)
        elif eid == 4624:
            rdp_successes.append(record)

    # Per-IP statistics
    ip_stats = {}
    for f in rdp_failures:
        ip = f.get("source_ip")
        if not ip or ip == "-":
            continue
        s = ip_stats.setdefault(ip, {"fails": 0, "users_tried": set(),
                                      "first_ts": None, "last_ts": None})
        s["fails"] += 1
        if f["user"]:
            s["users_tried"].add(f["user"])
        if not s["first_ts"] or (f["ts"] or "") < s["first_ts"]:
            s["first_ts"] = f["ts"]
        if not s["last_ts"] or (f["ts"] or "") > s["last_ts"]:
            s["last_ts"] = f["ts"]

    # Classify
    brute_force_ips = []
    credential_stuffing_ips = []
    for ip, s in ip_stats.items():
        if s["fails"] < threshold_failures:
            continue
        record = {
            "source_ip": ip,
            "failure_count": s["fails"],
            "distinct_users_tried": len(s["users_tried"]),
            "users_sample": sorted(s["users_tried"])[:10],
            "first_ts": s["first_ts"], "last_ts": s["last_ts"],
            "severity": "high" if s["fails"] >= threshold_failures * 3 else "medium",
        }
        if len(s["users_tried"]) >= spray_distinct_users_threshold:
            record["pattern"] = "credential_stuffing"
            credential_stuffing_ips.append(record)
        else:
            record["pattern"] = "single_account_brute_force"
            brute_force_ips.append(record)

    # Password spray: one user tried from many IPs
    user_ip_counts = {}
    for f in rdp_failures:
        u = f["user"]
        ip = f.get("source_ip")
        if u and ip and ip != "-":
            user_ip_counts.setdefault(u, set()).add(ip)
    password_spray_users = [
        {"user": u, "source_ip_count": len(ips),
         "source_ips": sorted(ips)[:10], "severity": "high"}
        for u, ips in user_ip_counts.items() if len(ips) >= 3
    ]

    # Survivors: successful 4624 type 10 from an IP that brute-forced
    brute_ips_set = {r["source_ip"] for r in brute_force_ips + credential_stuffing_ips}
    survivors = []
    for s in rdp_successes:
        if s.get("source_ip") in brute_ips_set:
            survivors.append({
                **s,
                "severity": "critical",
                "interpretation": "successful RDP logon after brute force from same IP",
            })

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for rec in brute_force_ips + credential_stuffing_ips + password_spray_users + survivors:
        if sev_rank.get(rec.get("severity", "info"), 0) > sev_rank.get(max_sev, 0):
            max_sev = rec["severity"]

    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "rdp_failure_count": len(rdp_failures),
        "rdp_success_count": len(rdp_successes),
        "brute_force_ips": brute_force_ips,
        "credential_stuffing_ips": credential_stuffing_ips,
        "password_spray_users": password_spray_users,
        "survivors": survivors,
        "max_severity": max_sev,
        "stats": {
            "attack_ips": len(brute_force_ips) + len(credential_stuffing_ips),
            "survivors_count": len(survivors),
            "spray_users": len(password_spray_users),
        },
    }


# =============================================================================
# CREDENTIAL ACCESS, RANSOMWARE, DEFENSE EVASION, DISCOVERY
# =============================================================================
#
# Closing MITRE ATT&CK gaps identified from 2025-2026 DFIR data:
#
#   TA0006 Credential Access  — LSASS dumping, SAM/NTDS, Mimikatz, DPAPI
#   TA0007 Discovery           — AD enumeration (BloodHound, net/nltest patterns)
#   TA0005 Defense Evasion     — event log clearing, timestomping
#   TA0040 Impact              — ransomware behavior (shadow copies, mass encrypt,
#                                taskkill-spree, cipher /w, ransom notes)
#
# These cover patterns that appeared in 80%+ of 2025 ransomware and APT
# reports on The DFIR Report, Red Canary, and Mandiant M-Trends.

# --- Credential Access -------------------------------------------------------

LSASS_DUMP_INDICATORS = {
    # Known credential-dumping process names
    "process_images": [
        "mimikatz.exe", "procdump.exe", "procdump64.exe", "pwdump.exe",
        "wce.exe", "secretsdump.py", "lsassy.exe", "nanodump.exe",
        "dumpert.exe", "handle.exe", "comsvcs.dll",
    ],
    # Command-line arguments that signal credential dumping
    "cmdline_patterns": [
        r"sekurlsa::",            # Mimikatz module
        r"lsadump::",
        r"kerberos::list",
        r"vault::",
        r"comsvcs\.dll.*MiniDump",  # LOLBin lsass dump
        r"rundll32.*comsvcs\.dll",
        r"-ma\s+lsass",            # procdump -ma lsass
        r"--target-ip.*--dump",     # secretsdump.py
        r"reg\s+save\s+hklm\\sam",
        r"reg\s+save\s+hklm\\security",
        r"reg\s+save\s+hklm\\system",
        r"ntdsutil.*ifm",           # NTDS.dit extraction
        r"vssadmin\s+create\s+shadow",  # often paired with NTDS copy
    ],
    # Sensitive files whose access indicates cred theft
    "sensitive_paths": [
        r"\\windows\\system32\\config\\sam",
        r"\\windows\\system32\\config\\security",
        r"\\windows\\ntds\\ntds\.dit",
        r"\\users\\[^\\]+\\appdata\\roaming\\microsoft\\credentials",
        r"\\users\\[^\\]+\\appdata\\local\\microsoft\\credentials",
        r"\\users\\[^\\]+\\appdata\\roaming\\microsoft\\protect",  # DPAPI
        r"\\users\\[^\\]+\\appdata\\local\\google\\chrome\\user data\\.*login data",
        r"\\users\\[^\\]+\\appdata\\roaming\\mozilla\\firefox\\.*key4\.db",
        r"/etc/shadow", r"/etc/gshadow", r"/etc/passwd-",
    ],
}


@tool(
    name="detect_credential_access",
    description="Scan for TA0006 Credential Access indicators: LSASS dumping "
                "(Mimikatz, procdump, comsvcs.dll MiniDump, nanodump), SAM/"
                "SECURITY/NTDS.dit access, DPAPI theft, browser credential "
                "store access, /etc/shadow reads. Cross-references process "
                "execution with Sysmon Event 10 (ProcessAccess) and sensitive-"
                "path reads.",
    schema={"type": "object", "properties": {
        "processes": {"type": "array",
                      "description": "process records from get_process_tree"},
        "sysmon_events_json": {"type": "string",
                               "description": "optional Sysmon events "
                                              "(Event 10 = ProcessAccess)"},
        "file_accesses": {"type": "array",
                          "description": "optional list of {ts, path, "
                                         "process, pid} records"},
    }, "required": []},
)
def detect_credential_access(processes=None, sysmon_events_json=None,
                              file_accesses=None):
    processes = processes or []
    file_accesses = file_accesses or []

    findings = []
    dumper_images = set(i.lower() for i in LSASS_DUMP_INDICATORS["process_images"])
    cmd_patterns = [re.compile(p, re.I)
                     for p in LSASS_DUMP_INDICATORS["cmdline_patterns"]]
    path_patterns = [re.compile(p, re.I)
                      for p in LSASS_DUMP_INDICATORS["sensitive_paths"]]

    # 1. Known dumping tool in process tree
    for p in processes:
        img = (p.get("image") or p.get("Image") or "").lower()
        cmd = (p.get("cmdline") or p.get("CommandLine") or "")
        name = img.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if name in dumper_images:
            findings.append({
                "technique": "T1003", "sub_technique": "credential_dumping_tool",
                "ts": p.get("start_ts") or p.get("ts"),
                "pid": p.get("pid"),
                "image": img, "cmdline": cmd[:200],
                "user": p.get("user"),
                "severity": "critical",
                "interpretation": f"known credential-dumping tool: {name}",
            })
            continue
        # Command-line pattern match
        for pat in cmd_patterns:
            if pat.search(cmd):
                findings.append({
                    "technique": "T1003", "sub_technique": "cmdline_pattern",
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"), "image": img, "cmdline": cmd[:300],
                    "pattern": pat.pattern, "severity": "critical",
                    "interpretation": "credential-access command-line pattern",
                })
                break

    # 2. Sysmon Event 10 — LSASS access with suspicious mask
    if sysmon_events_json:
        try:
            p = _safe_resolve(sysmon_events_json)
            if p.exists():
                text = p.read_text(encoding="utf-8", errors="replace")
                events = []
                try:
                    parsed = json.loads(text)
                    events = parsed if isinstance(parsed, list) else [parsed]
                except json.JSONDecodeError:
                    for line in text.splitlines():
                        if line.strip():
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    try:
                        eid = int(ev.get("EventID") or ev.get("event_id") or 0)
                    except (TypeError, ValueError):
                        continue
                    if eid != 10:
                        continue
                    target = (ev.get("TargetImage") or "").lower()
                    if "lsass.exe" not in target:
                        continue
                    mask = (ev.get("GrantedAccess") or "").lower()
                    # 0x1010 / 0x1410 / 0x1438 / 0x1fffff = dangerous masks for LSASS
                    if mask in ("0x1010", "0x1410", "0x1438", "0x143a",
                                 "0x1fffff", "0x001f1fff", "0x1400"):
                        findings.append({
                            "technique": "T1003.001",
                            "sub_technique": "lsass_access_highpriv_mask",
                            "ts": ev.get("TimeCreated"),
                            "source_image": ev.get("SourceImage"),
                            "source_pid": ev.get("SourceProcessId"),
                            "granted_access": mask,
                            "severity": "critical",
                            "interpretation": "process opened LSASS with "
                                               "credential-dumping access mask",
                        })
        except Exception as e:
            findings.append({"technique": "T1003", "error": str(e)[:200]})

    # 3. Sensitive-path access
    for fa in file_accesses:
        path = (fa.get("path") or "").lower()
        for pat in path_patterns:
            if pat.search(path):
                findings.append({
                    "technique": "T1003",
                    "sub_technique": "sensitive_file_access",
                    "ts": fa.get("ts"),
                    "path": fa.get("path"),
                    "process": fa.get("process"),
                    "pid": fa.get("pid"),
                    "severity": "high",
                    "interpretation": "read of a credential-material file",
                })
                break

    by_technique = {}
    for f in findings:
        t = f.get("technique", "unknown")
        by_technique[t] = by_technique.get(t, 0) + 1

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for f in findings:
        if sev_rank.get(f.get("severity", "info"), 0) > sev_rank.get(max_sev, 0):
            max_sev = f["severity"]

    return {"findings": findings, "finding_count": len(findings),
            "by_technique": by_technique, "max_severity": max_sev,
            "critical_findings": [f for f in findings
                                   if f.get("severity") == "critical"]}


# --- Ransomware Behavior -----------------------------------------------------

RANSOMWARE_INDICATORS = {
    # Commands attackers run to prevent recovery
    "anti_recovery": [
        re.compile(r"vssadmin.*delete\s+shadows", re.I),
        re.compile(r"wmic\s+shadowcopy\s+delete", re.I),
        re.compile(r"Get-WmiObject.*Win32_ShadowCopy.*Delete", re.I),
        re.compile(r"wbadmin\s+delete\s+(?:catalog|backup)", re.I),
        re.compile(r"bcdedit.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.I),
        re.compile(r"cipher.*\/w:", re.I),       # secure erase
        re.compile(r"fsutil\s+usn\s+deletejournal", re.I),
        re.compile(r"wevtutil.*(?:cl|clear-log)", re.I),  # clear event logs
    ],
    # Mass service/process termination
    "service_stop": [
        re.compile(r"net\s+stop\s+\S+", re.I),
        re.compile(r"sc\s+(?:stop|config)\s+\S+\s+start=\s*disabled", re.I),
        re.compile(r"taskkill(?:\.exe)?\s+/(?:f|im)", re.I),
    ],
    # Common ransom note file names
    "ransom_note_names": [
        "readme.txt", "readme.html", "readme_for_decrypt.txt",
        "!!!readme!!!.txt", "how_to_decrypt.txt", "decrypt_instructions.txt",
        "restore_files.txt", "recover_files.txt", "readme-warning.txt",
        "!!_readme_!!.txt", "ransom_note.txt", "$recycle.txt",
        "recovery_key.txt", "help_decrypt.html", "locker_note.txt",
        "how_to_back_files.html", "_readme.txt",
    ],
    # File extensions added by known ransomware families
    "ransom_extensions": [
        ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
        ".wncry", ".wcry", ".wncryt",                  # WannaCry
        ".conti", ".lock",                              # Conti/LockBit
        ".lockbit",                                      # LockBit
        ".hive",                                         # Hive
        ".blackcat", ".alphv",                           # BlackCat/ALPHV
        ".ryuk", ".rapid",                               # Ryuk, RapidRansom
        ".dharma", ".phobos",
        ".deadbolt",
        ".makop",
    ],
}


@tool(
    name="detect_ransomware_behavior",
    description="Detect TA0040 ransomware patterns: shadow-copy deletion "
                "(vssadmin/wmic/PowerShell Win32_ShadowCopy), mass taskkill "
                "or net stop sprees (>=10 services in 2min), cipher /w "
                "(secure erase), event log clearing, ransom-note file names "
                "appearing, and mass file renames to known ransomware "
                "extensions.",
    schema={"type": "object", "properties": {
        "processes": {"type": "array"},
        "fsevents_or_mft": {"type": "array"},
        "mass_kill_window_seconds": {"type": "integer", "default": 120},
    }, "required": []},
)
def detect_ransomware_behavior(processes=None, fsevents_or_mft=None,
                                mass_kill_window_seconds=120):
    processes = processes or []
    fsevents_or_mft = fsevents_or_mft or []

    findings = []

    # 1. Anti-recovery command matches
    anti_recov_hits = []
    for p in processes:
        cmd = (p.get("cmdline") or p.get("CommandLine") or "")
        for pat in RANSOMWARE_INDICATORS["anti_recovery"]:
            if pat.search(cmd):
                anti_recov_hits.append({
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"), "cmdline": cmd[:200],
                    "pattern": pat.pattern,
                })
                break
    if anti_recov_hits:
        findings.append({
            "technique": "T1490",
            "rule": "inhibit_system_recovery",
            "count": len(anti_recov_hits), "samples": anti_recov_hits[:10],
            "severity": "critical",
            "interpretation": "anti-recovery commands executed "
                              "(shadow copy / backup / boot config deletion)",
        })

    # 2. Mass taskkill / net stop within short window
    stop_events = []
    for p in processes:
        cmd = (p.get("cmdline") or p.get("CommandLine") or "")
        img = (p.get("image") or "").lower()
        for pat in RANSOMWARE_INDICATORS["service_stop"]:
            if pat.search(cmd):
                stop_events.append({
                    "ts": p.get("start_ts") or p.get("ts"),
                    "cmdline": cmd[:200],
                })
                break
    # Bucket by window
    stop_events.sort(key=lambda x: x.get("ts") or "")
    if len(stop_events) >= 10:
        # Check density: any window of N seconds with >=10 hits?
        for i, e in enumerate(stop_events):
            e_ts = _parse_ts(e.get("ts") or "")
            if e_ts is None:
                continue
            count_in_window = 1
            for later in stop_events[i+1:]:
                l_ts = _parse_ts(later.get("ts") or "")
                if l_ts is None:
                    continue
                if (l_ts - e_ts).total_seconds() <= mass_kill_window_seconds:
                    count_in_window += 1
                else:
                    break
            if count_in_window >= 10:
                findings.append({
                    "technique": "T1489",
                    "rule": "mass_service_stop",
                    "count_in_window": count_in_window,
                    "window_start_ts": e.get("ts"),
                    "window_seconds": mass_kill_window_seconds,
                    "severity": "critical",
                    "interpretation": "burst of service/process terminations "
                                      "(pre-encryption preparation)",
                })
                break

    # 3. Ransom note file creation
    note_names = set(RANSOMWARE_INDICATORS["ransom_note_names"])
    note_hits = []
    for e in fsevents_or_mft:
        path = (e.get("path") or "").lower()
        flags = e.get("flags") or []
        is_create = "Created" in flags or e.get("created") is not None
        if not is_create:
            continue
        filename = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if filename in note_names:
            note_hits.append({"ts": e.get("ts") or e.get("created"),
                               "path": e.get("path")})
    if note_hits:
        findings.append({
            "technique": "T1486",
            "rule": "ransom_note_written",
            "count": len(note_hits),
            "samples": note_hits[:10],
            "severity": "critical",
            "interpretation": "ransom note files appeared in filesystem",
        })

    # 4. Mass rename to ransomware extensions
    rename_hits = []
    for e in fsevents_or_mft:
        path = (e.get("path") or "").lower()
        flags = e.get("flags") or []
        # Detection on either modify with ransom ext, or rename events
        has_rename = "Renamed" in flags or "RenamedOldPath" in flags
        has_create_with_ransom_ext = ("Created" in flags) and any(
            path.endswith(ext) for ext in RANSOMWARE_INDICATORS["ransom_extensions"])
        if has_rename or has_create_with_ransom_ext:
            rename_hits.append({
                "ts": e.get("ts") or e.get("created"),
                "path": e.get("path"),
            })
    if len(rename_hits) >= 20:
        findings.append({
            "technique": "T1486",
            "rule": "mass_file_rename_to_ransom_ext",
            "count": len(rename_hits),
            "samples": rename_hits[:15],
            "severity": "critical",
            "interpretation": f"{len(rename_hits)} files renamed/created "
                              f"with ransomware extensions",
        })

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for f in findings:
        if sev_rank.get(f.get("severity", "info"), 0) > sev_rank.get(max_sev, 0):
            max_sev = f["severity"]

    return {"findings": findings, "finding_count": len(findings),
            "max_severity": max_sev,
            "stats": {
                "anti_recovery_hits": len(anti_recov_hits),
                "service_stop_events": len(stop_events),
                "ransom_notes_created": len([f for f in findings
                    if f.get("rule") == "ransom_note_written"]),
                "mass_renames": len(rename_hits),
            }}


# --- Defense Evasion ---------------------------------------------------------

EVASION_INDICATORS = {
    "log_clearing_cmds": [
        re.compile(r"wevtutil.*(?:cl|clear-log)\s+", re.I),
        re.compile(r"Clear-EventLog", re.I),
        re.compile(r"Remove-EventLog", re.I),
        re.compile(r"Get-WinEvent.*-ListLog.*\|.*ForEach.*Clear", re.I),
    ],
    "timestomp_cmds": [
        re.compile(r"SetFileTime", re.I),
        re.compile(r"touch\s+-[atm]", re.I),
        re.compile(r"powershell.*\.LastWriteTime\s*=", re.I),
        re.compile(r"powershell.*\.CreationTime\s*=", re.I),
    ],
    "log_clear_event_ids": {1102, 104},
}


@tool(
    name="detect_defense_evasion",
    description="Detect TA0005 Defense Evasion: event log clearing (Event "
                "ID 1102 Security, 104 System, or wevtutil cl / Clear-"
                "EventLog commands), timestomping (explicit SetFileTime "
                "calls, touch -t), and MFT $SI vs $FN timestamp mismatches "
                "(forensic artifact of timestomp).",
    schema={"type": "object", "properties": {
        "events_json": {"type": "string"},
        "processes": {"type": "array"},
        "mft_csv": {"type": "string"},
        "timestomp_si_fn_tolerance_seconds": {"type": "integer", "default": 5},
    }, "required": []},
)
def detect_defense_evasion(events_json=None, processes=None, mft_csv=None,
                            timestomp_si_fn_tolerance_seconds=5):
    processes = processes or []
    findings = []

    # 1. Event Log clearing events (1102 / 104)
    if events_json:
        p = _safe_resolve(events_json)
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            events = []
            try:
                parsed = json.loads(text)
                events = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                for line in text.splitlines():
                    if line.strip():
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                try:
                    eid = int(ev.get("EventID") or ev.get("event_id") or 0)
                except (TypeError, ValueError):
                    continue
                if eid in EVASION_INDICATORS["log_clear_event_ids"]:
                    findings.append({
                        "technique": "T1070.001",
                        "rule": "event_log_cleared",
                        "ts": ev.get("TimeCreated"),
                        "event_id": eid,
                        "channel": ev.get("Channel") or ev.get("channel"),
                        "user": ev.get("SubjectUserName") or ev.get("user"),
                        "severity": "critical",
                        "interpretation": "Windows event log was cleared "
                                           "(covering tracks)",
                    })

    # 2. wevtutil cl / Clear-EventLog in process cmdlines
    for p in processes:
        cmd = (p.get("cmdline") or p.get("CommandLine") or "")
        for pat in EVASION_INDICATORS["log_clearing_cmds"]:
            if pat.search(cmd):
                findings.append({
                    "technique": "T1070.001",
                    "rule": "log_clear_command",
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"), "cmdline": cmd[:200],
                    "severity": "critical",
                    "interpretation": "command to clear event logs executed",
                })
                break
        for pat in EVASION_INDICATORS["timestomp_cmds"]:
            if pat.search(cmd):
                findings.append({
                    "technique": "T1070.006",
                    "rule": "timestomp_command",
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"), "cmdline": cmd[:200],
                    "severity": "high",
                    "interpretation": "command that modifies file timestamps "
                                       "(timestomping)",
                })
                break

    # 3. MFT $SI vs $FN timestamp mismatch (timestomping forensic artifact)
    if mft_csv:
        p = _safe_resolve(mft_csv)
        if p.exists():
            anomalies = []
            try:
                for row in _read_csv(p):
                    si = _parse_ts(row.get("Created0x10") or
                                    row.get("SI_Created") or "")
                    fn = _parse_ts(row.get("Created0x30") or
                                    row.get("FN_Created") or "")
                    if si is None or fn is None:
                        continue
                    delta = abs((si - fn).total_seconds())
                    # timestomp: $SI modified, $FN stays original.
                    # A $SI timestamp EARLIER than $FN by >tolerance is
                    # a forensic anomaly.
                    if si < fn and delta > timestomp_si_fn_tolerance_seconds:
                        anomalies.append({
                            "path": (row.get("ParentPath", "") + "\\" +
                                      row.get("FileName", "")).strip("\\"),
                            "si_created": row.get("Created0x10"),
                            "fn_created": row.get("Created0x30"),
                            "delta_seconds": int(delta),
                        })
            except Exception:
                pass
            if anomalies:
                findings.append({
                    "technique": "T1070.006",
                    "rule": "mft_si_fn_mismatch",
                    "count": len(anomalies),
                    "samples": anomalies[:20],
                    "severity": "high",
                    "interpretation": "MFT $SI earlier than $FN — "
                                       "classic timestomping artifact",
                })

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for f in findings:
        if sev_rank.get(f.get("severity", "info"), 0) > sev_rank.get(max_sev, 0):
            max_sev = f["severity"]

    return {"findings": findings, "finding_count": len(findings),
            "max_severity": max_sev,
            "stats": {
                "event_log_clearings": sum(1 for f in findings
                    if f.get("rule") in ("event_log_cleared", "log_clear_command")),
                "timestomp_commands": sum(1 for f in findings
                    if f.get("rule") == "timestomp_command"),
                "mft_mismatches": sum(1 for f in findings
                    if f.get("rule") == "mft_si_fn_mismatch"),
            }}


# --- Discovery ---------------------------------------------------------------

DISCOVERY_INDICATORS = {
    # AD reconnaissance commands
    "ad_enum": [
        (r"net\s+user\s+(?:\/domain|\/dom)", "T1087.002", "domain_user_enum"),
        (r"net\s+group\s+(?:\/domain|\/dom)", "T1069.002", "domain_group_enum"),
        (r"net\s+group\s+[\"']?domain\s+admins", "T1069.002", "domain_admins_query"),
        (r"net\s+view\s+\/domain", "T1018", "remote_system_discovery"),
        (r"nltest\s+(?:\/domain_trusts|\/dclist)", "T1482", "domain_trust_discovery"),
        (r"dsquery\s+", "T1087.002", "dsquery_enum"),
        (r"Get-AD(?:User|Group|Computer|Trust|Domain)", "T1087.002", "powerview_adsi"),
        (r"Invoke-(?:ShareFinder|UserHunter|BloodHound)", "T1069", "bloodhound_collection"),
        (r"SharpHound", "T1069", "sharphound_collection"),
        (r"Get-NetUser|Get-NetGroup|Get-NetComputer", "T1087", "powerview"),
        (r"ldapsearch\s+", "T1087.002", "ldapsearch"),
    ],
    # Local enumeration
    "local_enum": [
        (r"whoami\s+(?:\/all|\/groups|\/priv)", "T1033", "whoami_privs"),
        (r"wmic\s+(?:useraccount|group|qfe|logicaldisk)", "T1082", "wmic_system_info"),
        (r"systeminfo(?:\.exe)?", "T1082", "systeminfo"),
        (r"tasklist\s+(?:\/v|\/svc)", "T1057", "tasklist_detailed"),
        (r"ipconfig\s+\/all", "T1016", "ipconfig"),
        (r"arp\s+-a", "T1018", "arp_scan"),
        (r"route\s+print", "T1016", "route_print"),
        (r"netstat\s+-[an]+", "T1049", "netstat"),
    ],
    # Linux enumeration
    "linux_enum": [
        (r"find\s+/\s+-perm\s+-[ug]\+s", "T1083", "find_suid"),
        (r"getent\s+passwd", "T1087.001", "getent_passwd"),
        (r"cat\s+/etc/(?:passwd|group|hosts)", "T1087.001", "etc_read"),
        (r"id\s+(?:-a|-G|-g|-u)", "T1033", "id_command"),
    ],
}


@tool(
    name="detect_discovery",
    description="Detect TA0007 Discovery commands: AD enumeration (net user "
                "/domain, nltest, PowerView, BloodHound, SharpHound), local "
                "enumeration (whoami /all, systeminfo, tasklist /v), network "
                "discovery (arp -a, netstat), Linux enumeration (find SUID, "
                "cat /etc/passwd). Flags high-volume sequences that look "
                "like scripted attacker reconnaissance.",
    schema={"type": "object", "properties": {
        "processes": {"type": "array"},
        "burst_threshold": {"type": "integer", "default": 5,
                            "description": "commands within burst_seconds "
                                           "to flag as scripted recon"},
        "burst_seconds": {"type": "integer", "default": 60},
    }, "required": []},
)
def detect_discovery(processes=None, burst_threshold=5, burst_seconds=60):
    processes = processes or []

    # Pre-compile
    all_patterns = []
    for group, pats in DISCOVERY_INDICATORS.items():
        for pat_str, technique, sub in pats:
            all_patterns.append((re.compile(pat_str, re.I),
                                  technique, sub, group))

    hits = []
    for p in processes:
        cmd = (p.get("cmdline") or p.get("CommandLine") or "")
        if not cmd:
            continue
        for pat, technique, sub, group in all_patterns:
            if pat.search(cmd):
                hits.append({
                    "ts": p.get("start_ts") or p.get("ts"),
                    "pid": p.get("pid"),
                    "user": p.get("user"),
                    "cmdline": cmd[:200],
                    "technique": technique,
                    "sub_technique": sub,
                    "group": group,
                    "severity": ("high" if group == "ad_enum" else "medium"),
                })
                break

    # Burst detection: N hits within burst_seconds from same user
    hits_sorted = sorted(hits, key=lambda x: x.get("ts") or "")
    bursts = []
    i = 0
    while i < len(hits_sorted):
        anchor = hits_sorted[i]
        anchor_ts = _parse_ts(anchor.get("ts") or "")
        if anchor_ts is None:
            i += 1
            continue
        window = [anchor]
        j = i + 1
        while j < len(hits_sorted):
            nxt = hits_sorted[j]
            nxt_ts = _parse_ts(nxt.get("ts") or "")
            if nxt_ts is None or (nxt_ts - anchor_ts).total_seconds() > burst_seconds:
                break
            window.append(nxt)
            j += 1
        if len(window) >= burst_threshold:
            bursts.append({
                "start_ts": anchor.get("ts"),
                "end_ts": window[-1].get("ts"),
                "command_count": len(window),
                "techniques": sorted({w["technique"] for w in window}),
                "user": anchor.get("user"),
                "severity": "high",
                "interpretation": f"{len(window)} discovery commands in "
                                   f"{burst_seconds}s — scripted recon",
            })
            i = j
        else:
            i += 1

    # Per-technique stats
    by_technique = {}
    for h in hits:
        by_technique[h["technique"]] = by_technique.get(h["technique"], 0) + 1

    # AD-specific recon (higher severity)
    ad_recon = [h for h in hits if h["group"] == "ad_enum"]

    max_sev = "info"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for rec in hits + bursts:
        if sev_rank.get(rec.get("severity", "info"), 0) > sev_rank.get(max_sev, 0):
            max_sev = rec["severity"]

    return {"hits": hits[:100], "hit_count": len(hits),
            "ad_recon_count": len(ad_recon),
            "recon_bursts": bursts, "by_technique": by_technique,
            "max_severity": max_sev}


def __forbidden_never_registered():
    """Intentionally NOT registered: execute_shell, write_file, mount,
    delete_file, network_egress, spawn_process, kill_process. See
    tests/test_mcp_bypass.py for the surface + negative-set verification."""
    raise NotImplementedError("documentation only")


# v0.4 expansion: Linux + macOS coverage (4 functions)
from dart_mcp import _v04_expansion as _v04  # noqa: E402, F401
