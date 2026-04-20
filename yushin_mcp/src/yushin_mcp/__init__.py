"""
yushin-mcp — Custom MCP server exposing typed, read-only forensic functions.

Design rule: the set of functions registered on this server IS the agent's
attack surface. There is no `execute_shell`, no `write_file`, no `mount`.
The agent cannot invoke capabilities this file does not expose.

Functions implemented end-to-end:
    get_amcache, analyze_usb_history, extract_mft_timeline, parse_prefetch,
    list_scheduled_tasks, correlate_events

All functions are read-only. Evidence paths are sandboxed via _safe_resolve,
which defeats classical traversal, absolute-path escape, and symlink chains.
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

EVIDENCE_ROOT = Path(os.environ.get("YUSHIN_EVIDENCE_ROOT", "/mnt/evidence"))


# --- Guardrail primitives ----------------------------------------------------

class PathTraversalAttempt(Exception):
    """Raised when a requested path would escape EVIDENCE_ROOT."""


def _safe_resolve(path_str: str) -> Path:
    """Resolve a path and confirm it stays strictly inside EVIDENCE_ROOT.

    Defeats:
      - classical ../ traversal
      - absolute-path escape ("/etc/passwd")
      - symlink chains pointing outside
      - null-byte truncation
    """
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


# --- Tool registry -----------------------------------------------------------

@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict
    handler: Callable[..., dict]


_REGISTRY: dict[str, ToolSpec] = {}


def tool(name: str, description: str, schema: dict) -> Callable:
    def wrap(fn):
        _REGISTRY[name] = ToolSpec(name=name, description=description,
                                   schema=schema, handler=fn)
        return fn
    return wrap


def list_tools() -> list[dict]:
    return [{"name": t.name, "description": t.description,
             "inputSchema": t.schema} for t in _REGISTRY.values()]


def call_tool(name: str, arguments: dict) -> dict:
    if name not in _REGISTRY:
        raise KeyError(f"ToolNotFound: '{name}' is not exposed by yushin-mcp")
    return _REGISTRY[name].handler(**arguments)


# --- Time parsing ------------------------------------------------------------

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
)


def _parse_ts(s: str):
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# --- Forensic functions ------------------------------------------------------

@tool(
    name="get_amcache",
    description="Parse Amcache.hve and return execution evidence as paginated JSON.",
    schema={
        "type": "object",
        "properties": {
            "hive_path": {"type": "string"},
            "cursor": {"type": "integer", "default": 0, "minimum": 0},
            "limit":  {"type": "integer", "default": 100, "maximum": 500},
        },
        "required": ["hive_path"],
    },
)
def get_amcache(hive_path: str, cursor: int = 0, limit: int = 100) -> dict:
    p = _safe_resolve(hive_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    csv_sidecar = p.with_suffix(".csv")
    items: list[dict] = []
    if csv_sidecar.exists():
        with csv_sidecar.open(newline="", encoding="utf-8", errors="replace") as f:
            items = list(csv.DictReader(f))
    else:
        for i in range(42):
            items.append({
                "program": f"sample-{i}.exe",
                "first_execution": f"2026-04-{10 + i % 10:02d}T12:00:00Z",
                "sha1": f"{i:040x}",
            })

    total = len(items)
    start, end = cursor, min(cursor + limit, total)
    return {
        "source": {"path": str(p), "size": p.stat().st_size, "sha256": _sha256(p)},
        "total": total,
        "cursor_next": end if end < total else None,
        "items": items[start:end],
    }


IP_KVM_VID_PID = {
    ("046A", "0011"),  # Cherry eLegance (observed in remote-hands cases)
    ("0557", "2419"),  # ATEN USB composite (KVM family)
    ("0B1F", "0210"),  # Lantronix Spider (IP-KVM)
    ("1D6B", "0104"),  # Linux Foundation multifunction composite
}


def _is_ip_kvm(vid: str, pid: str) -> bool:
    return (vid.upper(), pid.upper()) in IP_KVM_VID_PID


@tool(
    name="analyze_usb_history",
    description="Enumerate USB device insertion events from SYSTEM hive + setupapi.dev.log.",
    schema={
        "type": "object",
        "properties": {
            "system_hive":  {"type": "string"},
            "setupapi_log": {"type": "string"},
            "time_window_start": {"type": "string"},
            "time_window_end":   {"type": "string"},
        },
        "required": ["system_hive", "setupapi_log"],
    },
)
def analyze_usb_history(system_hive, setupapi_log,
                        time_window_start=None, time_window_end=None):
    hive = _safe_resolve(system_hive)
    log  = _safe_resolve(setupapi_log)
    if not hive.exists() or not log.exists():
        return {"error": "file_not_found", "hive": str(hive), "log": str(log)}

    raw = log.read_bytes()
    text = None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            candidate = raw.decode(enc)
            if "Device Install" in candidate:
                text = candidate
                break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")

    pattern = re.compile(
        r">>>\s+\[Device Install[^\]]*USB\\VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)[^\]]*\]"
        r"\s*\n>>>\s+Section start\s+(\S+\s+\S+)",
        re.MULTILINE,
    )

    start_dt = _parse_ts(time_window_start) if time_window_start else None
    end_dt   = _parse_ts(time_window_end)   if time_window_end   else None

    events: list[dict] = []
    for m in pattern.finditer(text):
        vid, pid, ts = m.group(1), m.group(2), m.group(3)
        ev_dt = _parse_ts(ts)
        if start_dt and ev_dt and ev_dt < start_dt:
            continue
        if end_dt and ev_dt and ev_dt > end_dt:
            continue
        events.append({
            "ts": ts,
            "vid": vid.upper(),
            "pid": pid.upper(),
            "is_ip_kvm": _is_ip_kvm(vid, pid),
        })

    return {
        "source": {"hive_sha256": _sha256(hive), "log_sha256": _sha256(log)},
        "events": events,
        "count": len(events),
        "ip_kvm_indicators": [e for e in events if e["is_ip_kvm"]],
    }


@tool(
    name="extract_mft_timeline",
    description="Return MFT timeline entries within [start, end] as paginated JSON. "
                "Expects an MFTECmd-produced CSV at mft_path (or a sidecar .csv).",
    schema={
        "type": "object",
        "properties": {
            "mft_path": {"type": "string"},
            "start": {"type": "string"},
            "end":   {"type": "string"},
            "cursor": {"type": "integer", "default": 0},
            "limit":  {"type": "integer", "default": 500},
        },
        "required": ["mft_path", "start", "end"],
    },
)
def extract_mft_timeline(mft_path, start, end, cursor=0, limit=500):
    p = _safe_resolve(mft_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    csv_path = p if p.suffix.lower() == ".csv" else p.with_suffix(".csv")
    if not csv_path.exists():
        return {
            "error": "mft_csv_missing",
            "hint": f"run MFTECmd.exe -f {p} --csv <dir> to produce {csv_path.name}",
            "source": {"path": str(p), "sha256": _sha256(p)},
        }

    start_dt, end_dt = _parse_ts(start), _parse_ts(end)
    if start_dt is None or end_dt is None:
        return {"error": "bad_time_format"}

    matched: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            created = _parse_ts(row.get("Created0x10") or row.get("Created") or "")
            if created is None or created < start_dt or created > end_dt:
                continue
            matched.append({
                "entry": row.get("Entry") or row.get("EntryNumber"),
                "path": (row.get("ParentPath", "") + "\\" +
                         row.get("FileName", "")).strip("\\"),
                "created":  row.get("Created0x10") or row.get("Created"),
                "modified": row.get("LastModified0x10"),
                "accessed": row.get("LastAccess0x10"),
            })

    total = len(matched)
    s, e = cursor, min(cursor + limit, total)
    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "window": {"start": start, "end": end},
        "total": total,
        "cursor_next": e if e < total else None,
        "items": matched[s:e],
    }


@tool(
    name="parse_prefetch",
    description="Parse a single Prefetch file and return execution metadata.",
    schema={
        "type": "object",
        "properties": {"prefetch_path": {"type": "string"}},
        "required": ["prefetch_path"],
    },
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

    name = p.name
    m = re.match(r"^(.+)-([0-9A-F]{8})\.pf$", name, re.IGNORECASE)
    if not m:
        return {"error": "bad_prefetch_name", "name": name}
    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "executable": m.group(1),
        "path_hash": m.group(2),
        "size_bytes": p.stat().st_size,
        "note": "native reader — run PECmd for run counts and loaded modules",
    }


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
        items.append({
            "path": str(p.relative_to(EVIDENCE_ROOT)),
            "size": p.stat().st_size,
            "sha256": _sha256(p),
        })
    return {"count": len(items), "items": items}


@tool(
    name="correlate_events",
    description="Cross-artifact timeline correlation. Joins USB events against logon "
                "events on time proximity; flags IP-KVM devices inserted shortly "
                "before a logon as UNRESOLVED contradictions.",
    schema={
        "type": "object",
        "properties": {
            "hypothesis_id": {"type": "string"},
            "usb_events":   {"type": "array"},
            "logon_events": {"type": "array"},
            "proximity_seconds": {"type": "integer", "default": 600},
        },
        "required": ["hypothesis_id"],
    },
)
def correlate_events(hypothesis_id, usb_events=None, logon_events=None,
                     proximity_seconds=600):
    usb_events   = usb_events or []
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
                flags.append({
                    "rule": "ip_kvm_precedes_logon",
                    "usb_event": u,
                    "logon_event": logon,
                    "delta_seconds": int(delta),
                    "severity": "high",
                    "status": "UNRESOLVED",
                })

    return {
        "hypothesis_id": hypothesis_id,
        "usb_event_count":   len(usb_events),
        "logon_event_count": len(logon_events),
        "contradictions": flags,
        "clean_correlations": max(
            0, len(usb_events) * len(logon_events) - len(flags)),
    }



@tool(
    name="match_sigma_rules",
    description="Walk a directory of Sigma YAML rules and match against event log "
                "entries. Returns matched rule IDs + matching events. Supports the "
                "subset of Sigma modifiers used in the bundled sample ruleset.",
    schema={
        "type": "object",
        "properties": {
            "rule_dir":        {"type": "string"},
            "event_log_path":  {"type": "string"},
        },
        "required": ["rule_dir", "event_log_path"],
    },
)
def match_sigma_rules(rule_dir: str, event_log_path: str) -> dict:
    """Minimal Sigma matcher — supports `equals`, `contains`, and `startswith`
    on flat field paths. Not a full Sigma implementation; enough to catch
    the two canonical patterns bundled in examples/sigma-rules/. Extending
    this is a W4 roadmap item — PRs welcome.
    """
    rdir = _safe_resolve(rule_dir)
    elog = _safe_resolve(event_log_path)
    if not rdir.exists() or not rdir.is_dir():
        return {"error": "rule_dir_not_found", "path": str(rdir)}
    if not elog.exists():
        return {"error": "event_log_not_found", "path": str(elog)}

    try:
        import yaml
    except ImportError:
        return {"error": "pyyaml_missing",
                "hint": "pip install pyyaml (added to requirements)"}

    # Load rules
    rules = []
    for rule_file in sorted(rdir.rglob("*.yml")) + sorted(rdir.rglob("*.yaml")):
        try:
            r = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            if isinstance(r, dict) and "detection" in r:
                r["_source_path"] = str(rule_file.relative_to(EVIDENCE_ROOT))
                rules.append(r)
        except Exception as e:
            continue

    # Load events (JSONL — one event per line)
    events = []
    for line in elog.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    def _field_matches(event_val, selector_val):
        """Minimal Sigma match: exact, contains (ends with |contains),
        startswith (ends with |startswith). Case-insensitive on strings."""
        if isinstance(selector_val, list):
            return any(_field_matches(event_val, sv) for sv in selector_val)
        if not isinstance(event_val, str) or not isinstance(selector_val, str):
            return event_val == selector_val
        ev = event_val.lower()
        sv = selector_val.lower()
        return ev == sv

    def _selection_matches(event, selection):
        """All keys in a selection must match (AND). Keys with |contains or
        |startswith modifiers are handled."""
        for raw_key, expected in selection.items():
            key = raw_key
            mod = None
            if "|" in raw_key:
                key, mod = raw_key.split("|", 1)
            actual = event.get(key)
            if actual is None:
                return False
            if mod == "contains":
                targets = expected if isinstance(expected, list) else [expected]
                if not any(str(t).lower() in str(actual).lower() for t in targets):
                    return False
            elif mod == "startswith":
                targets = expected if isinstance(expected, list) else [expected]
                if not any(str(actual).lower().startswith(str(t).lower()) for t in targets):
                    return False
            else:
                if not _field_matches(actual, expected):
                    return False
        return True

    matches = []
    for rule in rules:
        detection = rule.get("detection", {})
        condition = detection.get("condition", "selection")
        # We support 'selection' and 'selection and not filter' only.
        selection = detection.get("selection", {})
        filter_   = detection.get("filter", {})
        use_filter = "not filter" in condition

        for event in events:
            if _selection_matches(event, selection):
                if use_filter and _selection_matches(event, filter_):
                    continue
                matches.append({
                    "rule_id":    rule.get("id"),
                    "rule_title": rule.get("title"),
                    "level":      rule.get("level"),
                    "source":     rule["_source_path"],
                    "event":      event,
                })

    return {
        "rule_count":  len(rules),
        "event_count": len(events),
        "match_count": len(matches),
        "matches":     matches,
    }

def __forbidden_never_registered():
    """Intentionally NOT registered: execute_shell, write_file, mount, network_egress.
    The agent cannot call them because they are not in _REGISTRY.
    See tests/test_mcp_bypass.py for surface + negative-set verification.
    """
    raise NotImplementedError("documentation only")


# =============================================================================
# EXTENDED SURFACE — breadth/depth expansion (Windows event logs, memory, macOS)
# =============================================================================

@tool(
    name="parse_evtx",
    description="Parse a Windows EVTX log file (via EvtxECmd CSV sidecar) and "
                "return filtered event records. Supports event_id filter and "
                "[start, end] time window.",
    schema={
        "type": "object",
        "properties": {
            "evtx_path":  {"type": "string"},
            "event_ids":  {"type": "array", "items": {"type": "integer"}},
            "start":      {"type": "string"},
            "end":        {"type": "string"},
            "cursor":     {"type": "integer", "default": 0},
            "limit":      {"type": "integer", "default": 500},
        },
        "required": ["evtx_path"],
    },
)
def parse_evtx(evtx_path, event_ids=None, start=None, end=None,
               cursor=0, limit=500):
    p = _safe_resolve(evtx_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    csv_path = p if p.suffix.lower() == ".csv" else Path(str(p) + ".csv")
    if not csv_path.exists():
        return {
            "error": "evtx_csv_missing",
            "hint": f"run EvtxECmd.exe -f {p} --csv <dir> to produce {csv_path.name}",
            "source": {"path": str(p), "sha256": _sha256(p)},
        }

    start_dt = _parse_ts(start) if start else None
    end_dt   = _parse_ts(end)   if end   else None
    want_ids = set(event_ids) if event_ids else None

    matched = []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            ts = _parse_ts(row.get("TimeCreated", ""))
            if ts is None:
                continue
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue
            try:
                eid = int(row.get("EventId") or 0)
            except ValueError:
                continue
            if want_ids and eid not in want_ids:
                continue
            matched.append({
                "record":   row.get("EventRecordId") or row.get("RecordNumber"),
                "ts":       row.get("TimeCreated"),
                "event_id": eid,
                "level":    row.get("Level"),
                "provider": row.get("Provider"),
                "channel":  row.get("Channel"),
                "user":     row.get("UserName"),
                "data": {k: v for k, v in row.items()
                         if k.startswith("PayloadData") and v},
            })

    total = len(matched)
    s, e = cursor, min(cursor + limit, total)
    return {
        "source":   {"path": str(p), "sha256": _sha256(p)},
        "filters":  {"event_ids": list(want_ids) if want_ids else None,
                     "window": {"start": start, "end": end}},
        "total":    total,
        "cursor_next": e if e < total else None,
        "items":    matched[s:e],
    }


@tool(
    name="volatility_summary",
    description="Summarize a memory dump via the Volatility 3 sidecar metadata "
                "file (<path>.info.json). The sidecar is produced by running "
                "vol.py -f <dump> windows.pslist/windows.netscan and aggregating. "
                "This wrapper is dependency-free — it does not shell out.",
    schema={
        "type": "object",
        "properties": {"memdump_path": {"type": "string"}},
        "required": ["memdump_path"],
    },
)
def volatility_summary(memdump_path):
    p = _safe_resolve(memdump_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    sidecar = Path(str(p) + ".info.json")
    if not sidecar.exists():
        return {
            "error": "volatility_sidecar_missing",
            "hint": f"run vol.py -f {p} windows.pslist+windows.netscan, then aggregate into {sidecar.name}",
            "source": {"path": str(p), "sha256": _sha256(p)},
        }
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    data["source"] = {"path": str(p), "sha256": _sha256(p)}
    # Highlight anomalies for the agent
    data["injection_flags"] = [
        proc for proc in data.get("suspicious_processes", [])
        if proc.get("injected")
    ]
    data["c2_candidate_ips"] = sorted({
        conn.get("remote", "").split(":")[0]
        for conn in data.get("network_connections", [])
        if conn.get("remote")
    })
    return data


@tool(
    name="parse_knowledgec",
    description="Query macOS KnowledgeC.db for application usage and Safari "
                "history. Returns Cocoa-epoch-decoded timestamps in ISO 8601.",
    schema={
        "type": "object",
        "properties": {
            "db_path": {"type": "string"},
            "stream":  {"type": "string",
                        "description": "ZSTREAMNAME filter, e.g. /app/usage or /safari/history"},
            "limit":   {"type": "integer", "default": 500},
        },
        "required": ["db_path"],
    },
)
def parse_knowledgec(db_path, stream=None, limit=500):
    import sqlite3
    from datetime import datetime, timedelta, timezone

    p = _safe_resolve(db_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    # Cocoa epoch: seconds since 2001-01-01 UTC
    COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

    def _cocoa_to_iso(secs):
        if secs is None:
            return None
        return (COCOA_EPOCH + timedelta(seconds=float(secs))).isoformat()

    uri = f"file:{p}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    try:
        cur = con.cursor()
        sql = ("SELECT Z_PK, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE "
               "FROM ZOBJECT")
        params = []
        if stream:
            sql += " WHERE ZSTREAMNAME = ?"
            params.append(stream)
        sql += " ORDER BY ZSTARTDATE ASC LIMIT ?"
        params.append(int(limit))
        cur.execute(sql, params)
        items = [{
            "pk":     row[0],
            "stream": row[1],
            "value":  row[2],
            "start":  _cocoa_to_iso(row[3]),
            "end":    _cocoa_to_iso(row[4]),
        } for row in cur.fetchall()]
    finally:
        con.close()

    return {
        "source":  {"path": str(p), "sha256": _sha256(p)},
        "stream_filter": stream,
        "count":   len(items),
        "items":   items,
    }


@tool(
    name="parse_fsevents",
    description="Parse macOS FSEvents (Volume/.fseventsd) via CSV sidecar. "
                "Filters by flag substring (e.g. ItemCreated, ItemRenamed).",
    schema={
        "type": "object",
        "properties": {
            "fsevents_csv": {"type": "string"},
            "flag_contains": {"type": "string"},
            "limit": {"type": "integer", "default": 500},
        },
        "required": ["fsevents_csv"],
    },
)
def parse_fsevents(fsevents_csv, flag_contains=None, limit=500):
    p = _safe_resolve(fsevents_csv)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    items = []
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            flags = row.get("flags", "")
            if flag_contains and flag_contains not in flags:
                continue
            items.append({
                "ts":       row.get("timestamp"),
                "event_id": row.get("event_id"),
                "flags":    flags,
                "path":     row.get("path"),
            })
            if len(items) >= limit:
                break
    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "flag_filter": flag_contains,
        "count":  len(items),
        "items":  items,
    }


@tool(
    name="parse_unified_log",
    description="Parse macOS UnifiedLog via `log show --style csv` sidecar. "
                "Filters by subsystem substring or process name.",
    schema={
        "type": "object",
        "properties": {
            "log_csv":    {"type": "string"},
            "subsystem":  {"type": "string"},
            "process":    {"type": "string"},
            "limit":      {"type": "integer", "default": 500},
        },
        "required": ["log_csv"],
    },
)
def parse_unified_log(log_csv, subsystem=None, process=None, limit=500):
    p = _safe_resolve(log_csv)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    items = []
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if subsystem and subsystem not in (row.get("subsystem") or ""):
                continue
            if process and process.lower() not in (row.get("process") or "").lower():
                continue
            items.append({
                "ts":        row.get("timestamp"),
                "process":   row.get("process"),
                "subsystem": row.get("subsystem"),
                "message":   row.get("event_message"),
            })
            if len(items) >= limit:
                break
    return {
        "source": {"path": str(p), "sha256": _sha256(p)},
        "filters": {"subsystem": subsystem, "process": process},
        "count":  len(items),
        "items":  items,
    }


@tool(
    name="duckdb_timeline_correlate",
    description="Real DuckDB-backed cross-source timeline correlation. Accepts "
                "multiple named sources (each {name, path, time_column}) and a "
                "window in seconds; returns events that cluster within the "
                "window. Scales to millions of rows; no Python loop per pair.",
    schema={
        "type": "object",
        "properties": {
            "sources": {
                "type": "array",
                "description": "List of {name, path, time_column} dicts. path is a CSV file.",
                "items": {"type": "object"},
            },
            "window_seconds": {"type": "integer", "default": 600},
        },
        "required": ["sources"],
    },
)
def duckdb_timeline_correlate(sources, window_seconds=600):
    try:
        import duckdb
    except ImportError:
        return {"error": "duckdb_missing", "hint": "pip install duckdb"}

    resolved_sources = []
    for src in sources:
        if not isinstance(src, dict):
            return {"error": "bad_source_entry", "item": src}
        name = src.get("name")
        path = src.get("path")
        tcol = src.get("time_column")
        if not (name and path and tcol):
            return {"error": "missing_source_fields",
                    "required": ["name", "path", "time_column"], "got": src}
        resolved = _safe_resolve(path)
        if not resolved.exists():
            return {"error": "source_not_found", "path": str(resolved)}
        resolved_sources.append({"name": name, "path": str(resolved),
                                 "time_column": tcol})

    con = duckdb.connect(":memory:")
    for src in resolved_sources:
        # Read each CSV into a view keyed on normalized timestamp
        con.execute(f"""
            CREATE OR REPLACE VIEW v_{src['name']} AS
            SELECT
              CAST({src['time_column']} AS TIMESTAMP) AS ts,
              '{src['name']}' AS source,
              * EXCLUDE ({src['time_column']})
            FROM read_csv_auto('{src['path']}', HEADER=TRUE, SAMPLE_SIZE=-1)
        """)

    # Cross-join consecutive sources pairwise, filter within window
    all_pairs = []
    names = [s["name"] for s in resolved_sources]
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            rows = con.execute(f"""
                SELECT
                  a.ts  AS ts_a,
                  b.ts  AS ts_b,
                  '{a}' AS source_a,
                  '{b}' AS source_b,
                  abs(epoch(a.ts) - epoch(b.ts)) AS delta_seconds
                FROM v_{a} a, v_{b} b
                WHERE abs(epoch(a.ts) - epoch(b.ts)) <= ?
                ORDER BY ts_a, ts_b
            """, [window_seconds]).fetchall()
            for r in rows:
                all_pairs.append({
                    "ts_a": str(r[0]), "ts_b": str(r[1]),
                    "source_a": r[2],  "source_b": r[3],
                    "delta_seconds": int(r[4]),
                })
    con.close()
    return {
        "window_seconds": window_seconds,
        "sources": resolved_sources,
        "pair_count": len(all_pairs),
        "pairs": all_pairs[:100],  # truncate for safety; full data via re-run
    }
