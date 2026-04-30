"""
v0.4 expansion: Linux + macOS coverage.

Defines 4 new typed forensic functions and registers them on the
dart_mcp surface via the @tool decorator. Imported by dart_mcp/__init__.py
at module load time.

  - parse_auditd_log         (Linux)    — kernel-level syscall audit
  - parse_systemd_journal    (Linux)    — unified system log
  - parse_bash_history       (Linux/macOS) — shell history with attacker-pattern detection
  - parse_launchd_plist      (macOS)    — LaunchAgent/Daemon persistence

References (all open / public):
  • Red Hat Enterprise Linux Security Guide, ch. 7 (auditd)
  • SANS FOR577 — Linux Incident Response & Threat Hunting
  • systemd.journal-fields(7), freedesktop.org Journal Export Format
  • Apple Developer Library — Daemons and Services Programming Guide
  • Patrick Wardle — "The Art of Mac Malware" (corpus of LaunchAgent/Daemon TTPs)
  • MITRE ATT&CK — T1059.004 (Unix Shell), T1543.001/.004 (LaunchDaemon/Agent),
    T1098.004 (SSH authorized_keys), T1053.003 (Cron), T1027 (obfuscation),
    T1070.003 (history clear), T1548.001 (SUID/SGID)
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from dart_mcp import tool, _safe_resolve, _sha256, _parse_ts


# =============================================================================
# parse_auditd_log
# =============================================================================
_AUDIT_KV_RE = re.compile(r'(\w+)=([^\s"]+|"[^"]*")')
_AUDIT_TS_RE = re.compile(r'audit\((\d+\.\d+):\d+\)')

_SYSCALL_NAMES = {
    "59": "execve", "322": "execveat", "2": "open", "257": "openat",
    "82": "rename", "263": "unlinkat", "87": "unlink",
    "1": "write", "92": "chown", "94": "lchown",
    "260": "fchownat", "90": "chmod", "268": "fchmodat",
    "41": "socket", "42": "connect", "49": "bind",
}


@tool(
    name="parse_auditd_log",
    description=(
        "Parse Linux auditd kernel-level audit logs (/var/log/audit/audit.log). "
        "Filters by syscall, key, or executable. References: Red Hat RHEL Security "
        "Guide ch.7 (auditd), SANS FOR577 'Linux Incident Response & Threat Hunting', "
        "auditd(8). MITRE ATT&CK: T1059.004, T1547, T1548."
    ),
    schema={"type": "object", "properties": {
        "audit_log_path": {"type": "string"},
        "syscall_filter": {"type": "array", "items": {"type": "string"}},
        "key_filter": {"type": "string"},
        "exe_contains": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["audit_log_path"]},
)
def parse_auditd_log(audit_log_path, syscall_filter=None, key_filter=None,
                     exe_contains=None, time_window_start=None,
                     time_window_end=None, limit=500):
    p = _safe_resolve(audit_log_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p),
                "hint": "Linux: typically /var/log/audit/audit.log (root-only)"}

    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    events = []
    skipped = 0
    with p.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            kv = dict(_AUDIT_KV_RE.findall(line))
            ts_match = _AUDIT_TS_RE.search(line)
            ts_iso = None
            if ts_match:
                try:
                    dt = datetime.fromtimestamp(float(ts_match.group(1)),
                                                 tz=timezone.utc).replace(tzinfo=None)
                    ts_iso = dt.isoformat()
                    if sdt and dt < sdt:
                        skipped += 1; continue
                    if edt and dt > edt:
                        skipped += 1; continue
                except (ValueError, OSError):
                    pass

            syscall_num = kv.get("syscall", "").strip('"')
            syscall_name = _SYSCALL_NAMES.get(syscall_num, syscall_num)
            if syscall_filter and syscall_name not in syscall_filter \
               and syscall_num not in syscall_filter:
                continue

            evt_key = kv.get("key", "").strip('"').strip("(")
            if key_filter and key_filter not in evt_key:
                continue

            exe = kv.get("exe", "").strip('"')
            if exe_contains and exe_contains not in exe:
                continue

            events.append({
                "ts": ts_iso,
                "type": kv.get("type", "").strip('"'),
                "syscall": syscall_name,
                "success": kv.get("success", "").strip('"'),
                "exe": exe,
                "uid": kv.get("uid", "").strip('"'),
                "auid": kv.get("auid", "").strip('"'),
                "comm": kv.get("comm", "").strip('"'),
                "key": evt_key,
            })
            if len(events) >= limit:
                break

    by_syscall, by_type = {}, {}
    for e in events:
        by_syscall[e["syscall"]] = by_syscall.get(e["syscall"], 0) + 1
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1

    return {
        "total": len(events),
        "skipped_outside_window": skipped,
        "by_syscall": dict(sorted(by_syscall.items(), key=lambda kv: -kv[1])[:10]),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])[:10]),
        "events": events,
        "source": {"path": str(p), "sha256": _sha256(p)},
        "platform": "linux",
    }


# =============================================================================
# parse_systemd_journal
# =============================================================================
@tool(
    name="parse_systemd_journal",
    description=(
        "Parse systemd journal export (output of: journalctl -o json). Filters by "
        "unit, priority, message substring. Reference: systemd.journal-fields(7), "
        "freedesktop.org 'Journal Export Format'. MITRE ATT&CK: T1078, T1543.002."
    ),
    schema={"type": "object", "properties": {
        "journal_export_path": {"type": "string"},
        "unit_filter": {"type": "string"},
        "priority_max": {"type": "integer"},
        "message_contains": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["journal_export_path"]},
)
def parse_systemd_journal(journal_export_path, unit_filter=None,
                          priority_max=None, message_contains=None,
                          time_window_start=None, time_window_end=None,
                          limit=500):
    p = _safe_resolve(journal_export_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p),
                "hint": "produce via: journalctl -o json --no-pager > journal.ndjson"}

    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None

    text = p.read_text(encoding="utf-8", errors="replace")
    raw_entries = []
    try:
        parsed = json.loads(text)
        raw_entries = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    events, skipped = [], 0
    for e in raw_entries:
        ts_us = e.get("__REALTIME_TIMESTAMP")
        ts_iso = None
        if ts_us:
            try:
                dt = datetime.fromtimestamp(int(ts_us) / 1_000_000)
                ts_iso = dt.isoformat()
                if sdt and dt < sdt: skipped += 1; continue
                if edt and dt > edt: skipped += 1; continue
            except (ValueError, OSError):
                pass

        unit = e.get("_SYSTEMD_UNIT", "")
        if unit_filter and unit_filter not in unit:
            continue
        try:
            pri = int(e["PRIORITY"]) if "PRIORITY" in e else None
        except (ValueError, TypeError):
            pri = None
        if priority_max is not None and pri is not None and pri > priority_max:
            continue
        msg = e.get("MESSAGE", "")
        if message_contains and message_contains not in msg:
            continue

        events.append({
            "ts": ts_iso,
            "unit": unit,
            "priority": pri,
            "message": msg[:500],
            "pid": e.get("_PID"),
            "uid": e.get("_UID"),
            "comm": e.get("_COMM"),
            "exe": e.get("_EXE"),
        })
        if len(events) >= limit:
            break

    by_unit = {}
    for ev in events:
        u = ev["unit"] or "(no unit)"
        by_unit[u] = by_unit.get(u, 0) + 1

    return {
        "total": len(events),
        "skipped_outside_window": skipped,
        "by_unit": dict(sorted(by_unit.items(), key=lambda kv: -kv[1])[:10]),
        "events": events,
        "source": {"path": str(p), "sha256": _sha256(p)},
        "platform": "linux",
    }


# =============================================================================
# parse_bash_history
# =============================================================================
_SUSPICIOUS_PATTERNS = [
    ("base64_decode_pipe",   re.compile(r"base64\s+(-d|--decode)"),                "T1027",     "Obfuscated payload decode"),
    ("reverse_shell_bash",   re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/"),            "T1059.004", "Bash /dev/tcp reverse shell"),
    ("reverse_shell_nc",     re.compile(r"\bnc\s+(-e|-c)\b|\bncat\s+(-e|-c)\b"),   "T1059.004", "Netcat reverse shell"),
    ("reverse_shell_python", re.compile(r"python.*socket\.socket.*os\.dup2"),      "T1059.006", "Python reverse shell"),
    ("download_and_run",     re.compile(r"(curl|wget)\s+\S+\s*\|\s*(bash|sh|python)"), "T1105", "Download-and-pipe to shell"),
    ("ssh_key_modify",       re.compile(r">>\s*~?\.?/?\.ssh/authorized_keys"),     "T1098.004", "SSH authorized_keys modification"),
    ("crontab_persist",      re.compile(r"crontab\s+-[el]|>>\s*/etc/cron"),        "T1053.003", "Cron-based persistence"),
    ("history_clear",        re.compile(r"history\s+-c|>\s*~?/?\.bash_history|unset\s+HISTFILE"), "T1070.003", "Bash history cleared"),
    ("setuid_make",          re.compile(r"chmod\s+[ug]?\+s\s|chmod\s+[24][0-7]{3}\s"), "T1548.001", "SUID/SGID escalation"),
    ("disable_security",     re.compile(r"setenforce\s+0|systemctl\s+stop\s+(firewalld|iptables|ufw)"), "T1562.001", "Security tool disable"),
    ("password_in_command",  re.compile(r"--password[=\s]\S{4,}|-p\s+['\"]?\w{4,}"), "T1552.001", "Possible cleartext credentials"),
    ("kernel_module_load",   re.compile(r"\binsmod\b|\bmodprobe\s+(?!-r\b)\S+"),   "T1547.006", "Kernel module load (rootkit?)"),
]


@tool(
    name="parse_bash_history",
    description=(
        "Parse bash/zsh history file (~/.bash_history, ~/.zsh_history). Surfaces "
        "attacker-pattern hits: encoded payloads, reverse shells, SSH key insertion, "
        "history clearing. Reference: SANS FOR577, MITRE ATT&CK T1059.004 Unix Shell, "
        "T1070.003 (Clear Command History), T1098.004 (SSH Authorized Keys)."
    ),
    schema={"type": "object", "properties": {
        "history_path": {"type": "string"},
        "format": {"type": "string", "enum": ["auto", "bash", "zsh"], "default": "auto"},
        "command_contains": {"type": "string"},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["history_path"]},
)
def parse_bash_history(history_path, format="auto", command_contains=None, limit=500):
    p = _safe_resolve(history_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p),
                "hint": "Look in ~/.bash_history, ~/.zsh_history, ~/.history"}

    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    if format == "auto":
        format = "zsh" if any(l.startswith(": ") and ";" in l for l in lines[:50]) else "bash"

    commands, pending_ts = [], None
    for line in lines:
        if format == "bash":
            if line.startswith("#") and line[1:].strip().isdigit():
                try:
                    pending_ts = datetime.fromtimestamp(int(line[1:].strip())).isoformat()
                except (ValueError, OSError):
                    pending_ts = None
            elif line.strip():
                commands.append({"ts": pending_ts, "command": line.rstrip()})
                pending_ts = None
        else:
            m = re.match(r"^: (\d+):(\d+);(.*)$", line)
            if m:
                try:
                    ts = datetime.fromtimestamp(int(m.group(1))).isoformat()
                except (ValueError, OSError):
                    ts = None
                commands.append({"ts": ts, "command": m.group(3).rstrip(),
                                 "duration_sec": int(m.group(2))})
            elif line.strip():
                commands.append({"ts": None, "command": line.rstrip()})

    if command_contains:
        commands = [c for c in commands if command_contains in c["command"]]

    suspicious_hits = []
    for c in commands:
        for cat_id, pat, mitre, desc in _SUSPICIOUS_PATTERNS:
            if pat.search(c["command"]):
                suspicious_hits.append({
                    "ts": c.get("ts"),
                    "command": c["command"][:200],
                    "category": cat_id,
                    "mitre_technique": mitre,
                    "interpretation": desc,
                })
                break

    return {
        "format_detected": format,
        "total_commands": len(commands),
        "suspicious_count": len(suspicious_hits),
        "suspicious": suspicious_hits[:limit],
        "commands": commands[:limit],
        "source": {"path": str(p), "sha256": _sha256(p)},
        "platform": "linux/macos",
    }


# =============================================================================
# parse_launchd_plist
# =============================================================================
@tool(
    name="parse_launchd_plist",
    description=(
        "Parse a macOS LaunchAgent or LaunchDaemon plist for persistence indicators. "
        "Reference: Apple Developer 'Daemons and Services Programming Guide', "
        "Patrick Wardle 'The Art of Mac Malware', MITRE ATT&CK T1543.001 (LaunchDaemon) "
        "and T1543.004 (LaunchAgent)."
    ),
    schema={"type": "object", "properties": {
        "plist_path": {"type": "string"},
    }, "required": ["plist_path"]},
)
def parse_launchd_plist(plist_path):
    import plistlib
    p = _safe_resolve(plist_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    try:
        with p.open("rb") as f:
            d = plistlib.load(f)
    except Exception as e:
        return {"error": "plist_parse_failed", "path": str(p),
                "details": str(e)[:200]}

    label = d.get("Label", "")
    program_args = d.get("ProgramArguments", []) or []
    program = d.get("Program") or (program_args[0] if program_args else "")

    abs_path = str(p.resolve())
    if "/System/Library/LaunchDaemons" in abs_path:
        location_class, location_writable = "system_daemon", "root_only"
    elif "/System/Library/LaunchAgents" in abs_path:
        location_class, location_writable = "system_agent", "root_only"
    elif "/Library/LaunchDaemons" in abs_path:
        location_class, location_writable = "third_party_daemon", "root_only"
    elif "/Library/LaunchAgents" in abs_path:
        location_class, location_writable = "third_party_agent", "root_only"
    elif "/Users/" in abs_path and "Library/LaunchAgents" in abs_path:
        location_class, location_writable = "user_agent", "user_writable"
    else:
        location_class, location_writable = "non_standard", "unknown"

    run_at_load = bool(d.get("RunAtLoad"))
    keep_alive = d.get("KeepAlive")

    indicators = []
    if location_writable == "user_writable" and run_at_load:
        indicators.append({
            "id": "user_writable_persistence", "severity": "high",
            "mitre": "T1543.004",
            "desc": "RunAtLoad=true in user-writable LaunchAgent path"})
    suspicious_paths = ("/tmp/", "/private/tmp/", "/var/tmp/", "Downloads/")
    if program and any(s in program for s in suspicious_paths):
        indicators.append({
            "id": "executable_in_temp", "severity": "high", "mitre": "T1574",
            "desc": "Program runs from non-standard / world-writable path: " + program})
    if keep_alive is True or (isinstance(keep_alive, dict)
                              and keep_alive.get("SuccessfulExit") is False):
        indicators.append({
            "id": "keepalive_aggressive", "severity": "medium", "mitre": "T1543",
            "desc": "KeepAlive ensures the process restarts — common adversary persistence pattern"})
    if not label or len(label) < 3:
        indicators.append({
            "id": "missing_or_minimal_label", "severity": "low", "mitre": "T1036",
            "desc": "Label field missing or too short — possible masquerading"})

    return {
        "label": label,
        "program": program,
        "program_arguments": program_args,
        "run_at_load": run_at_load,
        "keep_alive": keep_alive,
        "start_interval_sec": d.get("StartInterval"),
        "start_calendar_interval": d.get("StartCalendarInterval"),
        "user_name": d.get("UserName"),
        "location_class": location_class,
        "location_writable": location_writable,
        "suspicion_indicators": indicators,
        "source": {"path": str(p), "sha256": _sha256(p)},
        "platform": "macos",
    }
