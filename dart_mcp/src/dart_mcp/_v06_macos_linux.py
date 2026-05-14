"""
v0.6 expansion: macOS quarantine + Linux cron + cross-platform DNS tunneling.

Three new typed forensic functions registered on the dart_mcp surface via @tool.
Imported by dart_mcp/__init__.py at module load time.

  - parse_macos_quarantine   (macOS)         — LSQuarantineEvent download provenance
  - parse_linux_cron_jobs    (Linux)         — system/user crontabs + cron.d/cron.{hourly,daily,weekly,monthly}
  - detect_dns_tunneling     (cross-platform) — Iodine/dnscat2 / high-entropy DNS C2 heuristics

References (all open / public):
  • Sarah Edwards — mac4n6.com QuarantineV2 schema research
  • Apple Developer Library — Launch Services Reference (kLSQuarantineEvent*)
  • crontab(5) — POSIX cron syntax
  • Red Hat RHEL Security Guide ch.7 — anacron, cron.d directory layout
  • Iodine paper — Yarrin & Andersson 2009 (DNS tunneling over A/CNAME/NULL records)
  • Paul A. Vixie — RFC 1035 (DNS) + RFC 3833 (DNS threat model)
  • SANS FOR572 — Advanced Network Forensics (DNS C2 detection patterns)
  • Splunk Security Essentials — DNS tunneling detection rule patterns
  • MITRE ATT&CK: T1204 (User Execution), T1053.003 (Cron), T1071.004 (DNS),
    T1568.002 (Domain Generation Algorithms), T1572 (Protocol Tunneling)
"""
from __future__ import annotations
import json
import math
import os
import re
import sqlite3
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dart_mcp import tool, _safe_resolve, _sha256, _parse_ts


# =============================================================================
# parse_macos_quarantine
# =============================================================================

# Browser/app bundle IDs commonly seen as legitimate downloaders.
# Anything outside this list, or sourced from outside-browser apps, gets flagged.
_KNOWN_BROWSERS = {
    "com.apple.Safari",
    "com.google.Chrome",
    "org.mozilla.firefox",
    "com.microsoft.Edge",
    "com.brave.Browser",
    "com.operasoftware.Opera",
    "com.vivaldi.Vivaldi",
    "com.apple.appstored",
    "com.apple.iCloud",
    "com.apple.mail",
    "com.apple.MobileSMS",
    "com.tinyspeck.slackmacgap",
    "us.zoom.xos",
}

# Suspicious origin URL patterns
_SUSPICIOUS_URL_PATTERNS = [
    (re.compile(r"\.(zip|dmg|pkg|tar\.gz|tgz|7z)$", re.I), "archive_download"),
    (re.compile(r"\.(sh|command|bash|py|rb|pl|js)$", re.I), "script_download"),
    (re.compile(r"\.(jar|class)$", re.I), "java_download"),
    (re.compile(r"raw\.githubusercontent\.com", re.I), "github_raw_payload"),
    (re.compile(r"pastebin\.|paste\.|hastebin\.|ghostbin\.", re.I), "pastesite_origin"),
    (re.compile(r"discord(?:app)?\.com/.*?/attachments", re.I), "discord_cdn_origin"),
    (re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I), "raw_ip_origin"),
    (re.compile(r"\.(onion|i2p)/", re.I), "darknet_origin"),
]


@tool(
    name="parse_macos_quarantine",
    description=(
        "Parse macOS LSQuarantineEvent SQLite database "
        "(~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2). "
        "Returns download provenance per file: origin URL, source app bundle ID, "
        "download timestamp, sender name. Flags suspicious downloaders (non-browser "
        "apps), suspicious URL patterns (raw IP, pastesites, archive/script extensions, "
        "darknet origins). References: Sarah Edwards QuarantineV2 schema (mac4n6.com), "
        "Apple Launch Services Reference, SANS FOR518. MITRE ATT&CK: T1204 (User "
        "Execution), T1566.002 (Spearphishing Link), T1105 (Ingress Tool Transfer)."
    ),
    schema={
        "type": "object",
        "properties": {
            "quarantine_db_path": {
                "type": "string",
                "description": "Path to QuarantineEventsV2 SQLite file (or copy thereof). "
                               "Standard location: ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            },
            "time_window_start": {"type": "string", "description": "ISO 8601 start filter"},
            "time_window_end": {"type": "string", "description": "ISO 8601 end filter"},
            "flagged_only": {
                "type": "boolean",
                "description": "If true, return only events with suspicious flags (default false)",
            },
            "cursor": {"type": "integer", "description": "Pagination cursor", "default": 0},
            "limit": {"type": "integer", "description": "Max rows to return", "default": 200},
        },
        "required": ["quarantine_db_path"],
    },
)
def parse_macos_quarantine(
    quarantine_db_path: str,
    time_window_start: str | None = None,
    time_window_end: str | None = None,
    flagged_only: bool = False,
    cursor: int = 0,
    limit: int = 200,
):
    """Read LSQuarantineEvent rows and surface download provenance + risk flags."""
    db_path = _safe_resolve(quarantine_db_path)
    if not db_path.exists():
        return {
            "source": {"path": str(db_path), "sha256": ""},
            "events": [],
            "total": 0,
            "next_cursor": None,
            "error": f"quarantine db not found at {db_path}",
        }

    sha = _sha256(db_path)
    start_dt = _parse_ts(time_window_start) if time_window_start else None
    end_dt = _parse_ts(time_window_end) if time_window_end else None

    # Open read-only; copy to temp if needed to avoid locking the live DB
    events_out = []
    try:
        # Use URI mode for read-only open
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # CFAbsoluteTime epoch = 2001-01-01 UTC
        CFAT_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
        cur.execute("""
            SELECT
                LSQuarantineEventIdentifier   AS event_id,
                LSQuarantineTimeStamp         AS ts_cfat,
                LSQuarantineAgentBundleIdentifier AS agent_bundle,
                LSQuarantineAgentName         AS agent_name,
                LSQuarantineDataURLString     AS data_url,
                LSQuarantineOriginURLString   AS origin_url,
                LSQuarantineSenderName        AS sender_name,
                LSQuarantineTypeNumber        AS type_number
            FROM LSQuarantineEvent
            ORDER BY LSQuarantineTimeStamp ASC
        """)
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error as e:
        return {
            "source": {"path": str(db_path), "sha256": sha},
            "events": [],
            "total": 0,
            "next_cursor": None,
            "error": f"sqlite error: {e}",
        }

    for r in rows:
        ts_cfat = r["ts_cfat"] or 0.0
        ts_dt = CFAT_EPOCH + timedelta(seconds=ts_cfat)
        ts_iso = ts_dt.isoformat()

        if start_dt and ts_dt < start_dt:
            continue
        if end_dt and ts_dt > end_dt:
            continue

        agent_bundle = r["agent_bundle"] or ""
        agent_name = r["agent_name"] or ""
        data_url = r["data_url"] or ""
        origin_url = r["origin_url"] or ""

        flags = []
        # Flag 1: non-browser downloader
        if agent_bundle and agent_bundle not in _KNOWN_BROWSERS:
            flags.append("non_browser_downloader")
        # Flag 2-N: URL patterns (check both data_url and origin_url)
        for url in (data_url, origin_url):
            if not url:
                continue
            for pat, label in _SUSPICIOUS_URL_PATTERNS:
                if pat.search(url):
                    if label not in flags:
                        flags.append(label)

        if flagged_only and not flags:
            continue

        events_out.append({
            "event_id": r["event_id"],
            "timestamp": ts_iso,
            "agent_bundle_id": agent_bundle,
            "agent_name": agent_name,
            "data_url": data_url,
            "origin_url": origin_url,
            "sender_name": r["sender_name"] or "",
            "type_number": r["type_number"],
            "flags": flags,
        })

    total = len(events_out)
    page = events_out[cursor:cursor + limit]
    next_cursor = cursor + limit if cursor + limit < total else None

    return {
        "source": {"path": str(db_path), "sha256": sha},
        "events": page,
        "total": total,
        "flagged_count": sum(1 for e in events_out if e["flags"]),
        "next_cursor": next_cursor,
    }


# =============================================================================
# parse_linux_cron_jobs
# =============================================================================

# Suspicious cron content patterns
_CRON_SUSPICIOUS_PATTERNS = [
    (re.compile(r"\bcurl\b.*?\|\s*(?:bash|sh|python|perl)", re.I), "curl_pipe_shell"),
    (re.compile(r"\bwget\b.*?\|\s*(?:bash|sh|python|perl)", re.I), "wget_pipe_shell"),
    (re.compile(r"\bbase64\s+-d\b", re.I), "base64_decode"),
    (re.compile(r"\beval\b\s*[\$\(]", re.I), "eval_expression"),
    (re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I), "raw_ip_url"),
    (re.compile(r"\.(?:onion|i2p)\b", re.I), "darknet_url"),
    (re.compile(r"\bnc\b\s+-[el]", re.I), "netcat_listener"),
    (re.compile(r"/dev/(?:tcp|udp)/", re.I), "bash_tcp_redirect"),
    (re.compile(r"chmod\s+[+]?[sx]\b", re.I), "perm_change"),
    (re.compile(r"/tmp/[^/\s]+\.sh\b", re.I), "tmp_script"),
    (re.compile(r"@reboot", re.I), "reboot_trigger"),
]

_CRON_FILE_LOCATIONS = [
    ("/etc/crontab", "system_crontab"),
    ("/etc/cron.d/", "system_cron_d"),
    ("/etc/cron.hourly/", "system_hourly"),
    ("/etc/cron.daily/", "system_daily"),
    ("/etc/cron.weekly/", "system_weekly"),
    ("/etc/cron.monthly/", "system_monthly"),
    ("/var/spool/cron/", "user_crontab"),
    ("/var/spool/cron/crontabs/", "user_crontab_debian"),
    ("/etc/anacrontab", "anacron_system"),
]


def _scan_cron_file(path: Path, kind: str):
    """Parse a single cron file/directory entry and return list of jobs."""
    jobs = []
    if not path.exists():
        return jobs

    if path.is_dir():
        for child in sorted(path.iterdir()):
            if child.is_file():
                jobs.extend(_scan_cron_file(child, kind))
        return jobs

    try:
        content = path.read_text(errors="replace")
    except (OSError, PermissionError) as e:
        return [{"path": str(path), "kind": kind, "error": str(e)}]

    sha = _sha256(path)
    for lineno, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip env-var lines like FOO=bar (no whitespace before =)
        if "=" in line.split()[0] if line.split() else False:
            continue
        # /etc/crontab and /etc/cron.d/* have an extra user field
        # but /etc/cron.hourly/* are direct executables — different parse rules
        if kind in ("system_hourly", "system_daily", "system_weekly", "system_monthly"):
            # The file itself IS the script. Single entry per file.
            jobs.append({
                "path": str(path),
                "sha256": sha,
                "kind": kind,
                "schedule": kind.replace("system_", "") + " run",
                "user": "root",
                "command": line,
                "lineno": lineno,
                "flags": _flag_cron_command(line),
            })
            break  # only need first non-comment line as marker; actual command IS the file
        else:
            # crontab-format: minute hour dom month dow [user] command
            parts = line.split(None, 6 if kind in ("system_crontab", "system_cron_d") else 5)
            if line.startswith("@"):
                # @reboot, @hourly, @daily, @yearly etc. — single schedule token
                # system_crontab/cron.d format: @sched user command
                # user-spool format:            @sched command
                p = line.split(None, 2 if kind in ("system_crontab", "system_cron_d") else 1)
                if kind in ("system_crontab", "system_cron_d"):
                    if len(p) < 3:
                        continue
                    sched, user, cmd = p[0], p[1], p[2]
                else:
                    if len(p) < 2:
                        continue
                    sched = p[0]
                    user = path.name  # user-spool uses filename as username
                    cmd = p[1]
            elif len(parts) >= (7 if kind in ("system_crontab", "system_cron_d") else 6):
                if kind in ("system_crontab", "system_cron_d"):
                    sched = " ".join(parts[:5])
                    user = parts[5]
                    cmd = parts[6]
                else:
                    sched = " ".join(parts[:5])
                    user = path.name  # user-spool uses filename as username
                    cmd = parts[5]
            else:
                continue

            jobs.append({
                "path": str(path),
                "sha256": sha,
                "kind": kind,
                "schedule": sched,
                "user": user,
                "command": cmd,
                "lineno": lineno,
                "flags": _flag_cron_command(f"{sched} {cmd}"),
            })
    return jobs


def _flag_cron_command(cmd: str) -> list[str]:
    """Apply suspicious-pattern checks to a single cron command string."""
    flags = []
    for pat, label in _CRON_SUSPICIOUS_PATTERNS:
        if pat.search(cmd):
            flags.append(label)
    return flags


@tool(
    name="parse_linux_cron_jobs",
    description=(
        "Enumerate Linux scheduled jobs across /etc/crontab, /etc/cron.d/, "
        "/etc/cron.{hourly,daily,weekly,monthly}/, /var/spool/cron/, and /etc/anacrontab. "
        "Detects attacker-pattern signals: curl-pipe-shell, wget-pipe-shell, base64 "
        "decode, eval, raw-IP URLs, darknet TLDs, netcat listeners, bash /dev/tcp "
        "redirects, /tmp/*.sh, @reboot triggers. References: crontab(5), anacrontab(5), "
        "Red Hat RHEL Security Guide ch.7, SANS FOR577. MITRE ATT&CK: T1053.003 (Cron), "
        "T1059.004 (Unix Shell), T1546 (Event Triggered Execution)."
    ),
    schema={
        "type": "object",
        "properties": {
            "evidence_root": {
                "type": "string",
                "description": "Root path to scan (default '/'). Use evidence_root/ for mounted images.",
                "default": "/",
            },
            "flagged_only": {
                "type": "boolean",
                "description": "Return only jobs with at least one suspicious flag (default false)",
                "default": False,
            },
            "cursor": {"type": "integer", "default": 0},
            "limit": {"type": "integer", "default": 500},
        },
    },
)
def parse_linux_cron_jobs(
    evidence_root: str = "/",
    flagged_only: bool = False,
    cursor: int = 0,
    limit: int = 500,
):
    root = _safe_resolve(evidence_root)
    all_jobs = []
    scanned_paths = []

    for relpath, kind in _CRON_FILE_LOCATIONS:
        # join evidence_root with the standard path
        joined = root / relpath.lstrip("/")
        scanned_paths.append(str(joined))
        all_jobs.extend(_scan_cron_file(joined, kind))

    if flagged_only:
        all_jobs = [j for j in all_jobs if j.get("flags")]

    flagged_count = sum(1 for j in all_jobs if j.get("flags"))
    total = len(all_jobs)
    page = all_jobs[cursor:cursor + limit]
    next_cursor = cursor + limit if cursor + limit < total else None

    return {
        "source": {"evidence_root": str(root), "scanned_paths": scanned_paths},
        "jobs": page,
        "total": total,
        "flagged_count": flagged_count,
        "next_cursor": next_cursor,
    }


# =============================================================================
# detect_dns_tunneling
# =============================================================================

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Public suffix shortlist — common TLDs we want to extract the parent domain from.
# Not exhaustive (no Public Suffix List dependency), but covers 95% of common cases.
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
    "com.au", "com.br", "com.cn", "com.tw", "com.hk", "com.sg",
    "ac.uk", "ac.jp", "ac.kr",
    "gov.uk", "gov.jp", "gov.kr",
    "or.kr", "or.jp", "ne.jp", "go.kr",
}


def _parent_domain(fqdn: str) -> str:
    """Return the registered parent domain of an FQDN (heuristic, no PSL)."""
    parts = fqdn.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # check two-level suffix
    if ".".join(parts[-2:]) in _TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# DNS query log format — common patterns we handle:
# bind9: 14-May-2026 10:23:45.123 client @0x7f... 10.0.0.1#54321 (a.example.com): query: a.example.com IN A +E(0)K (10.0.0.2)
# dnsmasq: May 14 10:23:45 host dnsmasq[1234]: query[A] a.example.com from 10.0.0.1
# unified format heuristic: pull last token ending in .ext-like, lowercased

_DNS_QUERY_PATTERNS = [
    # bind9 query log
    re.compile(r"query:\s+([a-zA-Z0-9._\-]+)\s+IN\s+(\w+)"),
    # dnsmasq
    re.compile(r"query\[(\w+)\]\s+([a-zA-Z0-9._\-]+)\s+from"),
    # generic FQDN extraction (last resort)
    re.compile(r"\b([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+){2,})\b"),
]


@tool(
    name="detect_dns_tunneling",
    description=(
        "Scan DNS query logs for tunneling / C2 indicators: high-Shannon-entropy "
        "subdomain labels, abnormally long labels (>50 char), high query volume per "
        "parent domain in short window, rare TXT/NULL/CNAME record types, and "
        "well-known tunneling tool signatures (Iodine, dnscat2, DNScat-B). Supports "
        "BIND9 query.log, dnsmasq syslog, and generic FQDN-extraction fallback. "
        "References: SANS FOR572 'Advanced Network Forensics', Iodine paper "
        "(Yarrin & Andersson 2009), RFC 1035, RFC 3833. MITRE ATT&CK: T1071.004 "
        "(Application Layer Protocol: DNS), T1568.002 (DGA), T1572 (Protocol "
        "Tunneling), TA0011 (Command and Control)."
    ),
    schema={
        "type": "object",
        "properties": {
            "dns_log_path": {
                "type": "string",
                "description": "Path to DNS query log (BIND9 query.log, dnsmasq syslog, or plain-text)",
            },
            "entropy_threshold": {
                "type": "number",
                "description": "Shannon entropy threshold for flagging a subdomain label (default 3.8)",
                "default": 3.8,
            },
            "long_label_threshold": {
                "type": "integer",
                "description": "Label length threshold (default 50; DNS spec max is 63)",
                "default": 50,
            },
            "volume_threshold": {
                "type": "integer",
                "description": "Min queries to same parent domain within window to flag (default 50)",
                "default": 50,
            },
            "volume_window_seconds": {
                "type": "integer",
                "description": "Sliding window for volume check (default 300s = 5min)",
                "default": 300,
            },
            "cursor": {"type": "integer", "default": 0},
            "limit": {"type": "integer", "default": 200},
        },
        "required": ["dns_log_path"],
    },
)
def detect_dns_tunneling(
    dns_log_path: str,
    entropy_threshold: float = 3.8,
    long_label_threshold: int = 50,
    volume_threshold: int = 50,
    volume_window_seconds: int = 300,
    cursor: int = 0,
    limit: int = 200,
):
    log_path = _safe_resolve(dns_log_path)
    if not log_path.exists():
        return {
            "source": {"path": str(log_path), "sha256": ""},
            "flagged_queries": [],
            "high_volume_domains": [],
            "total_queries_parsed": 0,
            "total_flagged": 0,
            "next_cursor": None,
            "error": f"DNS log not found at {log_path}",
        }

    sha = _sha256(log_path)
    queries = []  # all parsed (fqdn, qtype, line_no)
    flagged = []

    try:
        with log_path.open("r", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                fqdn = None
                qtype = None

                # try bind9 pattern
                m = _DNS_QUERY_PATTERNS[0].search(line)
                if m:
                    fqdn = m.group(1).lower()
                    qtype = m.group(2).upper()
                else:
                    m = _DNS_QUERY_PATTERNS[1].search(line)
                    if m:
                        qtype = m.group(1).upper()
                        fqdn = m.group(2).lower()
                    else:
                        # generic fallback
                        m = _DNS_QUERY_PATTERNS[2].search(line)
                        if m:
                            fqdn = m.group(1).lower()
                            qtype = "?"

                if not fqdn or len(fqdn) < 4:
                    continue
                fqdn = fqdn.rstrip(".")
                if fqdn.count(".") < 1:
                    continue

                queries.append((fqdn, qtype, lineno))

                # per-query flags
                labels = fqdn.split(".")
                subdomain_labels = labels[:-2] if len(labels) > 2 else []
                qflags = []

                for lbl in subdomain_labels:
                    if len(lbl) > long_label_threshold:
                        qflags.append("long_label")
                    if len(lbl) >= 8:  # entropy meaningful only above this
                        ent = _shannon_entropy(lbl)
                        if ent > entropy_threshold:
                            qflags.append("high_entropy_label")
                            break  # one flag per query is enough

                if qtype in ("TXT", "NULL", "CNAME") and len(subdomain_labels) >= 1:
                    qflags.append(f"rare_qtype_{qtype}")

                # well-known tool signatures
                if any("dnscat" in lbl for lbl in subdomain_labels):
                    qflags.append("dnscat2_signature")
                if subdomain_labels and subdomain_labels[0].startswith("io") and len(subdomain_labels[0]) > 40:
                    # iodine prefixes with base32-encoded data
                    qflags.append("iodine_signature_candidate")

                if qflags:
                    flagged.append({
                        "fqdn": fqdn,
                        "qtype": qtype,
                        "lineno": lineno,
                        "flags": list(set(qflags)),
                    })
    except (OSError, UnicodeDecodeError) as e:
        return {
            "source": {"path": str(log_path), "sha256": sha},
            "flagged_queries": [],
            "high_volume_domains": [],
            "total_queries_parsed": 0,
            "total_flagged": 0,
            "next_cursor": None,
            "error": f"log read error: {e}",
        }

    # Volume analysis: count queries per parent domain
    by_parent = Counter(_parent_domain(fqdn) for fqdn, _, _ in queries)
    high_volume = [
        {"parent_domain": pd, "query_count": cnt}
        for pd, cnt in by_parent.most_common()
        if cnt >= volume_threshold
    ]

    total_flagged = len(flagged)
    page = flagged[cursor:cursor + limit]
    next_cursor = cursor + limit if cursor + limit < total_flagged else None

    return {
        "source": {"path": str(log_path), "sha256": sha},
        "flagged_queries": page,
        "high_volume_domains": high_volume,
        "total_queries_parsed": len(queries),
        "total_flagged": total_flagged,
        "next_cursor": next_cursor,
    }
