"""dart_corr — cross-artifact correlation engine.

The architectural responsibility of this package is to *surface
contradictions* between artifacts, not to interpret them. The agent
(dart_agent) interprets; this package mechanically detects.

Three public entry points, all pure functions:

  - correlate_events(...)               proximity join, IP-KVM vs logon
  - correlate_timeline(...)             DuckDB-backed n-source join
  - correlate_download_to_execution(...) download → exec corroboration

Design contract:

  - No I/O. All inputs come in as Python data structures.
  - No agent state. Each call is independent.
  - Contradictions are returned as records with status='UNRESOLVED',
    never auto-resolved.
  - Rules are loaded from correlation-rules.yaml (shipped alongside
    this package). The rule pack is operator-tunable without touching
    Python.

These functions are exposed to the MCP wire through dart_mcp, which
imports and wraps them. Calling code can use either entry point —
direct import or via the MCP server — and gets identical behavior.

Version: 0.7.1 (extracted from dart_mcp inline implementation)
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

__version__ = "0.7.1"

# Timestamp formats we accept on input. Kept tolerant because evidence
# sources (Plaso/log2timeline, EVTX, MFT, bash history) all have their
# own conventions and we want to merge them without forcing a
# normalization pass on the caller.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
)


def _parse_ts(s: str | None) -> datetime | None:
    """Parse a timestamp string into a datetime, returning None on failure.

    Returning None (instead of raising) is deliberate — correlation
    functions get noisy inputs, and one malformed row should not abort
    the whole join."""
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# ─── Rule pack loader ─────────────────────────────────────────────────────

_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "correlation-rules.yaml"


def load_rules(path: Path | None = None) -> dict[str, Any]:
    """Load the correlation rule pack. Caller may override with a custom
    path for testing.

    The default location is dart_corr/correlation-rules.yaml at the
    package root. If the file is missing or yaml is not installed, we
    return an empty rule set rather than raising — the engine's
    built-in joins still work, just without operator-tunable rules
    layered on top."""
    p = path or _RULES_PATH
    if not p.exists():
        return {"rules": [], "_loaded_from": None}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {"rules": [], "_loaded_from": None,
                "_error": "pyyaml not installed; rule pack ignored"}
    try:
        data = yaml.safe_load(p.read_text()) or {}
        data["_loaded_from"] = str(p)
        return data
    except Exception as exc:
        return {"rules": [], "_loaded_from": str(p), "_error": str(exc)}


# ─── correlate_events ─────────────────────────────────────────────────────

def correlate_events(
    hypothesis_id: str,
    usb_events: list[dict] | None = None,
    logon_events: list[dict] | None = None,
    proximity_seconds: int = 600,
) -> dict[str, Any]:
    """Time-proximity join — USB events vs logon events.

    The headline case: IP-KVM USB device inserted ≤ proximity_seconds
    before a logon. That's the IP-KVM-precedes-logon contradiction
    pattern (insider-threat / DPRK IT-worker tells).

    Args:
      hypothesis_id: the agent's current hypothesis ID, threaded
        through so audit can correlate this call back to the
        hypothesis being tested.
      usb_events: list of dicts with at least 'ts' and 'is_ip_kvm'.
      logon_events: list of dicts with at least 'ts'.
      proximity_seconds: max gap to count as proximity (default 600s).

    Returns:
      dict with hypothesis_id, event counts, list of contradictions
      (each with status='UNRESOLVED' — never auto-resolved), and
      clean_correlations count.
    """
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
        "usb_event_count": len(usb_events),
        "logon_event_count": len(logon_events),
        "contradictions": flags,
        "clean_correlations": max(
            0, len(usb_events) * len(logon_events) - len(flags)),
    }


# ─── correlate_timeline ───────────────────────────────────────────────────

def correlate_timeline(
    events: list[dict],
    rules: list[dict] | None = None,
    window_seconds: int = 300,
) -> dict[str, Any]:
    """DuckDB-backed n-source timeline correlation.

    Accepts a heterogeneous list of event dicts from disk, memory,
    network, EVTX, etc. and joins cross-source events that share an
    actor or target inside window_seconds. Surfaces matches as
    'correlations' and contradictory matches (different fact, same
    actor/target) as 'contradictions' with status='UNRESOLVED'.

    This is the function that lets the agent ask 'did event X on disk
    have a corresponding event on the network within Y seconds?' at
    MFT scale without writing SQL.

    Args:
      events: list of dicts. Each dict should have ts (ISO-ish),
        source (string), and at least one of actor/user, target/path/
        image, type/event_type.
      rules: optional list of rule overlays. If None, we load the
        default rule pack from correlation-rules.yaml.
      window_seconds: join window (default 300s).

    Returns:
      dict with normalized_event_count, correlation count,
      contradictions list, and the DuckDB query stats.
    """
    import duckdb  # type: ignore

    normalized = []
    for e in events:
        if not isinstance(e, dict):
            continue
        ts = _parse_ts(str(e.get("ts", "") or e.get("timestamp", "")))
        if ts is None:
            continue
        normalized.append({
            "ts": ts,
            "source": e.get("source", ""),
            "actor": e.get("actor", "") or e.get("user", ""),
            "target": (e.get("target", "")
                       or e.get("path", "")
                       or e.get("image", "")),
            "type": e.get("type", "") or e.get("event_type", ""),
            "raw": json.dumps(e, default=str, sort_keys=True)[:2000],
        })

    if not normalized:
        return {
            "normalized_event_count": 0,
            "correlations": [],
            "contradictions": [],
            "window_seconds": window_seconds,
        }

    con = duckdb.connect(":memory:")
    con.execute("""
        CREATE TABLE ev (
            ts TIMESTAMP, source VARCHAR, actor VARCHAR,
            target VARCHAR, type VARCHAR, raw VARCHAR
        )
    """)
    con.executemany(
        "INSERT INTO ev VALUES (?, ?, ?, ?, ?, ?)",
        [(e["ts"], e["source"], e["actor"], e["target"],
          e["type"], e["raw"]) for e in normalized],
    )
    con.execute("CREATE INDEX ev_ts ON ev(ts)")

    # Cross-source actor or target match inside the time window.
    correlations = con.execute(f"""
        SELECT e1.source AS s1, e1.ts AS ts1, e1.actor AS a1,
               e1.target AS t1, e1.type AS ty1,
               e2.source AS s2, e2.ts AS ts2, e2.actor AS a2,
               e2.target AS t2, e2.type AS ty2,
               date_diff('second', e1.ts, e2.ts) AS delta_s
        FROM ev e1 JOIN ev e2
          ON e1.source <> e2.source
          AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {int(window_seconds)} SECOND
          AND ((e1.actor <> '' AND e1.actor = e2.actor)
               OR (e1.target <> '' AND e1.target = e2.target))
        LIMIT 1000
    """).fetchall()

    # Contradiction: same actor at overlapping time but different
    # event type. (e.g. process exit on disk vs same actor still
    # creating sockets on network.)
    contradictions = []
    seen_pairs: set[tuple] = set()
    for row in correlations:
        s1, ts1, a1, t1, ty1, s2, ts2, a2, t2, ty2, delta = row
        if ty1 and ty2 and ty1 != ty2 and a1 and a1 == a2:
            key = (a1, ty1, ty2)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            contradictions.append({
                "rule": "actor_concurrent_disagreement",
                "actor": a1,
                "source_a": s1, "type_a": ty1, "ts_a": str(ts1),
                "source_b": s2, "type_b": ty2, "ts_b": str(ts2),
                "delta_seconds": int(delta),
                "status": "UNRESOLVED",
            })

    # Apply caller-supplied or default rule overlays (operator-tunable
    # contradiction patterns).
    rules = rules if rules is not None else load_rules().get("rules", [])
    for rule in rules:
        # Each rule names a pair of source types that should be
        # mutually exclusive within window_seconds. The rule pack
        # lives in correlation-rules.yaml; see that file for the
        # canonical examples.
        src_a = rule.get("source_a")
        src_b = rule.get("source_b")
        if not (src_a and src_b):
            continue
        rule_window = int(rule.get("window_seconds", window_seconds))
        matches = con.execute(f"""
            SELECT e1.actor, e1.ts, e2.ts,
                   date_diff('second', e1.ts, e2.ts) AS delta_s
            FROM ev e1 JOIN ev e2
              ON e1.source = ? AND e2.source = ?
              AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {rule_window} SECOND
              AND e1.actor <> '' AND e1.actor = e2.actor
        """, [src_a, src_b]).fetchall()
        for actor, ts_a, ts_b, delta in matches:
            contradictions.append({
                "rule": rule.get("name", f"{src_a}_vs_{src_b}"),
                "actor": actor,
                "source_a": src_a, "ts_a": str(ts_a),
                "source_b": src_b, "ts_b": str(ts_b),
                "delta_seconds": int(delta),
                "severity": rule.get("severity", "medium"),
                "status": "UNRESOLVED",
            })

    con.close()
    return {
        "normalized_event_count": len(normalized),
        "correlations": [
            {"source_a": r[0], "ts_a": str(r[1]), "actor_a": r[2],
             "target_a": r[3], "type_a": r[4],
             "source_b": r[5], "ts_b": str(r[6]), "actor_b": r[7],
             "target_b": r[8], "type_b": r[9],
             "delta_seconds": int(r[10])}
            for r in correlations[:100]
        ],
        "correlations_truncated_at": 100 if len(correlations) > 100 else None,
        "contradictions": contradictions,
        "window_seconds": window_seconds,
    }


# ─── correlate_download_to_execution ──────────────────────────────────────

def correlate_download_to_execution(
    downloads: list[dict],
    executions: list[dict],
    window_seconds: int = 86400,
) -> dict[str, Any]:
    """Corroborate download events against subsequent execution events.

    Used in phishing→exfil cases: when did the dropper land, and when
    did it run? If a hypothesis claims 'executable X is malicious',
    this function looks for a matching download record that names X
    (or a parent path of X) inside window_seconds before the exec.

    No download record = the agent should revise the hypothesis (it
    might be a LOLBin call, not a dropper).

    Args:
      downloads: list of dicts with at least 'ts' and 'path'/'name'.
      executions: list of dicts with at least 'ts' and 'image'/'path'.
      window_seconds: how far back to look for a matching download
        (default 86400s = 24h).

    Returns:
      dict with execution counts, corroborated (matched) list,
      uncorroborated (no matching download — agent must revise) list.
    """
    corroborated = []
    uncorroborated = []
    for ex in executions:
        ex_ts = _parse_ts(str(ex.get("ts", "") or ex.get("timestamp", "")))
        if ex_ts is None:
            continue
        ex_image = (ex.get("image", "") or ex.get("path", "")
                    or ex.get("name", ""))
        ex_basename = ex_image.replace("\\", "/").rsplit("/", 1)[-1].lower()
        match = None
        for dl in downloads:
            dl_ts = _parse_ts(str(dl.get("ts", "") or dl.get("timestamp", "")))
            if dl_ts is None:
                continue
            delta = (ex_ts - dl_ts).total_seconds()
            if not (0 <= delta <= window_seconds):
                continue
            dl_path = (dl.get("path", "") or dl.get("name", "")
                       or dl.get("file", ""))
            dl_basename = dl_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if dl_basename and ex_basename and (
                    dl_basename == ex_basename
                    or dl_basename in ex_image.lower()
                    or ex_basename in dl_path.lower()):
                match = {
                    "download": dl, "execution": ex,
                    "delta_seconds": int(delta),
                    "status": "CORROBORATED",
                }
                break
        if match:
            corroborated.append(match)
        else:
            uncorroborated.append({
                "execution": ex,
                "image": ex_image,
                "status": "UNCORROBORATED — no matching download in window",
                "window_seconds": window_seconds,
            })
    return {
        "execution_count": len(executions),
        "download_count": len(downloads),
        "corroborated": corroborated,
        "uncorroborated": uncorroborated,
        "window_seconds": window_seconds,
        # The agent uses this to decide whether to revise the
        # hypothesis. uncorroborated > 0 means at least one claim
        # 'X is a malicious download' has no download to back it.
        "revision_required": len(uncorroborated) > 0,
    }


__all__ = [
    "correlate_events",
    "correlate_timeline",
    "correlate_download_to_execution",
    "load_rules",
    "__version__",
]
