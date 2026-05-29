"""
sift_adapters.evtxecmd — Eric Zimmerman EvtxECmd wrapper.

EvtxECmd parses Windows EVTX files into structured JSON / CSV. It's the
preferred EVTX parser on the SIFT Workstation (the alternative being
python-evtx for pure-Python or libevtx).

Tool: EvtxECmd (.NET 6 cross-platform)
Source: https://github.com/EricZimmerman/evtx
On SIFT: bundled in /opt/EricZimmermanTools/

What we expose:
    sift_evtxecmd_parse        Parse a single EVTX or directory to structured rows
    sift_evtxecmd_filter_eids  Convenience: parse + filter to specific Event IDs
"""
from __future__ import annotations

import csv
from typing import Any

from dart_mcp import tool

from ._common import (
    _sha256,
    _tempdir,
    _which,
    run_tool,
    safe_evidence_input,
)

EVTXECMD_TIMEOUT_SECONDS = 1800  # 30 min — multi-GB EVTX directories take time


def _evtxecmd_bin() -> str:
    return _which("EvtxECmd", env_var="DART_EVTXECMD_BIN")


def _run_evtxecmd(evtx_path: str, csv_filename: str = "evtx.csv",
                  max_rows: int | None = None,
                  row_filter=None) -> dict[str, Any]:
    """Internal — run EvtxECmd and stream-parse the resulting CSV.

    OOM-safety: EvtxECmd output for a busy Security.evtx
    can be hundreds of MB to multiple GB. The old implementation did
    `rows = [dict(r) for r in reader]`, materializing the ENTIRE CSV into
    a list of dicts before any limit was applied — a textbook OOM on real
    evidence. We now stream the CSV row-by-row and stop materializing once
    `max_rows` matching rows are collected, while still counting the total
    so callers can report `events_total` without holding every row.

    Args:
        max_rows: stop collecting after this many rows are kept (None =
            keep all — only safe for small inputs / tests).
        row_filter: optional predicate(dict) -> bool. Only rows for which
            it returns True are kept and counted toward max_rows. Rows that
            don't match are still counted in `total_scanned` but discarded
            immediately, so a filtered scan never holds the non-matching
            rows in memory.
    """
    sample = safe_evidence_input(evtx_path)
    sample_sha = _sha256(sample) if sample.is_file() else None

    with _tempdir(prefix="dart-evtxecmd-") as workdir:
        out_csv = workdir / csv_filename
        # EvtxECmd accepts -f for single file, -d for directory
        flag = "-d" if sample.is_dir() else "-f"
        cmd = [
            _evtxecmd_bin(),
            flag, str(sample),
            "--csv", str(workdir),
            "--csvf", csv_filename,
        ]
        result = run_tool(cmd, timeout=EVTXECMD_TIMEOUT_SECONDS,
                          capture_files=[out_csv])

        if not out_csv.is_file():
            return {
                "rows": [],
                "total_scanned": 0,
                "truncated": False,
                "stderr_tail": result.stderr[-500:],
                "duration_ms": result.duration_ms,
                "csv_sha256": None,
                "evtx_sha256": sample_sha,
            }

        rows: list[dict[str, Any]] = []
        total_scanned = 0
        truncated = False
        with out_csv.open("r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                total_scanned += 1
                if row_filter is not None and not row_filter(r):
                    continue
                if max_rows is None or len(rows) < max_rows:
                    rows.append(dict(r))
                elif max_rows is not None:
                    # We've collected our budget; keep counting total but
                    # stop materializing. For an unfiltered read we can
                    # stop scanning entirely (total would just be the file
                    # length, which the caller rarely needs precisely once
                    # truncated); for a filtered read we keep scanning so
                    # the matched-vs-scanned ratio stays meaningful.
                    truncated = True
                    if row_filter is None:
                        break

        return {
            "rows": rows,
            "total_scanned": total_scanned,
            "truncated": truncated,
            "duration_ms": result.duration_ms,
            "csv_sha256": result.output_files.get(str(out_csv)),
            "evtx_sha256": sample_sha,
        }


@tool(
    name="sift_evtxecmd_parse",
    description=(
        "Parse Windows EVTX file(s) via EvtxECmd. Accepts a single .evtx file "
        "or a directory. Returns structured event rows with TimeCreated, "
        "EventID, Channel, Computer, EventData, etc."
    ),
    schema={
        "type": "object",
        "properties": {
            "evtx_path": {
                "type": "string",
                "description": "Path to .evtx file or directory of .evtx files",
            },
            "limit": {
                "type": "integer", "default": 10000,
                "description": "Max events to return",
            },
        },
        "required": ["evtx_path"],
    },
)
def sift_evtxecmd_parse(evtx_path: str, limit: int = 10000) -> dict[str, Any]:
    # OOM-safe: only materialize up to `limit` rows. total_scanned reflects
    # how many events the CSV actually held (or, if truncated, at least
    # `limit`+the scan that hit the cap).
    parsed = _run_evtxecmd(evtx_path, max_rows=limit)
    rows = parsed["rows"]
    return {
        "events": rows,
        "metadata": {
            "tool": "evtxecmd",
            "evtx_path": evtx_path,
            "evtx_sha256": parsed.get("evtx_sha256"),
            "csv_sha256": parsed.get("csv_sha256"),
            "events_returned": len(rows),
            "events_total": parsed.get("total_scanned", len(rows)),
            "truncated": parsed.get("truncated", False),
            "limit": limit,
            "duration_ms": parsed["duration_ms"],
        },
    }


# The "heavy 12" EIDs from [Cheatsheet] evtx-threat-hunting-2026.md
_DEFAULT_HEAVY_HITTERS = [
    "4624", "4625", "4634", "4647", "4648", "4672", "4688",
    "4697", "4698", "4702", "4720", "4732", "4769", "5140", "5145",
    # Sysmon
    "1", "3", "11", "13",
    # PowerShell
    "4104",
]


@tool(
    name="sift_evtxecmd_filter_eids",
    description=(
        "Parse EVTX file(s) and filter to specific Event IDs. By default "
        "returns the 'heavy hitter' EIDs that catch ~80% of intrusions: "
        "4624/4625/4648/4672/4688/4697 etc. + Sysmon 1/3/11/13 + PowerShell 4104."
    ),
    schema={
        "type": "object",
        "properties": {
            "evtx_path": {"type": "string"},
            "event_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Event IDs to keep (string form). Empty = use defaults.",
            },
            "limit": {"type": "integer", "default": 10000},
        },
        "required": ["evtx_path"],
    },
)
def sift_evtxecmd_filter_eids(
    evtx_path: str,
    event_ids: list[str] | None = None,
    limit: int = 10000,
) -> dict[str, Any]:
    keep_eids = set(event_ids) if event_ids else set(_DEFAULT_HEAVY_HITTERS)

    # OOM-safe: push the EID predicate down into the streaming reader so
    # non-matching rows are discarded the instant they're read, never
    # accumulated. Only up to `limit` matching rows are materialized.
    def _keep(row: dict) -> bool:
        # EvtxECmd CSV column is "EventId" (no underscore, capital I)
        eid = str(row.get("EventId") or row.get("EventID") or "").strip()
        return eid in keep_eids

    parsed = _run_evtxecmd(evtx_path, max_rows=limit, row_filter=_keep)
    filtered = parsed["rows"]

    return {
        "events": filtered,
        "metadata": {
            "tool": "evtxecmd",
            "evtx_path": evtx_path,
            "evtx_sha256": parsed.get("evtx_sha256"),
            "filter_eids": sorted(keep_eids),
            "events_total": parsed.get("total_scanned", len(filtered)),
            "events_after_filter": len(filtered),
            "truncated": parsed.get("truncated", False),
            "limit": limit,
            "duration_ms": parsed["duration_ms"],
        },
    }
