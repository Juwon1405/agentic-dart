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


def _run_evtxecmd(evtx_path: str, csv_filename: str = "evtx.csv") -> dict[str, Any]:
    """Internal — run EvtxECmd and return parsed CSV rows."""
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
                "stderr_tail": result.stderr[-500:],
                "duration_ms": result.duration_ms,
                "csv_sha256": None,
                "evtx_sha256": sample_sha,
            }

        rows: list[dict[str, Any]] = []
        with out_csv.open("r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            rows = [dict(r) for r in reader]

        return {
            "rows": rows,
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
    parsed = _run_evtxecmd(evtx_path)
    rows = parsed["rows"][:limit]
    return {
        "events": rows,
        "metadata": {
            "tool": "evtxecmd",
            "evtx_path": evtx_path,
            "evtx_sha256": parsed.get("evtx_sha256"),
            "csv_sha256": parsed.get("csv_sha256"),
            "events_returned": len(rows),
            "events_total": len(parsed["rows"]),
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

    parsed = _run_evtxecmd(evtx_path)
    filtered = []
    for row in parsed["rows"]:
        # EvtxECmd CSV column is "EventId" (no underscore, capital I)
        eid = str(row.get("EventId") or row.get("EventID") or "").strip()
        if eid in keep_eids:
            filtered.append(row)
            if len(filtered) >= limit:
                break

    return {
        "events": filtered,
        "metadata": {
            "tool": "evtxecmd",
            "evtx_path": evtx_path,
            "evtx_sha256": parsed.get("evtx_sha256"),
            "filter_eids": sorted(keep_eids),
            "events_total": len(parsed["rows"]),
            "events_after_filter": len(filtered),
            "limit": limit,
            "duration_ms": parsed["duration_ms"],
        },
    }
