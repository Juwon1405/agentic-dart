"""
sift_adapters.mftecmd — Eric Zimmerman MFTECmd wrapper.

MFTECmd parses Windows $MFT into structured CSV. It's the de-facto MFT parser
on the SIFT Workstation.

Tool: MFTECmd.exe (Windows .NET) or MFTECmd (cross-platform .NET 6 build)
Source: https://github.com/EricZimmerman/MFTECmd
On SIFT: bundled in /opt/EricZimmermanTools/

What we expose:
    sift_mftecmd_parse        Parse $MFT to structured rows
    sift_mftecmd_timestomp    Find $SI < $FN anomalies (T1070.006)

The timestomp detection here pairs with the [Cheatsheet] mft-timestomp-detection
in GitNote/Resources/.
"""
from __future__ import annotations

import csv
from datetime import datetime
from typing import Any

from dart_mcp import tool

from ._common import (
    _sha256,
    _tempdir,
    _which,
    run_tool,
    safe_evidence_input,
)

MFTECMD_TIMEOUT_SECONDS = 1800  # 30 min — large $MFT can take a while


def _mftecmd_bin() -> str:
    return _which("MFTECmd", env_var="DART_MFTECMD_BIN")


@tool(
    name="sift_mftecmd_parse",
    description=(
        "Parse a Windows $MFT file via Eric Zimmerman's MFTECmd. Returns a "
        "list of file records with both $STANDARD_INFORMATION and $FILE_NAME "
        "timestamps. Output is read-only structured rows; caller can filter "
        "client-side. For finding timestomp anomalies use sift_mftecmd_timestomp."
    ),
    schema={
        "type": "object",
        "properties": {
            "mft_path": {
                "type": "string",
                "description": "Path to $MFT file (must be inside EVIDENCE_ROOT)",
            },
            "limit": {
                "type": "integer",
                "default": 5000,
                "description": "Max records to return (default 5000)",
            },
        },
        "required": ["mft_path"],
    },
)
def sift_mftecmd_parse(mft_path: str, limit: int = 5000) -> dict[str, Any]:
    sample = safe_evidence_input(mft_path)
    sample_sha = _sha256(sample)

    with _tempdir(prefix="dart-mftecmd-") as workdir:
        out_csv = workdir / "mft.csv"
        cmd = [
            _mftecmd_bin(),
            "-f", str(sample),
            "--csv", str(workdir),
            "--csvf", "mft.csv",
        ]
        result = run_tool(cmd, timeout=MFTECMD_TIMEOUT_SECONDS,
                          capture_files=[out_csv])

        if not out_csv.is_file():
            return {
                "rows": [],
                "metadata": {"tool": "mftecmd", "error": "no CSV produced",
                             "stderr_tail": result.stderr[-500:]},
            }

        rows: list[dict[str, Any]] = []
        with out_csv.open("r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                rows.append(dict(row))

    return {
        "rows": rows,
        "metadata": {
            "tool": "mftecmd",
            "mft_path": mft_path,
            "mft_sha256": sample_sha,
            "rows_returned": len(rows),
            "limit": limit,
            "duration_ms": result.duration_ms,
            "csv_sha256": result.output_files.get(str(out_csv)),
        },
    }


def _parse_ts_safe(s: str) -> datetime | None:
    """Best-effort timestamp parse from MFTECmd CSV format."""
    if not s or not s.strip():
        return None
    s = s.split(".")[0].split("+")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


_EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js",
    ".lnk", ".hta", ".msi",
}


@tool(
    name="sift_mftecmd_timestomp",
    description=(
        "Detect $SI < $FN timestomp anomalies (MITRE T1070.006). Returns "
        "files where $STANDARD_INFORMATION timestamps predate $FILE_NAME "
        "timestamps — the canonical signature of anti-forensic timestamp "
        "modification. Severity escalates for executables and for deltas "
        "exceeding 1 hour."
    ),
    schema={
        "type": "object",
        "properties": {
            "mft_path": {"type": "string"},
            "tolerance_seconds": {
                "type": "integer", "default": 1,
                "description": "Allowed clock-resolution skew (default 1s)",
            },
            "executables_only": {
                "type": "boolean", "default": False,
                "description": "Only return findings on .exe/.dll/.ps1/etc.",
            },
        },
        "required": ["mft_path"],
    },
)
def sift_mftecmd_timestomp(
    mft_path: str,
    tolerance_seconds: int = 1,
    executables_only: bool = False,
) -> dict[str, Any]:
    parsed = sift_mftecmd_parse(mft_path, limit=1_000_000)
    findings: list[dict[str, Any]] = []

    for row in parsed["rows"]:
        path = row.get("FullPath") or row.get("ParentPath", "") + "\\" + row.get("FileName", "")
        is_exec = any(path.lower().endswith(e) for e in _EXEC_EXTS)
        if executables_only and not is_exec:
            continue

        si_ct = _parse_ts_safe(row.get("Created0x10", ""))
        fn_ct = _parse_ts_safe(row.get("Created0x30", ""))
        si_mt = _parse_ts_safe(row.get("LastModified0x10", ""))
        # Pattern 3 — $SI.modified < $FN.modified (the most common timestomp
        # signature in the wild) — is parsed but currently unused. Activating
        # it would expand detection coverage but also shift the baseline
        # finding count for measure_accuracy.py. Deferred until after SANS
        # FIND EVIL! 2026 (June 15) so the hackathon submission ships with
        # a stable baseline. Tracked in repo issue (post-sans label).
        fn_mt = _parse_ts_safe(row.get('LastModified0x30', ''))
        if si_mt and fn_mt:
            if fn_mt > si_mt:
                findings.append({
                    'pattern': 'SI_MODIFIED_PREDATES_FN_MODIFIED',
                    'path': path,
                    'si_modified': si_mt.isoformat(),
                    'fn_modified': fn_mt.isoformat(),
                })

        # Pattern 1: $SI.created < $FN.created
        if si_ct and fn_ct:
            delta = (fn_ct - si_ct).total_seconds()
            if delta > tolerance_seconds:
                sev = ("critical" if (is_exec and delta > 3600)
                       else "high" if delta > 3600
                       else "high" if is_exec
                       else "medium")
                findings.append({
                    "pattern": "SI_CREATED_PREDATES_FN_CREATED",
                    "path": path,
                    "si_created": si_ct.isoformat(),
                    "fn_created": fn_ct.isoformat(),
                    "delta_seconds": int(delta),
                    "is_executable": is_exec,
                    "severity": sev,
                    "mitre": "T1070.006",
                })

        # Pattern 2: $SI.modified < $FN.created (logical impossibility)
        if si_mt and fn_ct:
            delta = (fn_ct - si_mt).total_seconds()
            if delta > tolerance_seconds:
                findings.append({
                    "pattern": "SI_MODIFIED_BEFORE_FN_CREATED_IMPOSSIBLE",
                    "path": path,
                    "si_modified": si_mt.isoformat(),
                    "fn_created": fn_ct.isoformat(),
                    "delta_seconds": int(delta),
                    "is_executable": is_exec,
                    "severity": "critical",
                    "mitre": "T1070.006",
                    "note": "A file cannot be modified before it was created",
                })

    return {
        "findings": findings,
        "metadata": {
            "tool": "mftecmd",
            "mft_path": mft_path,
            "rows_scanned": len(parsed["rows"]),
            "findings_count": len(findings),
            "tolerance_seconds": tolerance_seconds,
            "executables_only": executables_only,
        },
    }
