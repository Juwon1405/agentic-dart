"""
sift_adapters.recmd — Eric Zimmerman RECmd wrapper.

RECmd parses Windows Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SAM,
SECURITY, USRCLASS.DAT) using a built-in plugin/batch-file system that
includes high-yield ASEP enumerators out of the box.

Tool: RECmd (.NET 6 cross-platform)
Source: https://github.com/EricZimmerman/RECmd
On SIFT: bundled in /opt/EricZimmermanTools/

What we expose:
    sift_recmd_run_batch       Run a built-in or custom batch (e.g. ASEPs.reb)
    sift_recmd_query_key       Query a specific registry path
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

RECMD_TIMEOUT_SECONDS = 900  # 15 min


def _recmd_bin() -> str:
    return _which("RECmd", env_var="DART_RECMD_BIN")


# Curated list of ASEP-relevant batch files shipped with RECmd.
# These map to common persistence + DFIR enumeration patterns.
_KNOWN_BATCHES = {
    "ASEPs": "RECmd_Batch_MC.reb",   # Maxim Suhanov's ASEP enumerator
    "kroll":  "Kroll_Batch.reb",     # Kroll's full DFIR batch
    "USB":    "USB.reb",
    "All":    "RECmd_Batch_MC.reb",  # alias
}


@tool(
    name="sift_recmd_run_batch",
    description=(
        "Run a RECmd batch file against a registry hive. The batch system "
        "includes built-in ASEP (Auto-Start Extension Points) enumerators "
        "that surface 50+ persistence locations in one pass — Run keys, "
        "RunOnce, Image File Execution Options, Services, Scheduled Tasks, "
        "Winlogon Userinit, AppInit_DLLs, etc."
    ),
    schema={
        "type": "object",
        "properties": {
            "hive_path": {
                "type": "string",
                "description": "Path to registry hive (NTUSER.DAT, SYSTEM, SOFTWARE, etc.)",
            },
            "batch_name": {
                "type": "string",
                "default": "ASEPs",
                "description": "One of: ASEPs (default), kroll, USB, All",
            },
            "limit": {"type": "integer", "default": 5000},
        },
        "required": ["hive_path"],
    },
)
def sift_recmd_run_batch(
    hive_path: str,
    batch_name: str = "ASEPs",
    limit: int = 5000,
) -> dict[str, Any]:
    sample = safe_evidence_input(hive_path)
    sample_sha = _sha256(sample) if sample.is_file() else None
    batch_file = _KNOWN_BATCHES.get(batch_name, _KNOWN_BATCHES["ASEPs"])

    with _tempdir(prefix="dart-recmd-") as workdir:
        out_csv = workdir / "recmd.csv"
        cmd = [
            _recmd_bin(),
            "-f", str(sample),
            "--bn", batch_file,
            "--csv", str(workdir),
            "--csvf", "recmd.csv",
            "--nl",  # no logo (suppress banner)
        ]
        result = run_tool(cmd, timeout=RECMD_TIMEOUT_SECONDS,
                          capture_files=[out_csv])

        rows: list[dict[str, Any]] = []
        if out_csv.is_file():
            with out_csv.open("r", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for i, r in enumerate(reader):
                    if i >= limit:
                        break
                    rows.append(dict(r))

    return {
        "registry_findings": rows,
        "metadata": {
            "tool": "recmd",
            "hive_path": hive_path,
            "hive_sha256": sample_sha,
            "batch_name": batch_name,
            "batch_file": batch_file,
            "rows_returned": len(rows),
            "duration_ms": result.duration_ms,
        },
    }


@tool(
    name="sift_recmd_query_key",
    description=(
        "Query a specific registry key path inside a hive. Returns all values "
        "and subkeys. Use for targeted lookups (e.g. 'what's in Run? what's "
        "the latest USBSTOR connection?')."
    ),
    schema={
        "type": "object",
        "properties": {
            "hive_path": {"type": "string"},
            "key_path": {
                "type": "string",
                "description": "Registry key path (e.g. 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')",
            },
        },
        "required": ["hive_path", "key_path"],
    },
)
def sift_recmd_query_key(hive_path: str, key_path: str) -> dict[str, Any]:
    sample = safe_evidence_input(hive_path)
    sample_sha = _sha256(sample) if sample.is_file() else None

    cmd = [
        _recmd_bin(),
        "-f", str(sample),
        "--kn", key_path,
        "--nl",
    ]
    result = run_tool(cmd, timeout=RECMD_TIMEOUT_SECONDS)

    return {
        "raw_output": result.stdout,
        "metadata": {
            "tool": "recmd",
            "hive_path": hive_path,
            "hive_sha256": sample_sha,
            "key_path": key_path,
            "duration_ms": result.duration_ms,
        },
    }
