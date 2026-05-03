"""
sift_adapters.amcacheparser — Eric Zimmerman AmcacheParser wrapper.

AmcacheParser parses Amcache.hve, the Windows registry hive that records
metadata about every executable run on the system. Probably the single most
underrated execution-evidence artifact on Windows.

Tool: AmcacheParser (.NET 6 cross-platform)
Source: https://github.com/EricZimmerman/AmcacheParser
On SIFT: bundled in /opt/EricZimmermanTools/

What we expose:
    sift_amcacheparser_parse  Full Amcache parse (with file SHA-1 hashes!)
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

AMCACHE_TIMEOUT_SECONDS = 600  # 10 min — Amcache.hve is small


def _amcache_bin() -> str:
    return _which("AmcacheParser", env_var="DART_AMCACHEPARSER_BIN")


@tool(
    name="sift_amcacheparser_parse",
    description=(
        "Parse Amcache.hve via Eric Zimmerman's AmcacheParser. Amcache "
        "records metadata for every executable run on the host, including "
        "the file's SHA-1 hash. This is one of the highest-value DFIR "
        "artifacts: it survives file deletion and lets you pivot on hashes "
        "to threat intel."
    ),
    schema={
        "type": "object",
        "properties": {
            "amcache_path": {
                "type": "string",
                "description": "Path to Amcache.hve (typically %SystemRoot%\\AppCompat\\Programs\\Amcache.hve)",
            },
            "include_associated_files": {
                "type": "boolean", "default": True,
                "description": "Include the AssociatedFiles companion CSV (if produced)",
            },
            "limit": {"type": "integer", "default": 10000},
        },
        "required": ["amcache_path"],
    },
)
def sift_amcacheparser_parse(
    amcache_path: str,
    include_associated_files: bool = True,
    limit: int = 10000,
) -> dict[str, Any]:
    sample = safe_evidence_input(amcache_path)
    sample_sha = _sha256(sample)

    with _tempdir(prefix="dart-amcache-") as workdir:
        cmd = [
            _amcache_bin(),
            "-f", str(sample),
            "-i",                       # include all entries (not just associated)
            "--csv", str(workdir),
        ]
        result = run_tool(cmd, timeout=AMCACHE_TIMEOUT_SECONDS)

        # AmcacheParser writes multiple CSVs with timestamped names. Glob.
        csv_files = list(workdir.glob("*.csv"))

        records: dict[str, list[dict[str, Any]]] = {}
        hashes: dict[str, str] = {}

        for csv_file in csv_files:
            csv_sha = _sha256(csv_file)
            hashes[csv_file.name] = csv_sha
            # Categorize by filename pattern
            stem = csv_file.stem.lower()
            category = (
                "unassociated_executables" if "unassociatedfileentries" in stem
                else "associated_files" if "associatedfileentries" in stem
                else "programs" if "programentries" in stem
                else "drivers" if "driver" in stem
                else "shortcuts" if "shortcut" in stem
                else "device_pnp" if "device" in stem
                else "other"
            )
            if not include_associated_files and category == "associated_files":
                continue

            with csv_file.open("r", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                rows = []
                for i, r in enumerate(reader):
                    if i >= limit:
                        break
                    rows.append(dict(r))
                records.setdefault(category, []).extend(rows)

    return {
        "amcache_records": records,
        "metadata": {
            "tool": "amcacheparser",
            "amcache_path": amcache_path,
            "amcache_sha256": sample_sha,
            "csv_outputs_sha256": hashes,
            "categories_returned": sorted(records.keys()),
            "total_rows": sum(len(v) for v in records.values()),
            "duration_ms": result.duration_ms,
        },
    }
