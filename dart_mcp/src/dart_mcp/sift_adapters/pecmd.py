"""
sift_adapters.pecmd — Eric Zimmerman PECmd wrapper.

PECmd parses Windows Prefetch files (.pf) into structured CSV. Prefetch is
one of the most reliable artifacts of program execution on Windows.

Tool: PECmd (.NET 6 cross-platform)
Source: https://github.com/EricZimmerman/PECmd
On SIFT: bundled in /opt/EricZimmermanTools/

What we expose:
    sift_pecmd_parse           Parse Prefetch directory or single .pf file
    sift_pecmd_run_history     Convenience: extract last-N-runs per executable
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

PECMD_TIMEOUT_SECONDS = 600  # 10 min — Prefetch is small


def _pecmd_bin() -> str:
    return _which("PECmd", env_var="DART_PECMD_BIN")


def _run_pecmd(prefetch_path: str) -> dict[str, Any]:
    sample = safe_evidence_input(prefetch_path)
    sample_sha = _sha256(sample) if sample.is_file() else None

    with _tempdir(prefix="dart-pecmd-") as workdir:
        out_csv = workdir / "prefetch.csv"
        flag = "-d" if sample.is_dir() else "-f"
        cmd = [
            _pecmd_bin(),
            flag, str(sample),
            "--csv", str(workdir),
            "--csvf", "prefetch.csv",
        ]
        result = run_tool(cmd, timeout=PECMD_TIMEOUT_SECONDS,
                          capture_files=[out_csv])

        if not out_csv.is_file():
            return {
                "rows": [],
                "stderr_tail": result.stderr[-500:],
                "duration_ms": result.duration_ms,
                "csv_sha256": None,
                "input_sha256": sample_sha,
            }

        rows: list[dict[str, Any]] = []
        with out_csv.open("r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            rows = [dict(r) for r in reader]

        return {
            "rows": rows,
            "duration_ms": result.duration_ms,
            "csv_sha256": result.output_files.get(str(out_csv)),
            "input_sha256": sample_sha,
        }


@tool(
    name="sift_pecmd_parse",
    description=(
        "Parse Windows Prefetch (.pf) files via Eric Zimmerman's PECmd. "
        "Accepts a single .pf or a Prefetch directory. Returns rows with "
        "ExecutableName, RunCount, LastRun, PreviousRun0..6, FilesLoaded."
    ),
    schema={
        "type": "object",
        "properties": {
            "prefetch_path": {
                "type": "string",
                "description": "Path to .pf file or %SystemRoot%\\Prefetch directory",
            },
            "limit": {"type": "integer", "default": 5000},
        },
        "required": ["prefetch_path"],
    },
)
def sift_pecmd_parse(prefetch_path: str, limit: int = 5000) -> dict[str, Any]:
    parsed = _run_pecmd(prefetch_path)
    rows = parsed["rows"][:limit]
    return {
        "prefetch_records": rows,
        "metadata": {
            "tool": "pecmd",
            "prefetch_path": prefetch_path,
            "input_sha256": parsed.get("input_sha256"),
            "csv_sha256": parsed.get("csv_sha256"),
            "rows_returned": len(rows),
            "rows_total": len(parsed["rows"]),
            "duration_ms": parsed["duration_ms"],
        },
    }


@tool(
    name="sift_pecmd_run_history",
    description=(
        "Extract per-executable run history from a Prefetch directory. "
        "Returns name + RunCount + last-8-runs for each prefetched binary, "
        "sorted by RunCount descending. Useful for surfacing 'this binary "
        "ran 47 times in 2 hours' anomalies."
    ),
    schema={
        "type": "object",
        "properties": {
            "prefetch_path": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
        "required": ["prefetch_path"],
    },
)
def sift_pecmd_run_history(prefetch_path: str, limit: int = 200) -> dict[str, Any]:
    parsed = _run_pecmd(prefetch_path)
    history = []
    for row in parsed["rows"]:
        runs = []
        for k in ("LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2",
                  "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6"):
            v = row.get(k, "").strip()
            if v:
                runs.append(v)
        history.append({
            "executable": row.get("ExecutableName", ""),
            "run_count": int(row.get("RunCount", 0) or 0),
            "runs": runs,
            "size_bytes": row.get("Size", ""),
            "hash": row.get("Hash", ""),
        })
    history.sort(key=lambda h: -h["run_count"])
    history = history[:limit]

    return {
        "run_history": history,
        "metadata": {
            "tool": "pecmd",
            "prefetch_path": prefetch_path,
            "rows_returned": len(history),
            "duration_ms": parsed["duration_ms"],
        },
    }
