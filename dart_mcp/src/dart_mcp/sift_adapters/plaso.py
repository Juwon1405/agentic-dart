"""
sift_adapters.plaso — Plaso (log2timeline + psort) wrapper.

Plaso is the heavyweight super-timeline tool. It extracts events from
hundreds of artifact types into a single timeline, then `psort` filters
and renders. On the SIFT Workstation, log2timeline.py is the canonical
super-timeline generator.

Tool: log2timeline.py + psort.py (Python — Plaso project)
Source: https://github.com/log2timeline/plaso
On SIFT: pre-installed

What we expose:
    sift_plaso_log2timeline   Extract a Plaso storage file from evidence
    sift_plaso_psort          Filter + render an existing Plaso storage to L2T CSV

Note: Plaso runs are typically multi-hour on real disks. Default timeouts
are generous. Most cases want to run log2timeline once on disk image,
cache the .plaso storage, then run psort multiple times to slice.
"""
from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path
from typing import Any

from dart_mcp import tool

from ._common import (
    PathTraversalAttempt,
    _sha256,
    _tempdir,
    _which,
    run_tool,
    safe_evidence_input,
)

# log2timeline can take many hours on a real disk image. Conservative default.
LOG2TIMELINE_TIMEOUT_SECONDS = 6 * 60 * 60   # 6 hours
PSORT_TIMEOUT_SECONDS = 1 * 60 * 60          # 1 hour
DERIVED_ROOT_ENV = "DART_DERIVED_ROOT"


def _log2timeline_bin() -> str:
    return _which("log2timeline.py", env_var="DART_LOG2TIMELINE_BIN")


def _psort_bin() -> str:
    return _which("psort.py", env_var="DART_PSORT_BIN")


def _derived_root() -> Path:
    root = os.environ.get(DERIVED_ROOT_ENV)
    if root:
        return Path(root).expanduser().resolve()
    return (Path(tempfile.gettempdir()) / "agentic-dart-derived").resolve()


def _safe_derived_path(path_str: str, *, must_exist: bool = False) -> Path:
    """Resolve a Plaso storage path under DART_DERIVED_ROOT.

    Plaso is the one adapter family that needs a persistent derived artifact
    for later psort slicing. Derived artifacts must never be written back into
    EVIDENCE_ROOT, so this helper constrains them to a separate root.
    """
    if not isinstance(path_str, str) or not path_str:
        raise PathTraversalAttempt(f"invalid derived path: {path_str!r}")
    if "\x00" in path_str:
        raise PathTraversalAttempt("null byte in derived path")

    root = _derived_root()
    raw = Path(path_str).expanduser()
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        norm = path_str.replace("\\", "/")
        parts = [p for p in norm.split("/") if p]
        if not parts or any(p in (".", "..") for p in parts):
            raise PathTraversalAttempt(f"invalid derived path: {path_str!r}")
        candidate = (root / Path(*parts)).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as e:
        raise PathTraversalAttempt(
            f"derived path escapes {DERIVED_ROOT_ENV}: {path_str!r}"
        ) from e
    if must_exist and not candidate.exists():
        raise PathTraversalAttempt(f"derived path does not exist: {path_str!r}")
    return candidate


def _resolve_storage_input(storage_path: str) -> Path:
    try:
        return safe_evidence_input(storage_path)
    except PathTraversalAttempt:
        return _safe_derived_path(storage_path, must_exist=True)


@tool(
    name="sift_plaso_log2timeline",
    description=(
        "Run log2timeline against an evidence source (disk image, mount "
        "point, or single artifact). Produces a .plaso storage file. "
        "WARNING: this can take HOURS on a full disk image. Use a "
        "specific parser via 'parsers' to scope down (e.g. 'mft,evtx,prefetch')."
    ),
    schema={
        "type": "object",
        "properties": {
            "source_path": {
                "type": "string",
                "description": "Disk image / mount / artifact path",
            },
            "output_storage_path": {
                "type": "string",
                "description": "Relative or absolute path under DART_DERIVED_ROOT for the .plaso file",
            },
            "parsers": {
                "type": "string",
                "description": "Comma-separated parser preset (e.g. 'mft,evtx,prefetch'). Empty = all.",
            },
            "timeout_seconds": {
                "type": "integer",
                "default": LOG2TIMELINE_TIMEOUT_SECONDS,
            },
        },
        "required": ["source_path", "output_storage_path"],
    },
)
def sift_plaso_log2timeline(
    source_path: str,
    output_storage_path: str,
    parsers: str = "",
    timeout_seconds: int = LOG2TIMELINE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    source = safe_evidence_input(source_path)
    out_path = _safe_derived_path(output_storage_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        raise FileExistsError(
            f"derived storage already exists: {out_path}; choose a new output_storage_path"
        )

    cmd = [
        _log2timeline_bin(),
        "--storage_file", str(out_path),
    ]
    if parsers:
        cmd.extend(["--parsers", parsers])
    cmd.append(str(source))

    result = run_tool(cmd, timeout=timeout_seconds,
                      capture_files=[out_path])

    return {
        "metadata": {
            "tool": "plaso/log2timeline",
            "source_path": source_path,
            "source_sha256": _sha256(source) if source.is_file() else None,
            "output_storage_path": str(out_path),
            "derived_root": str(_derived_root()),
            "storage_sha256": result.output_files.get(str(out_path)),
            "parsers": parsers,
            "duration_ms": result.duration_ms,
            "stderr_tail": result.stderr[-500:],
        },
    }


@tool(
    name="sift_plaso_psort",
    description=(
        "Filter and render a .plaso storage file via psort. Default output "
        "is L2T CSV format. Optionally filter by date range or event type."
    ),
    schema={
        "type": "object",
        "properties": {
            "storage_path": {
                "type": "string",
                "description": "Path to .plaso storage file",
            },
            "output_format": {
                "type": "string", "default": "l2tcsv",
                "description": "Output format (l2tcsv, json_line, dynamic)",
            },
            "filter_expression": {
                "type": "string",
                "description": "psort filter expression (e.g. 'date > \"2026-04-22\"')",
            },
            "limit": {"type": "integer", "default": 10000},
        },
        "required": ["storage_path"],
    },
)
def sift_plaso_psort(
    storage_path: str,
    output_format: str = "l2tcsv",
    filter_expression: str = "",
    limit: int = 10000,
) -> dict[str, Any]:
    storage = _resolve_storage_input(storage_path)
    storage_sha = _sha256(storage)

    with _tempdir(prefix="dart-psort-") as workdir:
        out_file = workdir / f"timeline.{output_format}"
        cmd = [
            _psort_bin(),
            "-o", output_format,
            "-w", str(out_file),
            str(storage),
        ]
        if filter_expression:
            cmd.append(filter_expression)

        result = run_tool(cmd, timeout=PSORT_TIMEOUT_SECONDS,
                          capture_files=[out_file])

        rows: list[dict[str, Any]] = []
        if out_file.is_file() and output_format == "l2tcsv":
            with out_file.open("r", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for i, r in enumerate(reader):
                    if i >= limit:
                        break
                    rows.append(dict(r))

    return {
        "events": rows,
        "metadata": {
            "tool": "plaso/psort",
            "storage_path": storage_path,
            "storage_sha256": storage_sha,
            "output_format": output_format,
            "filter_expression": filter_expression,
            "rows_returned": len(rows),
            "duration_ms": result.duration_ms,
        },
    }
