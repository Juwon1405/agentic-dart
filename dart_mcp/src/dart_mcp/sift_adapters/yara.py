"""
sift_adapters.yara — YARA scanner wrapper.

YARA is the signature/IoC matching engine used by virtually every malware
analysis tool and DFIR-grade rule corpus (DFIR Report, Mandiant, ESET, etc.).

Tool: yara (C binary)
Source: https://github.com/VirusTotal/yara
On SIFT: pre-installed at /usr/bin/yara

What we expose:
    sift_yara_scan_file      Scan a single file
    sift_yara_scan_dir       Recursively scan a directory
"""
from __future__ import annotations

import re
from typing import Any

from dart_mcp import tool

from ._common import (
    _sha256,
    _which,
    run_tool,
    safe_evidence_input,
)

YARA_TIMEOUT_SECONDS = 1800  # 30 min — large directory scans


def _yara_bin() -> str:
    return _which("yara", env_var="DART_YARA_BIN")


# Format: <rulename> <filepath>  (default YARA output)
_YARA_OUTPUT_RE = re.compile(r"^(?P<rule>[^\s]+)\s+(?P<path>.+)$")


def _parse_yara_output(stdout: str) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("warning:") or line.startswith("error:"):
            continue
        m = _YARA_OUTPUT_RE.match(line)
        if m:
            matches.append({"rule": m.group("rule"), "path": m.group("path")})
    return matches


@tool(
    name="sift_yara_scan_file",
    description=(
        "Scan a single file with YARA rules. Returns a list of matched rule "
        "names. Pair with rule corpora like DFIR Report's Yara-Rules, "
        "Florian Roth's signature-base, or Mandiant's capa-rules."
    ),
    schema={
        "type": "object",
        "properties": {
            "rules_path": {
                "type": "string",
                "description": "Path to .yar / .yara rules file (or compiled rules)",
            },
            "target_path": {
                "type": "string",
                "description": "Path to the file to scan",
            },
            "fast_mode": {
                "type": "boolean", "default": True,
                "description": "Stop matching once first match found (-f)",
            },
        },
        "required": ["rules_path", "target_path"],
    },
)
def sift_yara_scan_file(
    rules_path: str,
    target_path: str,
    fast_mode: bool = True,
) -> dict[str, Any]:
    rules = safe_evidence_input(rules_path)
    target = safe_evidence_input(target_path)

    cmd = [_yara_bin()]
    if fast_mode:
        cmd.append("-f")
    cmd.extend([str(rules), str(target)])

    try:
        result = run_tool(cmd, timeout=YARA_TIMEOUT_SECONDS)
        matches = _parse_yara_output(result.stdout)
        duration_ms = result.duration_ms
    except Exception as e:
        # YARA returns non-zero on syntax errors etc. Catch and report.
        return {
            "matches": [],
            "metadata": {
                "tool": "yara",
                "error": str(e),
                "rules_path": rules_path,
                "target_path": target_path,
            },
        }

    return {
        "matches": matches,
        "metadata": {
            "tool": "yara",
            "rules_path": rules_path,
            "target_path": target_path,
            "target_sha256": _sha256(target) if target.is_file() else None,
            "match_count": len(matches),
            "duration_ms": duration_ms,
        },
    }


@tool(
    name="sift_yara_scan_dir",
    description=(
        "Recursively scan a directory tree with YARA rules. Returns "
        "{rule, path} for every match. Useful for sweeping a mounted "
        "evidence partition for known malware / IOC patterns."
    ),
    schema={
        "type": "object",
        "properties": {
            "rules_path": {"type": "string"},
            "target_dir": {"type": "string"},
            "fast_mode": {"type": "boolean", "default": True},
            "max_file_size": {
                "type": "integer", "default": 50 * 1024 * 1024,
                "description": "Skip files larger than this (bytes; default 50MB)",
            },
        },
        "required": ["rules_path", "target_dir"],
    },
)
def sift_yara_scan_dir(
    rules_path: str,
    target_dir: str,
    fast_mode: bool = True,
    max_file_size: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    rules = safe_evidence_input(rules_path)
    target = safe_evidence_input(target_dir)

    cmd = [_yara_bin(), "-r"]   # recursive
    if fast_mode:
        cmd.append("-f")
    if max_file_size > 0:
        # YARA uses --max-file-size=BYTES on supported builds; -z is alias
        cmd.extend(["--max-file-size", str(max_file_size)])
    cmd.extend([str(rules), str(target)])

    try:
        result = run_tool(cmd, timeout=YARA_TIMEOUT_SECONDS)
        matches = _parse_yara_output(result.stdout)
        duration_ms = result.duration_ms
    except Exception as e:
        return {
            "matches": [],
            "metadata": {
                "tool": "yara",
                "error": str(e),
                "rules_path": rules_path,
                "target_dir": target_dir,
            },
        }

    return {
        "matches": matches,
        "metadata": {
            "tool": "yara",
            "rules_path": rules_path,
            "target_dir": target_dir,
            "match_count": len(matches),
            "duration_ms": duration_ms,
        },
    }
