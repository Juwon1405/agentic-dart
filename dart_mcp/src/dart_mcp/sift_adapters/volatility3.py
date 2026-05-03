"""
sift_adapters.volatility3 — Volatility 3 wrapper for memory forensics.

Wraps Volatility 3 v2.27+ (the version on the current SIFT Workstation) plugins.
The agent gets typed access to the 12 highest-yield plugins for IR triage,
spanning Windows / Linux / macOS dumps.

Plugin coverage (matches the memory-forensics-vol3 cheatsheet):

  Windows:
    sift_vol3_windows_pslist        windows.pslist.PsList
    sift_vol3_windows_pstree        windows.pstree.PsTree
    sift_vol3_windows_psscan        windows.psscan.PsScan       (hidden process hunt)
    sift_vol3_windows_cmdline       windows.cmdline.CmdLine
    sift_vol3_windows_netscan       windows.netscan.NetScan
    sift_vol3_windows_malfind       windows.malfind.Malfind     (RWX injected code)
    sift_vol3_windows_dlllist       windows.dlllist.DllList
    sift_vol3_windows_svcscan       windows.svcscan.SvcScan
    sift_vol3_windows_runkey        windows.registry.printkey.PrintKey
                                     on Software\\Microsoft\\Windows\\CurrentVersion\\Run

  Linux:
    sift_vol3_linux_bash            linux.bash.Bash             (in-memory bash history)
    sift_vol3_linux_pslist          linux.pslist.PsList

  macOS:
    sift_vol3_mac_bash              mac.bash.Bash               (in-memory bash history)

Resolution:
    DART_VOLATILITY3_BIN env var -> shutil.which('vol') -> SiftToolNotFoundError

All output is parsed from Volatility's CSV/JSON renderer into a list of dicts.
The LLM never sees raw column-aligned text (which is hard to disambiguate
when filenames contain spaces).
"""
from __future__ import annotations

import csv
import io
from typing import Any

from dart_mcp import tool

from ._common import (
    SubprocessResult,
    _sha256,
    _which,
    run_tool,
    safe_evidence_input,
)

VOL_TIMEOUT_SECONDS = 1200  # 20 min — heavy plugins like pslist on big dumps


def _vol_bin() -> str:
    """Resolve the volatility3 binary."""
    return _which("vol", env_var="DART_VOLATILITY3_BIN")


def _run_vol_plugin(
    image_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
    timeout: int = VOL_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Execute one Volatility 3 plugin and return (rows, metadata).

    Volatility 3's --renderer=csv format is reliable for parsing.
    """
    sample = safe_evidence_input(image_path)
    sample_sha = _sha256(sample)

    cmd = [
        _vol_bin(),
        "-q",                       # quiet — suppress progress on stderr
        "-r", "csv",                # CSV renderer
        "-f", str(sample),
        plugin,
    ]
    if extra_args:
        cmd.extend(extra_args)

    result: SubprocessResult = run_tool(cmd, timeout=timeout)

    # Parse CSV output. Vol3 emits a single header row + data rows.
    rows: list[dict[str, Any]] = []
    if result.stdout.strip():
        try:
            reader = csv.DictReader(io.StringIO(result.stdout))
            rows = [dict(r) for r in reader]
        except csv.Error:
            # Some plugins (e.g., bash history) emit non-CSV — keep raw lines
            rows = [{"line": line} for line in result.stdout.splitlines() if line.strip()]

    metadata = {
        "plugin": plugin,
        "image_path": image_path,
        "image_sha256": sample_sha,
        "row_count": len(rows),
        "duration_ms": result.duration_ms,
        "tool": "volatility3",
    }
    return rows, metadata


# ============================================================
#  Windows plugins
# ============================================================

@tool(
    name="sift_vol3_windows_pslist",
    description=(
        "List active processes from a Windows memory image (Volatility 3 "
        "windows.pslist.PsList plugin). Returns PID, PPID, ImageFileName, "
        "Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime."
    ),
    schema={
        "type": "object",
        "properties": {
            "image_path": {"type": "string", "description": "Path to .raw / .vmem / .dmp memory image"},
        },
        "required": ["image_path"],
    },
)
def sift_vol3_windows_pslist(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.pslist.PsList")
    return {"processes": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_pstree",
    description=(
        "Process tree (parent → child) from Windows memory image. Use this "
        "before pslist if you suspect injection / unusual parent chains "
        "(e.g. cmd.exe parented by WINWORD.EXE)."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_pstree(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.pstree.PsTree")
    return {"process_tree": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_psscan",
    description=(
        "Pool-tag scan for hidden processes (DKOM / unlinked _EPROCESS). "
        "Diff against pslist — anything in psscan but NOT pslist is "
        "high-confidence rootkit signal."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_psscan(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.psscan.PsScan")
    return {"processes": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_cmdline",
    description=(
        "Per-process command line. Critical for surfacing -EncodedCommand "
        "PowerShell, comsvcs.dll MiniDump (LSASS), and other LotL signatures."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_cmdline(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.cmdline.CmdLine")
    return {"command_lines": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_netscan",
    description=(
        "Active TCP/UDP connections, sockets, listeners. Cross-reference "
        "ForeignAddr with threat intel for C2 / exfil detection."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_netscan(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.netscan.NetScan")
    return {"connections": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_malfind",
    description=(
        "Find RWX (read+write+execute) memory regions — process injection / "
        "reflective DLL signal. Each finding includes hex dump start. Look "
        "for MZ headers in injected regions."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_malfind(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.malfind.Malfind")
    return {"injected_regions": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_dlllist",
    description=(
        "Loaded DLLs per process. Filter by --pid for a specific process. "
        "Suspicious: DLLs in %TEMP%, %APPDATA%, or unsigned in system processes."
    ),
    schema={
        "type": "object",
        "properties": {
            "image_path": {"type": "string"},
            "pid": {"type": "integer", "description": "Filter to specific PID"},
        },
        "required": ["image_path"],
    },
)
def sift_vol3_windows_dlllist(image_path: str, pid: int | None = None) -> dict[str, Any]:
    extra = ["--pid", str(pid)] if pid is not None else None
    rows, meta = _run_vol_plugin(image_path, "windows.dlllist.DllList", extra)
    return {"dlls": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_svcscan",
    description=(
        "Windows services in memory. Persistence + lateral movement signal. "
        "Look for random 8-char service names (PsExec) or paths in non-standard locations."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_windows_svcscan(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "windows.svcscan.SvcScan")
    return {"services": rows, "metadata": meta}


@tool(
    name="sift_vol3_windows_runkey",
    description=(
        "Read the Run / RunOnce registry keys from memory hives. Persistence "
        "via Software\\Microsoft\\Windows\\CurrentVersion\\Run is one of the "
        "top 5 Windows persistence mechanisms."
    ),
    schema={
        "type": "object",
        "properties": {
            "image_path": {"type": "string"},
            "key": {
                "type": "string",
                "default": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "description": "Registry key path",
            },
        },
        "required": ["image_path"],
    },
)
def sift_vol3_windows_runkey(
    image_path: str,
    key: str = r"Software\Microsoft\Windows\CurrentVersion\Run",
) -> dict[str, Any]:
    extra = ["--key", key]
    rows, meta = _run_vol_plugin(
        image_path, "windows.registry.printkey.PrintKey", extra
    )
    meta["registry_key"] = key
    return {"registry_values": rows, "metadata": meta}


# ============================================================
#  Linux plugins
# ============================================================

@tool(
    name="sift_vol3_linux_pslist",
    description="List active Linux processes from a memory image.",
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_linux_pslist(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "linux.pslist.PsList")
    return {"processes": rows, "metadata": meta}


@tool(
    name="sift_vol3_linux_bash",
    description=(
        "Recover bash history from a Linux memory image. Catches attackers "
        "who deleted ~/.bash_history — the in-memory copy survives."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_linux_bash(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "linux.bash.Bash")
    return {"bash_history": rows, "metadata": meta}


# ============================================================
#  macOS plugins
# ============================================================

@tool(
    name="sift_vol3_mac_bash",
    description=(
        "Recover bash history from a macOS memory image. Same in-memory "
        "recovery technique as Linux — catches deleted ~/.bash_history."
    ),
    schema={
        "type": "object",
        "properties": {"image_path": {"type": "string"}},
        "required": ["image_path"],
    },
)
def sift_vol3_mac_bash(image_path: str) -> dict[str, Any]:
    rows, meta = _run_vol_plugin(image_path, "mac.bash.Bash")
    return {"bash_history": rows, "metadata": meta}
