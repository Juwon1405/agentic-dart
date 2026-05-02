"""
sift_adapters._common — Shared subprocess + safety helpers for SIFT tool wrappers.

Design principles (must hold for every adapter in this package):

  1. READ-ONLY ENFORCEMENT
       Every wrapper accepts evidence paths as input but writes *only* to a
       per-call temporary directory. The agent has no path to write back to
       evidence. The MCP boundary blocks rm/dd/shred/mv/cp/wget/curl/ssh.

  2. AUDIT-CHAIN COMPATIBILITY
       Every wrapper returns the SHA-256 of its primary input file so
       dart_audit can chain it into the case ledger. Any output artifact
       (e.g. CSV from MFTECmd) is *also* hashed before parsing.

  3. TIMEOUT BY DEFAULT
       Subprocess calls are timeout-bounded. A hung Volatility plugin or
       runaway log2timeline run cannot freeze the agent loop.

  4. STRUCTURED OUTPUT
       Wrappers parse the tool's stdout/CSV/JSON into a plain Python dict
       before returning. The LLM never sees raw shell output (which would
       be a prompt-injection vector when filenames contain attacker text).

  5. GRACEFUL DEGRADATION
       When the SIFT tool is not installed, the wrapper raises
       SiftToolNotFoundError with the install command. The agent can
       fall back to dart_mcp's native pure-Python implementation.

The set of tools this module exposes IS part of the agent's attack surface.
Adding new ones requires:
  - read-only verification
  - timeout default
  - SHA-256 of inputs and outputs
  - error path that does not leak filesystem layout
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

# Re-use the parent package's evidence root so SIFT adapters share the same
# sandbox boundary as native dart-mcp tools.
from dart_mcp import EVIDENCE_ROOT, PathTraversalAttempt, _safe_resolve, _sha256

# Default subprocess timeout (seconds). Individual adapters may override.
DEFAULT_TIMEOUT_SECONDS = 600  # 10 minutes — generous for a single Volatility plugin


class SiftToolNotFoundError(RuntimeError):
    """Raised when a SIFT tool binary is not on PATH (or not at the configured path)."""


class SiftToolFailedError(RuntimeError):
    """Raised when a SIFT tool returned a non-zero exit code or hit a timeout."""


@dataclass
class SubprocessResult:
    """Structured result of a subprocess invocation."""
    stdout: str
    stderr: str
    returncode: int
    duration_ms: int
    output_files: dict[str, str]  # name -> sha256 hash


def _which(binary: str, env_var: str | None = None) -> str:
    """
    Resolve a SIFT tool binary.

    Resolution order:
        1. Environment variable override (e.g. DART_VOLATILITY3_BIN=/opt/vol)
        2. shutil.which() lookup on PATH
        3. raise SiftToolNotFoundError

    This indirection lets users override paths when SIFT tools live outside
    PATH (e.g. virtualenv, custom install location).
    """
    if env_var:
        override = os.environ.get(env_var)
        if override:
            override_path = Path(override)
            if override_path.is_file() and os.access(override_path, os.X_OK):
                return str(override_path)
            raise SiftToolNotFoundError(
                f"{env_var}={override!r} is set but not an executable file"
            )
    found = shutil.which(binary)
    if found:
        return found
    raise SiftToolNotFoundError(
        f"SIFT tool {binary!r} not found on PATH. "
        f"Set {env_var or 'a tool-specific env var'} to its absolute path "
        f"or install on the SIFT Workstation."
    )


@contextmanager
def _tempdir(prefix: str = "dart-sift-") -> Iterator[Path]:
    """Create + clean up a per-call temporary working directory."""
    d = tempfile.mkdtemp(prefix=prefix)
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run_tool(
    cmd: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | Path | None = None,
    capture_files: Sequence[str | Path] | None = None,
) -> SubprocessResult:
    """
    Run a SIFT tool subprocess with timeout + audit logging.

    Args:
        cmd: Command list (NOT a string — no shell interpolation).
        timeout: Hard kill after this many seconds.
        cwd: Working directory. Defaults to None (process cwd).
        capture_files: Output files to SHA-256 after the command runs.

    Returns:
        SubprocessResult with stdout/stderr/returncode/duration + output hashes.

    Raises:
        SiftToolFailedError: non-zero exit or timeout.
    """
    import time
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise SiftToolFailedError(
            f"SIFT tool timed out after {timeout}s: {cmd[0]}"
        ) from e
    except FileNotFoundError as e:
        raise SiftToolNotFoundError(f"binary not found: {cmd[0]}") from e

    duration_ms = int((time.monotonic() - start) * 1000)

    output_files: dict[str, str] = {}
    if capture_files:
        for f in capture_files:
            p = Path(f)
            if p.is_file():
                output_files[str(p)] = _sha256(p)

    if proc.returncode != 0:
        raise SiftToolFailedError(
            f"{cmd[0]} exited with code {proc.returncode}: "
            f"{proc.stderr[:200] if proc.stderr else '(no stderr)'}"
        )

    return SubprocessResult(
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
        duration_ms=duration_ms,
        output_files=output_files,
    )


def safe_evidence_input(path_str: str) -> Path:
    """
    Resolve an evidence path under EVIDENCE_ROOT, with read-access verification.

    All SIFT adapters MUST pass user-supplied paths through this function
    before invoking subprocess. This is the boundary that makes path
    traversal structurally impossible.
    """
    p = _safe_resolve(path_str)
    if not p.exists():
        raise PathTraversalAttempt(f"evidence path does not exist: {path_str!r}")
    return p


def jsonify(obj) -> str:
    """Serialize for stdout / audit log. Handles bytes + datetime gracefully."""
    return json.dumps(obj, default=str, separators=(",", ":"), ensure_ascii=False)


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "EVIDENCE_ROOT",
    "PathTraversalAttempt",
    "SiftToolFailedError",
    "SiftToolNotFoundError",
    "SubprocessResult",
    "_sha256",
    "_tempdir",
    "_which",
    "jsonify",
    "run_tool",
    "safe_evidence_input",
]
