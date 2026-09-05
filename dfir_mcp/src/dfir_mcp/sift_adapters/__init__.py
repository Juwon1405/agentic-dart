"""
sift_adapters — SIFT Workstation tool adapters for agentic-dfir.

This subpackage adds typed, read-only MCP wrappers around the canonical
DFIR tools shipped on the SANS SIFT Workstation. Importing this package
registers all adapters with the parent dfir_mcp tool registry via the
@tool decorator, so they appear in list_tools() alongside the 48 native
agentic-dfir functions.

The adapters give the agent typed access to the SIFT Workstation's actual
tooling, while the architectural guardrails (dfir_audit hash chain,
dfir_corr contradiction handler, read-only EVIDENCE_ROOT sandbox) remain
in place.

Adapter list:
  - volatility3       12 plugins (Win/Linux/macOS pslist/pstree/psscan/etc.)
  - mftecmd           Eric Zimmerman MFT parser + timestomp detection
  - evtxecmd          Eric Zimmerman EVTX parser + EID filter
  - pecmd             Eric Zimmerman Prefetch parser + run history
  - recmd             Eric Zimmerman Registry parser (ASEPs batch)
  - amcacheparser     Eric Zimmerman Amcache parser (with file SHA-1)
  - yara              YARA single-file + recursive directory scan
  - plaso             log2timeline + psort super-timeline

All wrappers:
  - inherit dfir_mcp's EVIDENCE_ROOT sandbox + path-traversal guard
  - require explicit binary resolution (env var override or PATH)
  - subprocess timeouts to prevent agent loop freeze
  - SHA-256 hashes of every input + output for audit chain compatibility
  - parse stdout/CSV into structured rows (no raw shell to LLM)
  - graceful SiftToolNotFoundError when a tool isn't installed
"""
from __future__ import annotations

# Importing each adapter module triggers @tool decorator registration
# in the parent dfir_mcp registry. Order doesn't matter; all live in the
# same _REGISTRY dict.
from . import volatility3      # noqa: F401 — side-effect: registers @tool adapters
from . import mftecmd          # noqa: F401
from . import evtxecmd         # noqa: F401
from . import pecmd            # noqa: F401
from . import recmd            # noqa: F401
from . import amcacheparser    # noqa: F401
from . import yara             # noqa: F401
from . import plaso            # noqa: F401

from ._common import (
    SiftToolFailedError,
    SiftToolNotFoundError,
)


__all__ = [
    "SiftToolFailedError",
    "SiftToolNotFoundError",
]
