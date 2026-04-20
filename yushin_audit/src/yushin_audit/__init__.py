"""
yushin-audit — Append-only JSONL logger with SHA-256 hash chain.

Every MCP call is recorded as one line. Each line contains the SHA-256
of the previous line, forming a tamper-evident chain. The agent cannot
rewrite history because the file is opened O_APPEND and the chain is
verified at finalization.

This is the audit layer that makes every finding traceable.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any


GENESIS_PREV_HASH = "0" * 64  # SHA-256 of "nothing"


@dataclass
class AuditEntry:
    ts: str
    iteration: int
    tool_name: str
    inputs: dict
    output_digest: str              # SHA-256 of full tool output (not the output itself)
    token_count_in: int
    token_count_out: int
    finding_ids: list = field(default_factory=list)
    audit_id: str = ""              # 8-char random hex; filled in by logger
    prev_hash: str = GENESIS_PREV_HASH
    entry_hash: str = ""            # SHA-256 of (prev_hash + canonical body); filled in by logger

    def canonical_body(self) -> str:
        """Everything except entry_hash, in canonical JSON form."""
        body = {k: v for k, v in asdict(self).items() if k != "entry_hash"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"))


class AuditLogger:
    """Append-only writer. One instance per run."""

    def __init__(self, path: str | Path, run_id: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or secrets.token_hex(8)
        self._prev_hash = self._load_tail_hash()

    def _load_tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_PREV_HASH
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk = 4096
            f.seek(max(0, size - chunk))
            tail = f.read().splitlines()
        if not tail:
            return GENESIS_PREV_HASH
        return json.loads(tail[-1])["entry_hash"]

    def log(
        self,
        tool_name: str,
        inputs: dict,
        output: Any,
        iteration: int,
        token_count_in: int,
        token_count_out: int,
        finding_ids: list | None = None,
    ) -> str:
        """Record one MCP call. Returns audit_id."""
        # Hash the output (not the output itself — audit log must stay small)
        output_bytes = json.dumps(output, sort_keys=True, default=str).encode()
        output_digest = "sha256:" + hashlib.sha256(output_bytes).hexdigest()

        entry = AuditEntry(
            ts=time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{int(time.time()*1000)%1000:03d}Z",
            iteration=iteration,
            tool_name=tool_name,
            inputs=inputs,
            output_digest=output_digest,
            token_count_in=token_count_in,
            token_count_out=token_count_out,
            finding_ids=finding_ids or [],
            audit_id=secrets.token_hex(4),
            prev_hash=self._prev_hash,
        )
        # Chain: hash(prev_hash || canonical_body)
        entry.entry_hash = hashlib.sha256(entry.canonical_body().encode()).hexdigest()

        # Append atomically with O_APPEND semantics
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._prev_hash = entry.entry_hash
        return entry.audit_id

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, str]:
        """Walk the chain end-to-end. Returns (ok, message)."""
        p = Path(path)
        if not p.exists():
            return False, f"audit log not found: {p}"

        prev = GENESIS_PREV_HASH
        n = 0
        with p.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                obj = json.loads(raw)
                if obj["prev_hash"] != prev:
                    return False, f"line {lineno}: prev_hash mismatch (expected {prev[:10]}..., got {obj['prev_hash'][:10]}...)"
                body = {k: v for k, v in obj.items() if k != "entry_hash"}
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
                recomputed = hashlib.sha256(canonical.encode()).hexdigest()
                if recomputed != obj["entry_hash"]:
                    return False, f"line {lineno}: entry_hash mismatch (audit_id={obj['audit_id']})"
                prev = obj["entry_hash"]
                n += 1
        return True, f"chain verified: {n} entries, tail={prev[:16]}..."


__all__ = ["AuditLogger", "AuditEntry", "GENESIS_PREV_HASH"]
