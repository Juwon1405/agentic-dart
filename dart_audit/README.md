# dart-audit

Structured JSONL logger. Side-tapped from every MCP call. Append-only. Never rewritten.

## Entry schema

```json
{
  "ts": "2026-06-01T14:23:17.412Z",
  "iteration": 2,
  "tool_name": "extract_mft_timeline",
  "inputs": {"start": "2025-12-01T00:00:00Z", "end": "2025-12-08T00:00:00Z"},
  "output_digest": "sha256:...",
  "audit_id": "a7f3e9",
  "token_count_in": 412,
  "token_count_out": 1847,
  "finding_ids": ["F-013", "F-014"]
}
```

## Why append-only matters

Every finding in the final report carries an `audit_id`. That ID resolves — in ≤3 clicks — to:

1. The MCP call that produced the evidence
2. The exact underlying SIFT tool command
3. The raw tool output (byte-identical)

If the audit log were rewritable, the trace would be untrustworthy. It is not.

## Integrity

- Each entry is written with `O_APPEND`
- SHA-256 of each entry is included in the next entry (chain)
- At finalization, the chain is verified end-to-end

## Status

Scaffolding. Append-only writer + chain verifier target late April 2026.
