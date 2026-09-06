# dfir-audit

`dfir-audit` is the append-only, tamper-evident JSONL log that records every MCP call the agent makes — inputs, output digest, `audit_id`, timestamp and a SHA-256 hash chain — so a human reviewer can replay the agent's reasoning end-to-end. This page explains why the chain exists, the Python API and entry format, the integrity properties, the `verify` / `lookup` / `trace` / `summary` CLI, and what chain integrity does and does not prove.

## Why this exists

Forensic findings have a chain-of-custody requirement that ordinary software doesn't. If the agent claims "USB Kingston DataTraveler was inserted at 14:22:18 UTC", a reviewer must be able to verify, after the fact:

1. The agent actually saw that artifact (audit recorded the read)
2. The artifact has not been edited between the agent's read and the reviewer's verification (hash anchored)
3. No log entry has been silently inserted, deleted, or reordered (chain unbroken)

A simple append-only log gives you (1). A SHA-256 chain — where each entry's hash includes the previous entry's hash — gives you (2) and (3) for free. Tampering with any entry breaks the chain at that point and every subsequent point.

### Why append-only matters

Every finding in the final report carries an `audit_id`. That ID resolves — in three commands at most — to:

1. The MCP call that produced the evidence (`lookup`)
2. The exact tool and validated inputs that were run (the entry's `tool_name` and `inputs`; for SIFT adapters the wrapped command)
3. The digest of the raw tool output, byte-identical when replayed against the same evidence

If the audit log were rewritable, the trace would be untrustworthy. It is not.

## API

```python
from dfir_audit import AuditLogger

logger = AuditLogger("audit/CASE-001.jsonl", run_id="run-abc")   # run_id defaults to a random hex token
audit_id = logger.log(
    tool_name="get_amcache",
    inputs={"hive_path": "disk/Windows/AppCompat/Programs/Amcache.hve"},
    output={"items": [...]},
    iteration=1,
    token_count_in=15,
    token_count_out=500,
    finding_ids=["F-001"],   # optional, used when this call directly produced a finding
)

ok, message = AuditLogger.verify("audit/CASE-001.jsonl")           # static; walks the whole chain
```

`log()` returns the entry's `audit_id`. The package exports `AuditLogger`, the `AuditEntry` dataclass and `GENESIS_PREV_HASH` (64 zeros). Opening an existing file resumes the chain: the constructor reads the last complete line and continues from its `entry_hash`, so a run that is interrupted and restarted keeps one unbroken chain.

## Entry schema

Each `log()` call writes one JSON line. This is the first entry of the committed reference run, [`examples/out/ref-01/audit.jsonl`](../examples/out/ref-01/audit.jsonl):

```json
{
  "audit_id": "7f311676",
  "entry_hash": "ea08eeb3545d901a8b7e5a0154f42ef93d492975f8e5f9cabc25d5cab31b5db0",
  "finding_ids": ["F-001"],
  "inputs": {"hive_path": "disk/Windows/AppCompat/Programs/Amcache.hve"},
  "iteration": 1,
  "output_digest": "sha256:46a1479e21342706e2df979e3b5e0fe31544dad6ffb29684cfa0cf1cd81c1cd4",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "token_count_in": 15,
  "token_count_out": 500,
  "tool_name": "get_amcache",
  "ts": "2026-06-14T21:02:19.713Z"
}
```

| Field | Type | Purpose |
|---|---|---|
| `audit_id` | 8-char hex (`secrets.token_hex(4)`) | Random per-entry ID. Used by findings for citation. |
| `prev_hash` | hex SHA-256 | `entry_hash` of the previous entry. The first entry uses `GENESIS_PREV_HASH` (`0000...0000`). |
| `entry_hash` | hex SHA-256 | Hash of *this* entry's canonical body, which includes `prev_hash`. |
| `iteration` | int | Loop iteration counter. |
| `tool_name` | str | The MCP function called. |
| `inputs` | dict | Validated inputs as passed in. |
| `output_digest` | `sha256:` + hex | Digest of the canonical JSON of the output (the full output is not stored — too big). |
| `finding_ids` | list[str] | Findings this call produced (empty if none). |
| `ts` | ISO-8601, millisecond precision, UTC | Wall-clock timestamp. |
| `token_count_in`, `token_count_out` | int | LLM token accounting (deterministic mode uses synthetic counts). |

Output is referenced by SHA-256 digest only — the output JSON itself is *not* persisted in the chain file. This keeps the file small enough to read and verify in one pass. To re-derive the output, replay the same `tool_name` + `inputs` against the same evidence; the digest will match if the evidence and the function are deterministic. (Live mode keeps its own per-call record in `live_tool_calls.jsonl` under the `--out` directory; the deterministic run keeps only the digest.)

## Integrity

- Each entry is appended with `O_APPEND` semantics: the file is opened in append mode, the line is flushed and `fsync`ed before the in-memory `prev_hash` advances.
- `entry_hash = SHA-256(canonical body)`, where the canonical body is every field except `entry_hash` — including `prev_hash` — serialised as sorted, compact JSON. This is the chain: each entry commits to the one before it.
- The same `default=str` serialisation is used when logging, when computing the canonical body and when verifying, so an input containing a `Path` or `datetime` neither crashes `log()` nor desynchronises the hash.
- `log()` is protected by a per-instance lock, so concurrent callers cannot produce two entries with the same `prev_hash`.
- At finalisation the chain is verified end-to-end: the deterministic agent calls `AuditLogger.verify` on exit and returns a non-zero exit code if the walk fails.

## Verifying the chain

```bash
python3 -m dfir_audit verify examples/out/ref-01/audit.jsonl
```

Output (clean chain, the committed reference run):

```
chain verified: 3 entries, tail=ec9fd1a90c9c893d...
```

Output (tampered) is one of:

```
line 12: entry_hash mismatch (audit_id=8fa06156)
line 12: prev_hash mismatch (expected 4f7a9c1b3e..., got 0c2e7d91aa...)
```

A path that does not exist reports `audit log not found: <path>` and also exits 1.

The verifier walks the chain forward, re-hashes each entry from its raw fields, and checks that `entry_hash` matches and that `prev_hash` matches the previous `entry_hash`. Any tamper — payload change, deletion, reorder — breaks the walk at the first affected line, and the command exits 1. `python3 -m dfir_audit.verify <audit.jsonl>` is an equivalent single-purpose entry point.

## CLI

```
python -m dfir_audit verify  <audit.jsonl>
python -m dfir_audit lookup  <audit.jsonl> <audit_id>
python -m dfir_audit trace   <audit.jsonl> <finding_id>
python -m dfir_audit summary <audit.jsonl>
```

`lookup` prints the full entry for one `audit_id`. `summary` prints entry count, chain verification result, calls per tool, calls per iteration and every finding ID referenced — for the reference run: 3 entries, `get_amcache` ×1 and `analyze_usb_history` ×2, findings `F-001` and `F-013`. Exit codes: 0 on success, 1 when the chain fails verification, 2 for a missing argument, unknown command, or an ID that is not found.

## Tracing a finding back to evidence

When the agent emits a finding like `F-013`, the report cites the `audit_id`s of the supporting MCP calls, and those entries carry `F-013` in their `finding_ids`. To trace:

```bash
python3 -m dfir_audit trace examples/out/ref-01/audit.jsonl F-013
```

`trace` walks the file and emits every entry that references the finding, as one JSON object: `finding_id`, `entry_count` and `entries` (each with its `tool_name`, `inputs`, `output_digest`, `iteration` and hashes). For `F-013` in the reference run that is the two `analyze_usb_history` calls — the first that surfaced the contradiction and the widened re-run that resolved it — which is how a reviewer gets from a claim in the report to the artifact reads behind it. This is the "three clicks from finding to raw evidence" path.

## What chain integrity does *not* prove

- That the inputs to a tool call were honest. The agent could pass any input.
- That the outputs were not selectively emitted by a buggy or malicious tool implementation.
- That the playbook the agent loaded was the playbook the operator thought they were running.

The audit chain is a *transcript integrity* tool, not a *reasoning correctness* tool. See [Threat model](../docs/threat-model.md) for the full scope.

## Files

```
dfir_audit/
├── README.md
├── pyproject.toml         # dfir-audit; no runtime dependencies
└── src/dfir_audit/
    ├── __init__.py        # AuditLogger, AuditEntry, GENESIS_PREV_HASH
    ├── __main__.py        # python -m dfir_audit -> cli.main()
    ├── cli.py             # verify, lookup, trace, summary
    └── verify.py          # python -m dfir_audit.verify <audit.jsonl>
```

## Status

Implemented — append-only writer, chain verifier and finding tracer. The integrity tests are in [`tests/test_audit_chain.py`](../tests/test_audit_chain.py) (clean chain verifies, tampering is detected, resume preserves the chain, non-JSON-native inputs hash consistently); run them with `pytest tests/test_audit_chain.py`.

## See also

- [Architecture — Why SHA-256 chained audit](../docs/architecture.md#why-sha-256-chained-audit) — why chained, why SHA-256
- [Threat model — What the audit chain proves](../docs/threat-model.md#what-the-audit-chain-proves)
- [dfir-agent](../dfir_agent/README.md) — the `_call` primitive that writes every entry
- [Operator guide — Verifying the audit chain](../docs/operator-guide.md#verifying-the-audit-chain)
- [`tests/test_audit_chain.py`](../tests/test_audit_chain.py) — integrity tests
