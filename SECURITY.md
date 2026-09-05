# Security Policy

## Reporting vulnerabilities

If you believe you've found a way to bypass Agentic-DFIR's architectural
guardrails — particularly the read-only MCP surface or the SHA-256
audit chain — please open a private advisory on GitHub rather than a
public issue.

Specifically in scope:

- Any function that escapes `_safe_resolve` and reads outside `EVIDENCE_ROOT`
- Any tampering of `audit.jsonl` that is NOT caught by `dfir-audit verify`
- Any agent-reachable path to a destructive operation

Out of scope:

- Findings produced by the agent that are later shown to be false
  positives — these are accuracy concerns, not security issues.
  Open a normal issue.

## Supported versions

The `main` branch and the latest tagged release are supported. Older
tags receive no fixes.
