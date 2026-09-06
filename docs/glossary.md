# Glossary

DFIR, agent, and MCP terms used across the project, with the meaning they carry in Agentic-DFIR specifically. Sorted alphabetically. Where a term names a file, test, or command, the entry gives the exact name so it can be looked up in the tree.

### Agentic-DFIR

This project: an autonomous DFIR agent whose guardrails live in the architecture (read-only MCP surface, SHA-256 audit chain, contradiction handling) rather than in the prompt. Scope grows from autonomous DFIR (Phase 1) to detection engineering (Phase 2) to agentic SOC (Phase 3), with later phases building on the same read-only, audit-chained core. See [About the name](./about-the-name.md).

### Architecture-first

Design philosophy: guardrails are encoded in the *type system* and *function surface*, not in the LLM prompt. A jailbroken model is still bounded by what functions exist on the wire. Compare prompt-first.

See [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md).

### Audit chain

Append-only JSONL where each entry's `entry_hash` includes the previous entry's hash (`prev_hash`). SHA-256. Tampering with any entry breaks the chain at that point and every subsequent point. Written by `dfir_audit.AuditLogger`; see [dfir-audit](../dfir_audit/README.md).

### Audit ID

8-character hex string (4-byte `secrets.token_hex(4)`) randomly generated per audit-chain entry. Findings cite their supporting `audit_id`s, so any finding can be traced back to the logged MCP calls that produced it with `python3 -m dfir_audit trace <audit.jsonl> <finding_id>`; a single entry is retrieved with `python3 -m dfir_audit lookup <audit.jsonl> <audit_id>`.

### Bypass test

[`tests/test_mcp_bypass.py`](../tests/test_mcp_bypass.py). Asserts that destructive function names (`execute_shell`, `write_file`, `mount`, `umount`, `eval`, `exec_python`, `network_egress`, `delete_file`, `system`, `spawn_process`, `kill_process`) are not registered on the surface, that the registered set is exactly the expected positive set, that path traversal and null bytes are refused, and that SQL-injection payloads in correlation rules are rejected. The most important test in the repository — if it fails, the architectural guarantee is broken.

### Case class

A YAML tag in a playbook that says what kind of case the rules are tuned for. v1 lists them under `target_case_class`, v2 under `target_case_classes`, and v3 maps attack patterns to them with `maps_to_case_class`. Values in the bundled playbooks include `insider_threat_unauthorized_access`, `remote_hands_ip_kvm`, `living_off_the_land_execution`, `ransomware_response_recovery_denial`, `identity_centric_intrusion`, `vishing_initial_access`, and `exploit_initial_access`. See [dfir-playbook](../dfir_playbook/README.md).

### Chain integrity

The property that an audit chain re-validates from scratch: every entry's `prev_hash` matches the previous entry's `entry_hash`, and every `entry_hash` recomputes from its body. The CLI command is `python3 -m dfir_audit verify <file>`.

### Contradiction (UNRESOLVED / RESOLVED)

When two artifacts disagree about a fact — e.g. auth log says the event happened at T, the MFT says the profile was timestomped 74 seconds earlier. `dfir-corr` returns it as a record with `status: "UNRESOLVED"` and never auto-resolves it; the agent must either run additional calls that resolve it or report the finding as unresolved with both sources cited. Mechanical, not subjective.

### Derived root

`DFIR_DERIVED_ROOT` env var. The directory where SIFT adapters that must produce output (the Plaso `log2timeline` / `psort` wrappers) write their storage files. Separate from the evidence root, so generated timelines never touch evidence.

### Deterministic mode

Run the agent without an external LLM (`--mode deterministic`, the default of `python3 -m dfir_agent`). A scripted analyst exercises the playbook end-to-end, writes `audit.jsonl`, `progress.jsonl`, and `report.json`, and verifies the chain at exit. No `ANTHROPIC_API_KEY` needed. Suitable for CI and air-gapped runs.

### dfir-agent

The wrapper loop. The only Python package with control flow. Reads a playbook, calls MCP functions, runs `dfir-corr`, writes the audit chain (deterministic mode), emits findings. Provides both modes; see [dfir-agent](../dfir_agent/README.md).

### dfir-audit

SHA-256 chained audit log. Append-only JSONL. CLI subcommands `verify`, `lookup`, `trace`, `summary`. See [dfir-audit](../dfir_audit/README.md).

### dfir-corr

Cross-artifact correlation. DuckDB-backed. Surfaces contradictions as `UNRESOLVED`. Three public functions: `correlate_events`, `correlate_timeline`, `correlate_download_to_execution`. The architecture-first claim made concrete. See [dfir-corr](../dfir_corr/README.md).

### dfir-mcp

The typed MCP server: the typed forensic function surface, schema-validated, read-only. The "surface" — anything not here is not callable. See [dfir-mcp](../dfir_mcp/README.md).

### dfir-playbook

YAML sequencing rules. Operator-tunable. Decides what the agent calls next given the current state. See [dfir-playbook](../dfir_playbook/README.md).

### Evidence root

`DFIR_EVIDENCE_ROOT` env var. The directory the agent reads from. Mounted read-only by the operator (Layer 3 defense). All MCP functions route file paths through `_safe_resolve`, which canonicalizes and rejects anything outside this root.

### Finding

A claim the agent emits in its final report, e.g. "USB Kingston DataTraveler inserted at 14:22:18 UTC". Each finding cites the `audit_id`s of the supporting MCP calls, so it can be traced back to the logged calls with `dfir_audit trace`. Finding IDs look like `F-001`, `F-013`.

### Ground truth

The expected findings for a bundled case, stored in that case's `truth.json`. Eleven cases ship with the repository: eight synthetic self-evaluation cases and three external-evaluation cases built on public datasets. Scoring lives in `scripts/eval/`; see [Dataset](./dataset.md).

### Hypothesis

The agent's current working theory: a statement with a confidence score and lists of supporting and contradicting findings. The loop keeps a primary and an alternative hypothesis and writes both to `progress.jsonl` after every iteration. Revised on `UNRESOLVED` contradictions or new evidence.

### Live mode

Run the agent connected to a real Claude model (`--mode live`). Needs Anthropic credentials, resolved per model: Haiku uses local Claude credentials when present and falls back to `ANTHROPIC_API_KEY`; Sonnet and Opus need `ANTHROPIC_API_KEY` (see [Live mode](./live-mode.md#model-aware-authentication)). Same surface, same architectural guarantees as deterministic mode. `--dry-run` drives the same MCP plumbing with a scripted mock model and needs no key. See [Live mode](./live-mode.md).

### LOLBin

"Living Off the Land Binary". A signed Microsoft binary with a benign primary purpose that can be repurposed for malicious use (e.g. `comsvcs.dll` for LSASS dump, `regsvr32.exe` for code execution). Detected by `detect_credential_access` and similar functions.

### MCP (Model Context Protocol)

Anthropic's open protocol for connecting an LLM to typed external tools. Used by `dfir-mcp` over JSON-RPC stdio (`python -m dfir_mcp.server_stdio`). https://modelcontextprotocol.io

### MITRE ATT&CK

The framework that maps attacker techniques to a tactic taxonomy (enterprise tactics from Initial Access through Impact). Detection functions in `dfir-mcp` tag their hits with technique IDs, and playbook v3 attack patterns list their `mitre_techniques`. https://attack.mitre.org

### Playbook

A YAML file that encodes "what should the agent call next given the current state". Operator-tunable, lives in [dfir-playbook](../dfir_playbook/README.md). Three versions ship: v1 (quick demo), v2 (methodology baseline), v3 (default, industrialization release).

### Progress log

`progress.jsonl`: one snapshot per iteration with the phase, the primary and alternative hypothesis, unresolved items, and notes. Agent-writable state, inside the agent's trust boundary (unlike `audit.jsonl`).

### Prompt-first

The opposite of architecture-first. Guardrails live in the LLM's system prompt: "do not modify evidence", "do not exfiltrate". Vulnerable to prompt injection, jailbreaks, and prompt erosion over long sessions.

### Replay attack (in audit)

An attempt to replay a previously recorded audit entry as if it were a fresh one. Prevented by per-entry random `audit_id`. The chain integrity check still validates structurally; the random IDs make stitched-together logs detectable.

### Senior-analyst loop

The reasoning pattern Agentic-DFIR implements: form hypothesis → call typed tools → check for contradictions → revise on contradiction → emit findings with citations. Encoded in the [dfir-playbook](../dfir_playbook/README.md) YAML, executed by [dfir-agent](../dfir_agent/README.md).

### SIFT adapter

A typed, read-only MCP wrapper around a tool shipped on the SANS SIFT Workstation, implemented as a subprocess call with binary resolution, timeouts, SHA-256 hashing of inputs and outputs, and structured parsing of stdout. 25 adapters: 12 Volatility 3 plugins, 9 Eric Zimmerman tool wrappers (MFTECmd, EvtxECmd, PECmd, RECmd, AmcacheParser), 2 YARA, 2 Plaso. See [SIFT adapter layer](./sift-adapter-layer.md).

### Sigma

Open YAML-based signature format for security event log detection. Vendor-agnostic. The `dfir_sigma` package ships a detection rule pack (11 rules) that `match_sigma_rules` evaluates; Sigma rule *synthesis* from audit corpora is Phase 2 work on the [roadmap](./roadmap.md). https://github.com/SigmaHQ/sigma

### Surface

The set of function names callable on the MCP wire. **48 native MCP tools + 25 SIFT adapters = 73** typed read-only tools. Asserted as the test `test_mcp_surface.py::test_registered_tools_are_exact_set` and again in the bypass test.

### `_safe_resolve`

The path-safety helper in `dfir_mcp`. Canonicalizes any path argument (resolves `..`, symlinks), refuses null bytes and over-long paths, and rejects results outside `DFIR_EVIDENCE_ROOT` by raising `PathTraversalAttempt`. Layer 2 of the read-only guarantee.

### Timestomp

Modifying file timestamps to evade detection. Detected by comparing `$SI` (Standard Information, user-modifiable) against `$FN` (File Name, kernel-set) in the MFT. Mismatch = timestomp. T1070.006.

## See also

- [About the name](./about-the-name.md) — what the name says
- [Architecture](./architecture.md)
- [Threat model](./threat-model.md)
- [MCP function catalog](./mcp-function-catalog.md)
- [Documentation index](./README.md)
