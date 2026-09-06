# FAQ

Short answers to the questions that come up first about Agentic-DFIR: what it is, how it relates to Claude and to adjacent DFIR tooling, what the architecture does and does not guarantee, and where to read further. Each answer links to the page that covers the topic in depth.

## Project basics

### What is Agentic-DFIR, in one sentence?
An autonomous DFIR agent on the SANS SIFT Workstation that thinks like a senior analyst — architecture-first, not prompt-first.

### What does the name mean?
It is literal: *agentic* — an autonomous, iterative, auditable loop rather than a wrapper around an LLM — plus *DFIR*, digital forensics and incident response. Nothing in the name needs decoding. See [About the name](./about-the-name.md) for the four-phase plan.

### Is this a fork of something?
No. Original work, MIT licensed. The MCP protocol is from Anthropic, and Claude is the LLM used in live mode, but the architecture and code are independent.

### Is this a personal project?
Yes. This is a personal, independent project, built outside any employer relationship; all work, opinions, and code in the repository are the author's own and do not represent the views of any organization the author is affiliated with. The Author section of the [README](../README.md) makes that explicit.

### Was AI used in the development?
Yes, openly. The "Development approach" section of the [Overview](./overview.md) discloses Claude as a coding collaborator. Architectural decisions, threat coverage taxonomy, MITRE mapping, and final review are human-driven; implementation, synthetic evidence generation, test scaffolding, and documentation drafting were AI-accelerated. Every commit is reviewed before it lands.

## Technical

### Is the MCP surface really fixed in size?
Yes. `tests/test_mcp_surface.py` asserts the exact positive set, and `tests/test_mcp_bypass.py` asserts it again together with a negative set. If a 74th tool appears or any of the 73 disappears, the tests fail on the next CI run.

### Does Agentic-DFIR work without the Claude API?
Yes. The deterministic demo path (`bash examples/demo-run.sh`) runs end-to-end with no API key, and `python3 -m dfir_agent --case test --out /tmp/out --mode live --dry-run` exercises the real MCP stdio plumbing with a scripted mock model. Live mode (real Claude model + MCP stdio) is available but optional. See [Live mode](./live-mode.md).

### How big is the audit log?
One JSONL line per MCP call, roughly 570 bytes each: the committed reference run [`examples/out/ref-01/audit.jsonl`](../examples/out/ref-01/audit.jsonl) holds 3 entries in 1,704 bytes. A run that makes a few dozen calls therefore produces an audit log in the tens of kilobytes. The chain is verified at the end of every deterministic run; tampered logs are detected.

### Why DuckDB and not SQLite?
DuckDB handles columnar joins on millions of rows orders of magnitude faster than SQLite, which matters for MFT-scale timeline correlation. SQLite is fine for the audit log; DuckDB is right for `dfir-corr`. See [Architecture — Why DuckDB](./architecture.md#why-duckdb).

### Will it run on other Linux distributions outside SIFT?
Yes. The host is **Linux only** — the SANS SIFT Workstation (Ubuntu 22.04) is the primary target, and other distributions (RHEL / Rocky / AlmaLinux 8+, Fedora) work via their package manager. macOS and Windows are **not** supported as the host (the Plaso / libyal toolchain doesn't build cleanly on them). This is about *where the agent runs* — macOS and Windows **evidence** are fully supported as analysis targets (dedicated artifact parsers; self-evaluation case-03 is itself a macOS investigation). See [Platform support](./platform-support.md).

### Why Python and not Rust / Go?
Three reasons:
1. The MCP ecosystem is Python-first
2. DFIR tooling (Volatility, Plaso, etc.) is Python
3. The bottleneck is LLM API latency, not Python execution time

If a specific function needed to be rewritten in a faster language (e.g. an MFT parser doing 10M rows), it would still be exposed via the same MCP schema. The MCP surface is what the agent sees; the implementation is opaque.

## Safety & guarantees

### Can the agent damage evidence?
No. By construction. The MCP surface has no write functions, and the evidence directory is mounted read-only at the OS level. See [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md) and [Threat model](./threat-model.md).

### Can the agent make stuff up?
It can, in the sense that any LLM can. The architectural guarantee is *not* that the agent never hallucinates. The guarantee is that:
1. Every finding carries the audit_ids of the MCP calls that produced it
2. The audit log is replayable and tamper-evident
3. `dfir-corr` flags contradictions as `UNRESOLVED` rather than hiding them

So a hallucinated finding either (a) carries no audit_id, which is visible in the report and is counted as a hallucination by the demo scorer, or (b) has an audit_id, in which case a human reviewer can trace it back to the logged call (`python3 -m dfir_audit trace <audit.jsonl> <finding_id>`), replay it, and confirm.

### What if the LLM ignores the system prompt?
Doesn't matter. The system prompt is not a security boundary. The MCP surface is. See [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md).

### What's NOT in scope for safety?
- Confidentiality of the evidence (the agent reads everything you mount)
- Network egress prevention (run in an air-gapped environment if you care)
- Resource exhaustion (use container limits)

These are deployment concerns. Agentic-DFIR addresses them by *not* being responsible for them. The full list is in [Threat model — Out of scope](./threat-model.md#out-of-scope-be-honest).

## Comparison with adjacent tools

### How is this different from Velociraptor?
Velociraptor is excellent for *collection*. Agentic-DFIR is for *reasoning over collected evidence*. They compose: a Velociraptor flow collects, the [collector adapter](https://github.com/Juwon1405/agentic-dfir-collector-adapter) converts the output into an evidence root, then `dfir-agent --case` reasons over it.

### How is this different from KAPE?
KAPE is similar — collection / triage. Same compositional answer.

### How is this different from a fine-tuned LLM?
This project doesn't fine-tune anything. The LLM is generic; the value comes from the architecture (MCP surface + correlation engine + audit chain + playbook). A fine-tuned LLM could replace the generic one, but it would still need this scaffolding to be safe and auditable.

### How is this different from "just give the LLM bash"?
The "just give the LLM bash" approach is exactly what `dfir-mcp` is designed to *not* be. See [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md) and, for the full layer map against adjacent tools, [Comparison](./comparison.md).

## See also

- [Overview](./overview.md) — what the project is, why it exists, what it guarantees
- [Architecture](./architecture.md)
- [Threat model](./threat-model.md)
- [Glossary](./glossary.md)
- [Troubleshooting](./troubleshooting.md)
- [Documentation index](./README.md)
