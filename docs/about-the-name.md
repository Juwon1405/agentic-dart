# About the name

This page explains what the name Agentic-DFIR says, why the "Agentic" prefix is there, and the four-phase plan the name is designed to outlast: the current release is the DFIR phase, and the later phases build on the same read-only, audit-chained core. The shipped-versus-planned detail for each phase lives in [`roadmap.md`](./roadmap.md); this page is about the naming and the direction.

## What the name says

The name is literal. **Agentic** says how the system works: an autonomous, iterative, auditable loop rather than a prompt wrapper. **DFIR** says what it works on: digital forensics and incident response. Put together, Agentic-DFIR is an agentic system for digital forensics and incident response — nothing in the name needs decoding.

The name makes no claim on its own — the guarantees do: a read-only MCP tool surface, a SHA-256-chained audit trail behind every finding, and a correlation layer that flags contradictions as `UNRESOLVED` instead of smoothing them over. Those guarantees are enumerated in [`overview.md`](./overview.md#architectural-guarantees).

## Why "Agentic"?

The "Agentic" prefix is a deliberate signal that this is not a wrapper around an LLM, not a single-shot tool, and not a chatbot. It is:

- **Autonomous** within a tightly typed boundary
- **Iterative** with hypothesis revision and confidence tracking
- **Auditable** end to end via SHA-256 chains

The word "agentic" is industry shorthand for "the agent is the unit of work, not the prompt." That matches what this project is.

## The four-phase plan

Agentic-DFIR begins as an *agentic DFIR* assistant. The current release is the DFIR phase. Later phases build on the same read-only, audit-chained core.

### Phase 1 (current) — Agentic DFIR

Senior-analyst reasoning encoded as architecture across forensic artifacts. The typed `dfir-mcp` surface (native pure-Python + SIFT Workstation adapters) covers broad MITRE ATT&CK enterprise tactic coverage. Verified by the test suite (run `pytest` on a fresh clone) and the bundled [IP-KVM](./case-ip-kvm.md) and [PtH-timestomp](./case-pth-timestomp.md) case studies.

Phase 1 includes the [agentic-dfir-collector-adapter](https://github.com/Juwon1405/agentic-dfir-collector-adapter), which converts Velociraptor offline-collector output into the `evidence_root` layout that Agentic-DFIR reads. The step-by-step Phase 1 rollout (1.0 cold workflow through 1.7 handover pack) is tabulated in [`roadmap.md`](./roadmap.md).

### Phase 2 — Agentic Detection Engineering

Once the DFIR loop is solid, the same architecture-first approach extends to:

- **Detection-as-code generation** — Sigma rule synthesis from observed evidence
- **Coverage-gap reasoning** — given an environment, what tactics is the current rule set blind to?
- **Rule maintenance** — what existing rules are now firing on benign behavior, and why?

Phase 2 also carries the supply-chain IOC sweep functions ported from [yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector) *(archived)* and generalized to cross-platform (litellm PyPI attack pattern, npm typosquat detection, install-hook abuse); they ship today in `dfir_mcp._v05_supply_chain`.

The MCP surface for Phase 2 will be additive (the existing typed surface stays intact; new functions for detection-engineering tasks are added). The architectural guarantee — read-only, audit-chained, contradiction-aware — stays the same.

### Phase 3 — Agentic SOC

Once detection is mature, the project moves into supervised SOC operations:

- **Triage** — given an alert, what is the minimum set of MCP calls needed to decide if it's worth waking a human?
- **Enrichment** — given an indicator, what is the agent allowed to look up and how does that integrate with internal threat intelligence?
- **Response orchestration** — a strict superset of the read-only surface, where *some* response actions become callable, but only through a separate "armed" MCP server with a different audit chain and human-in-the-loop confirmation.

This is where response actions first become callable — behind a separate armed server with its own audit chain and human confirmation.

### Phase 4 — Broader agentic security

Once the detection-and-response loop works, the same patterns extend to broader agentic security workflows beyond traditional detection-and-response boundaries:

- Vulnerability management (which CVEs in this codebase actually exposed?)
- Compliance evidence gathering
- Adversary emulation pre-flight checks
- Tabletop exercise generation

## Independence

This project is independent and personal. It is built outside any employer relationship; see the author section of the [project README](../README.md#author).

## See also

- [`overview.md`](./overview.md) — what Agentic-DFIR is, why it exists, and what it guarantees
- [`memex-bet.md`](./memex-bet.md) — the bet underneath the project
- [`roadmap.md`](./roadmap.md) — implemented versus planned, phase by phase
- [`architecture-first-vs-prompt-first.md`](./architecture-first-vs-prompt-first.md) — the central design claim
- [`README.md`](./README.md) — documentation index
