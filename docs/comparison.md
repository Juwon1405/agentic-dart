# How YuShin Compares to Existing DFIR Tooling

This is the document a reviewer should read before asking "why not just
use Velociraptor?" YuShin is not a replacement for any of the tools
below — it sits at a different layer of the stack.

## Layer map

```
┌─────────────────────────────────────────────────────────────┐
│  YuShin                                                     │
│  Autonomous AI agent / orchestration / reasoning            │
│  (senior-analyst playbook, self-correction, audit chain)    │
├─────────────────────────────────────────────────────────────┤
│  Protocol SIFT (SANS baseline)                              │
│  MCP plumbing between AI and SIFT tools                     │
├─────────────────────────────────────────────────────────────┤
│  SANS SIFT Workstation — 200+ DFIR tools                   │
│  volatility · plaso · MFTECmd · PECmd · tshark · ...        │
├─────────────────────────────────────────────────────────────┤
│  Velociraptor / KAPE / Timesketch / GRR                     │
│  Collection, triage, timeline visualization                 │
├─────────────────────────────────────────────────────────────┤
│  Evidence (disk / memory / network)                         │
└─────────────────────────────────────────────────────────────┘
```

YuShin does not replace any of the lower layers. It orchestrates them.

## Side-by-side

| Tool | Layer | Primary actor | Guardrail model |
|------|-------|---------------|-----------------|
| Velociraptor | Collection / query | Human analyst writes VQL | Role-based access |
| KAPE | Triage | Human analyst runs target set | File system scope |
| Timesketch | Visualization | Human analyst explores timeline | N/A |
| GRR | Remote live forensics | Human operator | Role-based access |
| Plaso (log2timeline) | Timeline construction | Human / script | N/A |
| Sigma rules | Detection logic | SIEM/EDR engines | N/A |
| **Protocol SIFT (baseline)** | AI orchestration | AI agent (prompted) | **Prompt-based** |
| **YuShin** | AI orchestration | AI agent (architectural) | **Architectural (typed MCP surface)** |

## The YuShin thesis — where it differs from Protocol SIFT

Protocol SIFT and YuShin share the top-layer category (AI agent on
SIFT). The difference is how guardrails are enforced:

| Concern | Protocol SIFT (baseline) | YuShin |
|---|---|---|
| Destructive commands | Agent is told not to | Function does not exist on the server |
| Evidence modification | Prompt-based "please don't" | `mount -o ro,noload` + no write function in registry |
| Path traversal | Prompt-based | `_safe_resolve` — architectural |
| Audit trail | Log of LLM turns | SHA-256-chained JSONL, trace-queryable |
| Self-correction | Best-effort prompting | Playbook-forced, `progress.jsonl` state |
| Accuracy measurement | N/A by default | `scripts/measure_accuracy.py`, committed numbers |

This is the contribution YuShin tries to make to the FIND EVIL!
community: move the defender's analog of Anthropic's GTG-1002
architecture from prompt-obedience to architectural-enforcement.

## Things YuShin is NOT trying to be

- It is **not** a Velociraptor replacement. Velociraptor collects; YuShin reasons.
- It is **not** a Sigma engine replacement. YuShin's `match_sigma_rules`
  is a subset implementation for the agent's own triage needs, not a
  production SIEM detection engine.
- It is **not** a Timesketch alternative. It builds timelines for the
  agent to reason on, not for human visual exploration.
- It is **not** a production IR platform yet. It is a hackathon
  submission that demonstrates an architectural thesis and provides a
  working MVP to build on.

## When to use YuShin vs. when to use something else

| Goal | Use |
|------|-----|
| Collect artifacts from 10,000 endpoints | Velociraptor |
| Triage a single workstation via live flash drive | KAPE |
| Visualize a multi-host timeline with a team | Timesketch / Plaso |
| Run an autonomous AI triage of a disk image with an architectural safety guarantee | **YuShin** |
| Detect known attack patterns from Sigma rules at SIEM scale | Splunk / Elastic / Chronicle |
| Have an AI senior-analyst-style loop produce a courtroom-traceable report | **YuShin** |

The two use cases where YuShin is the right answer are the ones above
in bold. For everything else, reach for the tool that was built for
that job, and consider YuShin as the layer that can orchestrate those
tools under a safety-enforced agent loop.
