# Comparison with adjacent tools

How Agentic-DFIR relates to existing DFIR tooling and to other AI-assisted
security approaches. This is the page a reviewer should read before asking
"why not just use Velociraptor?" — Agentic-DFIR is not a replacement for any of
the tools below; it sits at a different layer of the stack. The comparison is
honest, not adversarial: most of these tools do something Agentic-DFIR
deliberately does not, and vice versa.

## TL;DR matrix

| | Agentic-DFIR | Velociraptor | Plaso/Log2Timeline | Eric Zimmerman tools | OpenAI / generic LLM agents |
|---|:---:|:---:|:---:|:---:|:---:|
| Reads forensic evidence | ✅ | ✅ | ✅ | ✅ | depends |
| Architectural read-only boundary | ✅ | partial | ✅ (parsers only) | ✅ | ❌ |
| Cross-artifact correlation | ✅ | ✅ | partial | ❌ | depends |
| LLM reasoning loop | ✅ | ❌ | ❌ | ❌ | ✅ |
| Tamper-evident audit log | ✅ | partial | ❌ | ❌ | ❌ |
| Operator-tunable playbook (YAML) | ✅ | ✅ | ❌ | ❌ | depends |
| MITRE ATT&CK chain reasoning | ✅ | partial | ❌ | ❌ | depends |
| Reproducible accuracy claim | ✅ | ✅ | ✅ | ✅ | rare |

## Layer map

```
┌─────────────────────────────────────────────────────────────┐
│  Agentic-DFIR                                               │
│  Autonomous AI agent / orchestration / reasoning            │
│  (senior-analyst playbook, self-correction, audit chain)    │
├─────────────────────────────────────────────────────────────┤
│  Prompt-first baseline agent                                │
│  MCP plumbing between AI and SIFT tools                     │
├─────────────────────────────────────────────────────────────┤
│  SANS SIFT Workstation — 200+ DFIR tools                    │
│  volatility · plaso · MFTECmd · PECmd · tshark · ...        │
├─────────────────────────────────────────────────────────────┤
│  Velociraptor / KAPE / Timesketch / GRR                     │
│  Collection, triage, timeline visualization                 │
├─────────────────────────────────────────────────────────────┤
│  Evidence (disk / memory / network)                         │
└─────────────────────────────────────────────────────────────┘
```

Agentic-DFIR does not replace any of the lower layers. It orchestrates them.

## Side-by-side

| Tool | Layer | Primary actor | Guardrail model |
|------|-------|---------------|-----------------|
| Velociraptor | Collection / query | Human analyst writes VQL | Role-based access |
| KAPE | Triage | Human analyst runs target set | File system scope |
| Timesketch | Visualization | Human analyst explores timeline | N/A |
| GRR | Remote live forensics | Human operator | Role-based access |
| Plaso (log2timeline) | Timeline construction | Human / script | N/A |
| Sigma rules | Detection logic | SIEM/EDR engines | N/A |
| **Prompt-first baseline agent** | AI orchestration | AI agent (prompted) | **Prompt-based** |
| **Agentic-DFIR** | AI orchestration | AI agent (architectural) | **Architectural (typed MCP surface)** |

## Velociraptor

**What it is:** Endpoint detection / forensic acquisition platform.
Open-source. The de-facto live-collection tool in modern DFIR.

**Overlaps with Agentic-DFIR:** Both expose typed forensic operations
(Velociraptor's VQL ≈ `dfir-mcp` functions). Both are operator-tunable.

**Differences:** Velociraptor is *live collection* — it runs on endpoints,
talks to a server, executes VQL queries against a running OS. Agentic-DFIR is
*post-collection analysis* — it reads dumps Velociraptor (or anything else)
produced. They're complementary: Velociraptor gathers, Agentic-DFIR reasons.
The companion collector adapter ingests a Velociraptor offline-collector ZIP
(or a raw disk image) into the `evidence_root/` layout the agent reads — see
the [operator guide](./operator-guide.md).

**Could they integrate further?** Yes — `dfir-mcp` could grow a
`velociraptor_query` function for live cases. Currently out of scope (Phase 1
is offline only).

https://docs.velociraptor.app/

## Plaso / log2timeline

**What it is:** The reference Python timeline-extraction toolkit. Parses 200+
forensic artifact types, produces a unified CSV/Plaso-storage timeline.

**Overlaps:** `dfir-mcp`'s parsers are a small subset of what Plaso supports.
Plaso is the gold standard for "I want every artifact parsed".

**Differences:** Plaso is *extraction*, Agentic-DFIR is *reasoning over
extracted data*. Plaso has no reasoning loop, no MITRE mapping, no
contradiction detection. They're complementary.

**Could they integrate?** They already do at the adapter level: the
`sift_plaso_log2timeline` and `sift_plaso_psort` adapters wrap Plaso on a SIFT
host (see the [SIFT adapter layer](./sift-adapter-layer.md)), and running
Plaso first to produce the timeline, then `dfir-corr` to correlate against
it, is a plausible workflow. Plaso → CSV → `correlate_timeline` works today.

https://github.com/log2timeline/plaso

## Eric Zimmerman's tools (PECmd, AmcacheParser, MFTECmd, ShellBags Explorer)

**What they are:** Single-purpose Windows artifact parsers. Used by every
working DFIR analyst on Windows.

**Overlaps:** `dfir-mcp`'s Windows parsers (`get_amcache`, `parse_prefetch`,
`parse_shellbags`, `extract_mft_timeline`) are *modeled on* the field
semantics these tools use. Naming and output structure aligned for operator
familiarity. Nine SIFT adapters (`sift_mftecmd_*`, `sift_evtxecmd_*`,
`sift_pecmd_*`, `sift_recmd_*`, `sift_amcacheparser_parse`) wrap the tools
themselves when they are installed.

**Differences:** Zimmerman's tools are command-line one-shots. Agentic-DFIR
invokes typed equivalents inside an autonomous loop. We didn't replicate
Zimmerman's depth; the goal is "structured-enough to feed an agent", not
"replace EZ tools". For deep manual analysis, use the originals.

https://ericzimmerman.github.io/

## TheHive / Cortex / SOAR platforms

**What they are:** SOAR (Security Orchestration, Automation, Response)
platforms — case management, automated playbooks, SOC workflow.

**Overlaps:** Both can run "playbooks". Both produce audit trails.

**Differences:** SOAR playbooks are typically *scripted decision trees* with
humans in the loop. Agentic-DFIR is *autonomous within a typed surface*.
Phase 3 (`dfir-responder`) will overlap more directly with SOAR — but only
with explicit human approval per action.

**Could they integrate?** Yes. The Phase 3 design lets Agentic-DFIR produce
response *proposals* that a SOAR platform takes through its own approval
flow. The architecture refuses to be a SOAR replacement; it's a reasoning
component upstream of one.

## "Just put DFIR data in ChatGPT / Claude"

**What it is:** Pasting EVTX exports, CSVs, MFT dumps into a chat window and
asking the model to analyze.

**Overlaps:** Both involve LLMs reasoning about forensic data.

**Differences (the big ones):**

- **No surface boundary.** A vanilla LLM will happily generate
  `subprocess.run` commands or claim it executed something. Agentic-DFIR's
  architecture refuses this by construction.
- **No audit chain.** A vanilla chat has no tamper-evident record of what
  was looked at.
- **No contradiction enforcement.** A vanilla LLM smooths over disagreements
  between artifacts.
- **No MITRE chain reasoning.** Maybe, if you remind it every turn.
- **No reproducibility.** Same input → different output (sampling, prompt
  drift).

This is the population Agentic-DFIR is *most* directly responding to. The
architectural argument is: if your DFIR workflow involves an LLM, the boundary
should be in code, not in the prompt.

## Sigma + sigma-cli

**What it is:** Open YAML-based signature format for log detection. The
community-maintained corpus of detection rules.

**Overlaps:** Many of `dfir-mcp`'s detection functions encode patterns that
Sigma rules also match (e.g. `comsvcs.dll` LSASS dump, AS-REP roasting). The
`match_sigma_rules` tool matches parsed events against the bundled
[`dfir_sigma`](../dfir_sigma/README.md) pack (11 rules).

**Differences:** Sigma is *signatures*. Agentic-DFIR is *reasoning*. Sigma
alerts on a known pattern; Agentic-DFIR can reason from low-signal evidence
to a chain.

**Future integration:** Phase 2 introduces `dfir-synth` — synthesize new
Sigma rules from audit corpora of past Agentic-DFIR runs. Already on the
[roadmap](./roadmap.md).

https://github.com/SigmaHQ/sigma

## NIST SP 800-150 / 800-86

**What it is:** NIST's reference frameworks for *threat hunting* (800-150)
and *forensic process* (800-86).

**Overlaps:** Agentic-DFIR's senior-analyst loop is *modeled on* the analyst
workflow described in 800-150 (form hypothesis → gather → analyze → revise).
800-86's chain-of-custody requirements informed `dfir-audit`.

**Differences:** NIST publishes guidance. Agentic-DFIR is an implementation
that conforms to the guidance — specifically the chain-of-custody,
replayability, and uncertainty-handling parts. The 800-150 hypothesis-driven
model is encoded in the playbook.

## The Agentic-DFIR thesis — where it differs from a prompt-first agent

A prompt-first baseline agent and Agentic-DFIR share the top-layer category
(AI agent on SIFT). The difference is how guardrails are enforced:

| Concern | Prompt-first baseline agent | Agentic-DFIR |
|---|---|---|
| Destructive commands | Agent is told not to | Function does not exist on the server |
| Evidence modification | Prompt-based "please don't" | `mount -o ro,noload` + no write function in registry |
| Path traversal | Prompt-based | `_safe_resolve` — architectural |
| Audit trail | Log of LLM turns | SHA-256-chained JSONL, trace-queryable |
| Self-correction | Best-effort prompting | Playbook-forced, `progress.jsonl` state |
| Accuracy measurement | N/A by default | `scripts/eval/demo.py`, committed numbers |

This is the contribution Agentic-DFIR tries to make: move the defender's
analog of Anthropic's GTG-1002 architecture from prompt-obedience to
architectural enforcement. The full argument is in
[Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md).

## What Agentic-DFIR deliberately is not

- **Not a replacement** for any of the above. The MCP surface is
  intentionally small. Use the right tool for the right job.
- It is **not** a Velociraptor replacement. Velociraptor collects;
  Agentic-DFIR reasons.
- It is **not** a Sigma engine replacement. Agentic-DFIR's `match_sigma_rules`
  is a subset implementation for the agent's own triage needs, not a
  production SIEM detection engine.
- It is **not** a Timesketch alternative. It builds timelines for the agent
  to reason on, not for human visual exploration.
- **Not a "general-purpose AI security analyst"** — it's tuned for
  evidence-based DFIR within a typed surface.
- **Not production-ready.** It is a research-grade implementation that
  demonstrates an architectural thesis and provides a working reference
  implementation to build on; production hardening is Phase 2–3.

## When to use Agentic-DFIR vs. when to use something else

| Goal | Use |
|------|-----|
| Collect artifacts from 10,000 endpoints | Velociraptor |
| Triage a single workstation via live flash drive | KAPE |
| Visualize a multi-host timeline with a team | Timesketch / Plaso |
| Run an autonomous AI triage of a disk image with an architectural safety guarantee | **Agentic-DFIR** |
| Detect known attack patterns from Sigma rules at SIEM scale | Splunk / Elastic / Chronicle |
| Have an AI senior-analyst-style loop produce a courtroom-traceable report | **Agentic-DFIR** |

The two use cases where Agentic-DFIR is the right answer are the ones above
in bold. For everything else, reach for the tool that was built for that
job, and consider Agentic-DFIR as the layer that can orchestrate those tools
under a safety-enforced agent loop.

## See also

- [About the name](./about-the-name.md)
- [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md)
- [Architecture](./architecture.md)
- [SIFT adapter layer](./sift-adapter-layer.md) — how the SIFT tools named above are wrapped
- [Roadmap](./roadmap.md) — Phase 2 `dfir-synth` and Phase 3 `dfir-responder`
