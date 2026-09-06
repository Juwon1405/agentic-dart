# The Memex bet — why Agentic-DFIR encodes reasoning, not transcripts

This page is the long form of the bet underneath the whole project: that the durable, compounding artifact in DFIR is the senior analyst's reasoning, not the report, and that an LLM agent inside a typed read-only boundary is the maintainer that can finally keep such an artifact current. It traces the idea from Vannevar Bush's Memex through Karpathy's LLM Wiki pattern to the shape of Agentic-DFIR, and ends with a reading list. The short version is in [`overview.md`](./overview.md#the-deeper-bet--dfir-as-a-compounding-artifact).

> *"There may be millions of fine thoughts, and the records of experience on which they are based, all encased within stone walls of acceptable architectural form; but if the scholar can get at only one a week by diligent search, his syntheses are not likely to keep up with the current scene."*
>
> — **Vannevar Bush**, *As We May Think* (1945)

## Bush's vision and what was missing

In 1945, Vannevar Bush sketched the **Memex** — a personal, curated, associative knowledge store. Not a filing cabinet. Not an encyclopedia. A *device of trails*: every piece of information linked to every other piece by the user's own reasoning, building up over a lifetime into a thinking machine that augmented its operator.

The web came close. So did wikis. So did Obsidian, Roam, Notion. But none of them solved Bush's actual problem. The reason is simple:

**The trails decay because no one maintains them.**

Linking your notes is fun for a week. Updating them when new evidence contradicts old claims is bookkeeping. Cross-referencing fifteen pages when one new fact arrives is bookkeeping. Re-deriving a synthesis after the underlying sources change is bookkeeping. Humans abandon knowledge bases because the maintenance burden compounds faster than the value.

Bush did not have an answer for who would do the maintenance. The answer did not exist in 1945. It does now.

## Karpathy's bet — and why it generalizes

Andrej Karpathy's [LLM Wiki pattern (April 2026)](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) makes this explicit:

- The knowledge base is the **durable, compounding artifact**, not the chat
- The LLM is the maintainer that humans never were
- Every source is integrated once and *kept current* — not re-derived per query
- Contradictions are flagged, not smoothed over
- Every claim cites a real source

This is the Memex with the maintenance problem solved. The LLM does the bookkeeping no human will. The knowledge base keeps getting richer with every source added and every question asked.

## DFIR has the same shape

A senior digital forensics analyst is a Memex made of bone and coffee.

They have read tens of thousands of MFT records and recognize the timestomp pattern at a glance. They have seen *comsvcs.dll loaded by rundll32 with MiniDump in the command line* enough times to know it's T1003.001 LSASS access. They know that EVTX 4624 logon-type 9 with an admin token is almost always T1134 access-token manipulation. They have internalized the difference between Bianco's Pyramid layers — that an IP address is cheap to change but a TTP is not. They know, instinctively, that a contradiction between two artifacts is the most valuable signal in the entire investigation.

This knowledge does not transfer. When a senior analyst leaves the team, the team gets dumber. When the team is asked to investigate a new case at 3 AM, the analysis quality is whoever is on call.

A single forensic investigation generates dozens of intermediate findings: process trees, MFT timestamps, EVTX events, lateral-movement chains. In conventional tooling these findings vanish into a chat log or a one-off PDF. Nothing accumulates. Every new investigation re-derives the same patterns from scratch.

The DFIR profession has been carrying this exact Memex problem for thirty years. Same maintenance bottleneck, different domain.

## Agentic-DFIR is the same bet, applied to DFIR

We took Karpathy's framing and asked: *what if the durable, compounding artifact for DFIR is the senior-analyst loop itself?*

| Karpathy's LLM Wiki | Agentic-DFIR |
|---|---|
| Raw sources (immutable) | Forensic evidence (read-only mount) |
| Knowledge base (LLM-maintained markdown) | [Playbook v3](../dfir_playbook/README.md) (multi-section YAML methodology — default; v2 retained as baseline) |
| Schema (CLAUDE.md / AGENTS.md) | [MCP surface](../dfir_mcp/README.md) (the typed forensic function surface) + [audit chain](../dfir_audit/README.md) |
| LLM does maintenance | Agent runs every case, audit-traced |
| Every claim cites a source | Every finding cites an `audit_id` |
| Contradictions flagged | [`dfir-corr`](../dfir_corr/README.md) — contradictions returned as `UNRESOLVED`, carried into the report, never auto-resolved |
| Knowledge base compounds over time | Each case adds to the playbook's case classes |

The senior analyst is the Memex. The playbook is the schema. The MCP surface is the boundary. The audit chain is the trail. The agent is the maintainer.

The architecture-first principle goes one step further than Karpathy's pattern: in DFIR, *we cannot trust the maintainer*. An LLM acting as an editor in a research vault has limited blast radius. An LLM acting as a forensic analyst with shell access has unlimited blast radius. So we removed the shell. The typed MCP surface (48 native pure-Python functions + 25 SIFT Workstation adapters) is not a guideline — it is the entire universe the agent inhabits. Why that boundary has to be architectural rather than prompted is the subject of [`architecture-first-vs-prompt-first.md`](./architecture-first-vs-prompt-first.md).

## The bet, in one sentence

> **The senior analyst's reasoning is the durable artifact, not the report.**
>
> Encode it once, as architecture. Let it run on every case. Let it self-correct against contradictions. Let every claim cite the audit ID of the call that produced it.

If we are right, this is what every DFIR team will look like in five years — a small number of senior analysts curating the playbook, a fleet of audit-chained agents running it, and a maintenance loop that compounds rather than decays.

If we are wrong, the architecture is still safer than the alternative. The agent cannot run `rm -rf` on evidence. That alone is worth shipping.

## Reading list

- Vannevar Bush, [*As We May Think*](https://www.theatlantic.com/magazine/archive/1945/07/as-we-may-think/303881/) — *The Atlantic*, July 1945
- Andrej Karpathy, [LLM Wiki gist](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) — April 2026
- David Bianco, [Pyramid of Pain](https://www.sans.org/tools/the-pyramid-of-pain) (2013) and [Hunting Maturity Model](https://www.sans.org/tools/hunting-maturity-model)
- Caltagirone, Pendergast, Betz, [*Diamond Model of Intrusion Analysis*](https://apps.dtic.mil/sti/citations/ADA586960) (2013)
- Mandiant, [*M-Trends 2026*](https://cloud.google.com/security/resources/m-trends) — 500K hours of frontline incident response
- Hutchins, Cloppert, Amin, [*Intelligence-Driven Computer Network Defense*](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf) — Lockheed Martin (2011)

## See also

- [`about-the-name.md`](./about-the-name.md) — what the name says and the four-phase plan
- [`architecture.md`](./architecture.md) — the packages that implement the boundary, the trail and the schema
- [`architecture-first-vs-prompt-first.md`](./architecture-first-vs-prompt-first.md) — the central design claim
- [`threat-model.md`](./threat-model.md) — what the architecture defends against and what it does not
- [`dfir_playbook/README.md`](../dfir_playbook/README.md) — the senior-analyst methodology in YAML
