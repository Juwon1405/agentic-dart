# YuShin (優心) — Autonomous DFIR Agent on SANS SIFT Workstation

> *An autonomous DFIR agent that thinks like a senior analyst.  
> Architecture-first, not prompt-first.*

**Submission to:** [SANS FIND EVIL! Hackathon 2026](https://findevil.devpost.com/)  
**License:** MIT  
**Status:** 🚧 Active development — submission deadline June 15, 2026

---

## Why YuShin exists

Protocol SIFT proved that AI agents can operate the SIFT Workstation. It also hallucinates more than a DFIR practitioner can stand behind in a courtroom-grade report. YuShin is an attempt to close that gap by encoding the *reasoning pattern of a senior analyst* as architecture — not as a prompt.

The name is a Japanese reading of **優心**, meaning "discerning mind."

## Architectural thesis

1. **Custom MCP Server** is the primary enforcement layer. The agent has no `execute_shell()`. Destructive commands are not refused — they are *not present*.
2. **Direct Agent Extension on Claude Code** handles session ergonomics. Security boundaries live in the server, not the prompt.
3. **Persistent Learning Loop** forces the agent to write its hypothesis, confidence, and unresolved gaps to disk every iteration. The next iteration must address those gaps or declare them unreachable.

Evidence is mounted **read-only at the OS level** before the agent is ever started. Integrity is a property of the system shape, not a rule the agent is asked to follow.

## Repository layout
