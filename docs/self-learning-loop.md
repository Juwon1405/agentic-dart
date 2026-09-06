# The self-learning loop (Phase 2 design)

> *How Agentic-DFIR improves its own analysis quality from its own execution
> traces — without fine-tuning, and without ever loosening the read-only
> guarantee.*

This is a **Phase 2 design note**, not shipped code. It documents the next
architectural bet: that an agent which already records a perfect, structured
trace of everything it did can be made to *compound* — to get measurably
better at the cases it just got wrong. Read it for the intended mechanism
(Run → Reflect → Extract → Loop), the guard that keeps a bad lesson from
degrading the agent, the cost model, and an honest statement of what exists in
the tree today.

---

## Why

A static agent starts every run from the same playbook. It never sharpens on
the case it just missed. A senior analyst is the opposite: each investigation
tightens their instincts, and that compounding *is* the expertise.

The bet here is that the compounding can be mechanized as **in-context
learning over the agent's own audit trail**. The SHA-256 ledger is already a
complete, machine-readable record of *what the agent did* and *whether it was
right* — exactly the substrate a learning loop needs.

---

## The loop: Run → Reflect → Extract → Loop

1. **Run** — the agent works a case (or the whole benchmark) and writes its
   audit chain, progress log, and findings.
2. **Reflect** — score the findings against ground truth (self-evaluation
   cases ship `truth.json`; real cases use the analyst's verdict): recall,
   precision, hallucination, per case. Then locate *where* it missed or went
   down a wrong path, and which tool sequence would have caught it.
3. **Extract** — turn those reflections into **durable, human-readable
   heuristics**: new `dfir-playbook` entries, refined `dfir-corr` thresholds,
   case-class hints. Not weights — text. The artifact is a reviewable diff.
4. **Loop** — re-run the benchmark with the updated heuristics. Keep the
   change *only* if it improves the aggregate without regressing any case.

---

## In-context, not fine-tuned

No model weights change. The learning lives in the **playbooks and configs the
agent reads at the start of each run**.

- Every behavior change is a **text diff**, attributable to the reflection
  that produced it. Fine-tuning would bury the lesson in opaque weights — the
  opposite of this project's thesis that DFIR reasoning belongs in inspectable
  architecture, not hidden state.
- **Evidence-Driven Development (EDD):** the benchmark is the test suite. A
  heuristic only ships if it moves the measured number.

---

## The recall-regression guard (Git rollback)

Every loop iteration is a commit.

- After re-running the benchmark, a guard compares per-case recall to the
  previous commit.
- If **any case regresses** (or aggregate recall drops), the guard **reverts
  the commit automatically** and logs why.
- Net effect: the playbook can only ratchet **upward**. A bad "lesson" can
  never silently degrade the agent.

---

## Cost model — always-on without burning API spend

The loop is meant to run continuously (overnight, or on every push), which
would be expensive on metered API. The split:

| Workload | Model | Credential |
|---|---|---|
| The always-on learning loop | **Haiku** | **OAuth subscription token** — flat cost, runs as long as you let it |
| Real-evidence analysis + headline benchmark numbers | **Sonnet / Opus** | **Metered API key** — reserved for top-tier reasoning |

`dfir-auth` (model-aware authentication, added in v1.2.0 as
`dfir_agent.auth`) already resolves the right credential per model, so the
loop and the benchmark coexist without manual token juggling. How the
credentials are resolved today is in [Live mode](./live-mode.md).

---

## Keep-alive architecture

A single long-running **supervised** process holds the loop: it wakes on a
trigger (timer or push), runs one `Run → Reflect → Extract → Loop` cycle,
commits or reverts, then sleeps.

- It is **supervised** — every cycle is logged to the same append-only
  ledger, and a human reviews the accumulated diffs before they reach `main`.
- It has **no new privileges**: it calls the same read-only MCP surface the
  agent always uses. It can edit playbooks and configs (text); it can never
  touch evidence.

---

## Safety — the read-only guarantee is untouched

The loop changes *how the agent reasons* (playbooks, thresholds), never *what
it can do* to evidence.

- The destructive-function exclusion (asserted by CI as an exact set) still
  holds: a self-written heuristic **cannot** add a destructive tool, because
  the registry is asserted, not appended to.
- The worst case of a bad lesson is a regression the guard catches and
  reverts.

---

## How it ties together

- **[dfir-audit](../dfir_audit/README.md)** — the structured record the loop
  reflects on.
- **[dfir-playbook](../dfir_playbook/README.md)** — where extracted heuristics
  land.
- **[dfir-corr](../dfir_corr/README.md)** — where refined correlation
  thresholds land.
- **The benchmark** ([`scripts/eval/`](../scripts/eval/README.md)) — the test that
  gates every lesson.

---

## Status

Design for [Phase 2 — agentic detection engineering](./roadmap.md#phase-2--agentic-detection-engineering).
Nothing on this page is implemented: the tree has no reflection step, no
heuristic extractor, no recall-regression guard, and no supervisor process,
and there is no `dfir_synth` package. Phase 1 already ships the parts the loop
needs — the audit chain (`dfir_audit`), the benchmark harness
(`scripts/eval/`: `self.py`, `external.py`, `score.py`), model-aware
authentication (`dfir_agent.auth`), and the YAML playbooks — so the loop is an
**assembly of existing pieces**, not new infrastructure.

## See also

- [Roadmap](./roadmap.md) — where Phase 2 sits among the four phases
- [Architecture-first vs prompt-first](./architecture-first-vs-prompt-first.md) — why lessons land in text, not weights
- [The Memex Bet](./memex-bet.md) — the compounding-artifact thesis this loop extends
- [Accuracy report](./accuracy-report.md) — the numbers the guard would compare
- [dfir-playbook](../dfir_playbook/README.md) — the file the loop edits
