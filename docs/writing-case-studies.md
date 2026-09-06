# Writing case studies

This page explains how to add a new bundled case study to Agentic-DFIR: what a
good case looks like, where its files go, how `truth.json` is structured and
validated, how to run and score the agent against it, and what a pull request
needs to carry. Case studies are the most useful contribution after typed
forensic functions — they extend coverage to new attack patterns and validate
the architecture against new ground truth.

---

## What makes a good case study

| Property | Why |
|---|---|
| **Mechanically verifiable ground truth** | Every claim the agent makes must be checkable against artifacts. No "the analyst's intuition says X". |
| **Cross-artifact correlation required** | Single-artifact cases can be solved by string match. Real DFIR is correlation. |
| **At least one designed contradiction** | This exercises [`dfir-corr`](../dfir_corr/README.md). If everything aligns, the case is too easy. |
| **Self-contained** | Bundled in the repository, no external downloads, bundled evidence under 50MB. |
| **Reproducible exactly** | Same inputs → same findings and hypotheses (per-run audit IDs, hashes and timestamps will differ; the finding set won't). |

---

## Layout

Bundled cases live under `examples/case-studies/` in two tiers. A new authored
case goes in the self-evaluation tier:

```
examples/case-studies/
├── self-evaluation/            # synthetic scenarios authored for this project
│   └── case-NN/
│       ├── README.md           # incident narrative + reasoning hooks
│       ├── truth.json          # the N ground-truth findings the agent must surface
│       └── evidence_root/      # the read-only evidence tree the agent consumes
│           ├── disk/...
│           └── event-logs/...
└── external-evaluation/        # public third-party datasets, downloaded on demand
    └── case-NN/
        ├── README.md
        └── truth.json          # evidence is fetched by analyze.py --download
```

Folder names are **index-only** (`case-01`, `case-02`, …, numbered in the order
accepted into the repository); the human title lives in each case's
`README.md`. The agent resolves a case's evidence from its own
`case-NN/evidence_root/`. External-tier cases do not bundle evidence (size and
third-party licensing); their download registry is `scripts/eval/datasets.py`.
Use `self-evaluation/case-01/` as the pattern — `CONTRIBUTING.md` names it as
the reference layout.

---

## Step-by-step

### 1. Decide the case class

An issue is welcome but not required.
Before writing the case, work out — and, if you open an issue, describe:

- Attack pattern / case class
- Why existing cases don't cover it (check the case table in
  [`examples/case-studies/README.md`](../examples/case-studies/README.md))
- Approximate ground-truth count (5-30 findings is the sweet spot)
- Source of inspiration (real CTF, public IR report, your own work)

This avoids redundancy. Some attack patterns are already covered.

### 2. Generate or extract artifacts

Two paths:

**Synthetic** — generate artifacts programmatically. Good for: precise
control, reproducibility, no licensing concerns. Used by the bundled
`self-evaluation` cases (case-01..08).

**Real (with permission)** — use a published forensic dataset. Good for:
realism, immediate credibility. Reference dataset name + license + DOI / URL in
the case's `README.md`.

Either way: **artifacts are read-only**. The MCP surface exposes no function
that writes to the evidence tree, every path is resolved inside
`DFIR_EVIDENCE_ROOT`, and `scripts/eval/demo.py` hashes every evidence file
before and after the run and fails if anything changed.

### 3. Write `truth.json`

The file has two top-level keys, `case_metadata` and `ground_truth_findings`,
in the shape `self-evaluation/case-01/truth.json` uses:

```json
{
  "case_metadata": {
    "case_id": "case-01-ipkvm-insider",
    "title": "IP-KVM Remote-Hands Insider Pattern",
    "scenario_class": "Insider threat with remote-hands physical access vector",
    "evidence_path": "examples/case-studies/self-evaluation/case-01/evidence_root/",
    "platform": "Windows",
    "incident_window": "2026-03-15 14:19 - 14:30 UTC",
    "ground_truth_provenance": "Authored alongside the bundled sample evidence; ..."
  },
  "ground_truth_findings": [
    {
      "finding_id": "F-001",
      "category": "initial_access",
      "claim": "IP-KVM device (ATEN VID 0557 PID 2419) inserted before operator logon",
      "evidence_path": "disk/Windows/INF/setupapi.dev.log",
      "artifact_type": "usb_history",
      "host_path": "disk/Windows/INF/setupapi.dev.log",
      "expected_dfir_mcp_function": "analyze_usb_history",
      "mitre_attack": ["T1200"],
      "severity": "high",
      "rationale": "USB insertion signature at 14:19:47 precedes logon by ~3 minutes."
    }
  ]
}
```

Each finding **must** be supported by an artifact in your `evidence_root/`
(`host_path`). If a finding requires the agent to "infer", the case is not
mechanically verifiable — split it into atomic claims.
`expected_dfir_mcp_function` must name a registered `dfir-mcp` tool;
`python3 scripts/eval/validate_ground_truth.py` checks every finding against
the registered tool list and warns on unregistered names. Findings that carry
no `mitre_attack` technique (investigative conclusions, audit-chain notes) are
excluded from the scorer's denominator rather than counted as misses, because
`scripts/eval/score.py` matches findings on ATT&CK technique overlap.

### 4. Run the agent

Live mode, through the primary runner (API key required):

```bash
python3 analyze.py --case self-evaluation/case-NN
python3 -m scripts.eval.score \
    --findings out/self-evaluation/case-NN/<timestamp>/findings.json \
    --truth examples/case-studies/self-evaluation/case-NN/truth.json
```

Every `analyze.py` run writes `out/<tier>/<case-id>/<timestamp>/` with
`findings.json`, `report.json` and `summary.json`.

Deterministic loop against your evidence tree (no API key):

```bash
export DFIR_EVIDENCE_ROOT="$PWD/examples/case-studies/self-evaluation/case-NN/evidence_root"
python3 -m dfir_agent --case <case-id> --out ./out/<case-id> --mode deterministic --max-iterations 25
```

Compare the agent's output to `truth.json`:

- Recall: how many of the N findings did the agent surface?
- False positive rate: did the agent claim things not in ground truth?
- Hallucination count: did the agent claim facts not in any artifact? Every
  reported `audit_id` must resolve in the run's `audit.jsonl`.

`python3 analyze.py --list` shows every discovered case and whether it is
bundled, spec-only, or downloadable.

### 5. Tune the playbook (if needed)

If the agent doesn't reach the right findings within the iteration ceiling, the
playbook needs a hint. Add a `next_call_decisions` entry for your case class to
`dfir_playbook/senior-analyst-v3.yaml` (the default). Live mode loads the
highest-versioned `senior-analyst-v*.yaml` in `dfir_playbook/` automatically,
so no code change is involved. Keep the rule at the level of a case class that
generalizes (insider threat, ransomware, web breach) rather than one that only
matches your case; the playbook is shared by every case. See [Case study:
IP-KVM remote-hands insider](./case-ip-kvm.md#how-the-playbook-was-tuned-for-this-case)
for a worked example.

### 6. Write the case-study page under `docs/`

Add `docs/case-<short-name>.md`, using
[Case study: Pass-the-Hash with timestomp pre-existence](./case-pth-timestomp.md)
and [Case study: IP-KVM remote-hands insider](./case-ip-kvm.md) as templates,
and add a row for it to the [documentation index](./README.md). Include:

- The scenario (what happened, who's involved)
- The artifacts (what evidence is bundled)
- The agent's reasoning trace (call-by-call)
- Where the contradiction was (every good case has one)
- Measured accuracy
- Reproduction commands

Links are relative (`./other-page.md`, `../dfir_corr/README.md`,
`../examples/...`).

### 7. Open the PR

In the PR description, include:

- The issue number, if you opened one in step 1
- Number of findings, recall achieved, false-positive rate, audit-chain tail hash
- Any new playbook rules added, with rationale
- Confirmation that the existing test suite still passes (run `pytest`) and
  that the `CONTRIBUTING.md` PR checklist holds

---

## Anti-patterns

Things we will *not* accept:

| Anti-pattern | Why |
|---|---|
| Findings that require subjective judgment | Ground truth must be mechanical |
| Cases solvable by single function call | No architectural value |
| Cases with no contradictions | Doesn't exercise [`dfir-corr`](../dfir_corr/README.md) |
| Evidence pulled from a customer / production env | Even with anonymization, risk is too high. Synthetic only, or public-corpus only. |
| Cases that require new destructive verbs to solve | The architecture says no. Ever. |
| Cases that rely on prompt instructions | Use playbook YAML or new typed functions. Not prompts. |

---

## Review process

PRs adding case studies go through:

1. **Schema check** — `truth.json` passes
   `python3 scripts/eval/validate_ground_truth.py`, the same gate the
   pre-commit hook and the `benchmark-integrity` CI workflow run.
2. **Reproducibility check** — CI runs `bash examples/demo-run.sh` and
   `python3 -m scripts.eval.demo` on the bundled deterministic case and asserts
   the audit chain verifies; a new case must leave them green, and reviewers
   re-run the new case from the commands in the PR to confirm the documented
   findings count is reached.
3. **Architecture check** — no new prompt-based guardrails introduced; any new
   functions go through the standard surface-extension review (see
   [`CONTRIBUTING.md`](../CONTRIBUTING.md)).
4. **Documentation page accompanying** — the case-study page under `docs/` must
   be in the same PR.

Typical review turnaround: 3-7 days.

---

## See also

- [Architecture](./architecture.md)
- [Accuracy report](./accuracy-report.md) — how case-study accuracy gets measured
- [Case library](../examples/case-studies/README.md) — the eleven bundled cases and their tiers
- [`scripts/eval/README.md`](../scripts/eval/README.md) — the runners and the scorer
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
