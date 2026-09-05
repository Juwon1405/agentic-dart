# `scripts/eval/` — the evaluation suite

Three runners plus the helpers they share. All three drive the **real**
pipeline; the only difference is what they run against and whether they call the
model.

| Runner | Calls the model? | Runs against | Answers |
|---|---|---|---|
| `demo.py` | No (deterministic) | case-01's bundled evidence | "is the toolchain wired up correctly?" |
| `self.py` | **Yes** (key required) | our 8 self-evaluation cases | "how good is the model on scenarios we authored?" |
| `external.py` | **Yes** (key required) | public images (CFReDS / Hadi / M57) | "how good is the model on third-party evidence?" |

`demo` is a fast sanity check, not a benchmark. The benchmark is simply running
`self` and/or `external` across one or more models and comparing — research data
on how models differ on pre-collected case studies.

## Quick start

```bash
# 0. fast rig check — no API key
python3 -m scripts.eval.demo

# 1. self cases, one model (needs a key)
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m scripts.eval.self

# 2. self cases, compare models -> docs/benchmarks/MODEL-COMPARISON.md
python3 -m scripts.eval.self \
    --models claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8

# 3. external datasets (downloads + verifies + adapts on first run)
python3 -m scripts.eval.external --case external-evaluation/case-01

# stage external data without spending tokens
python3 -m scripts.eval.external --prepare-only
```

`self` and `external` fail fast if `ANTHROPIC_API_KEY` is unset — they always
check before doing any work.

## Files

| File | Role |
|---|---|
| `demo.py` | deterministic rig check (accuracy 1.0 / integrity / containment) |
| `self.py` | run + score the self cases per model; writes the comparison matrix |
| `external.py` | one-shot prepare (download → MD5-verify → adapt to evidence_root) then run + score |
| `score.py` | score a run's `findings.json` against a case `truth.json` over the tool-reachable subset |
| `datasets.py` | registry of the public datasets (URLs, hashes, image names, truth paths) |
| `download.py` | resumable image download + checksum verification |
| `validate_ground_truth.py` | CI gate: truth.json integrity |

## How scoring works

`score.py` matches a run's findings to a case's ground truth and computes recall
over the **scorable** subset:

- **self** cases carry ATT&CK techniques; a finding matches by technique
  overlap. Findings with no technique (investigative conclusions, audit-chain
  notes) are excluded from the denominator, not counted as misses.
- **external** cases mostly carry no technique and instead flag
  `directly_detectable_v053` — whether the current toolset can reach the answer
  at all. Recall is computed over the reachable subset, so a low number reflects
  tool coverage (much of CFReDS needs SOFTWARE-hive / email parsing still on the
  roadmap), not model skill. Technique-less reachable findings match by the
  distinctive nouns in the claim.

## External data flow (unified)

`external.py`'s `prepare()` is idempotent and self-contained:

1. evidence_root already populated → reuse.
2. image already under `datasets/<short>/` → skip download; else download
   (resumable).
3. MD5-verify the image (when a hash is registered).
4. adapt the image into the case's `evidence_root` — collector adapter
   (`agentic-dfir-collector-adapter`) if installed, sleuthkit `tsk_recover`
   fallback otherwise.

`analyze.py` then only reads the prepared `evidence_root`. The heavy
fetch/verify/adapt lives here, where the dataset knowledge is.
