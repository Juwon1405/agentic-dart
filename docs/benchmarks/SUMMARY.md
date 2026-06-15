# Benchmark ledger — self + external

_Record of record. Each row is one case (self **and** external); the left column is the **last time that case was run**. Running a single case — even a single model — updates only that row/cell and its timestamp; everything else is left as-is. Rendered from `ledger.json`. (Run history accumulates separately in `HISTORY.md`.)_

| Last run (UTC) | Case | haiku | sonnet | opus |
|---|---|---|---|---|
| 2026-06-15 00:00:00 | self-evaluation/case-01 | 67% | 67% | 100% |
| 2026-06-15 00:00:00 | self-evaluation/case-02 | 0% | 100% | 100% |
| 2026-06-15 00:00:00 | self-evaluation/case-03 | 57% | 100% | 71% |
| 2026-06-15 00:00:00 | self-evaluation/case-04 | 80% | 60% | 80% |
| 2026-06-15 00:00:00 | self-evaluation/case-05 | 75% | 75% | 100% |
| 2026-06-15 00:00:00 | self-evaluation/case-06 | 89% | 100% | 89% |
| 2026-06-15 00:00:00 | self-evaluation/case-07 | 69% | 85% | 0% |
| 2026-06-15 00:00:00 | self-evaluation/case-08 | 83% | 92% | 92% |
| 2026-06-15 06:00:00 | external-evaluation/case-01 | 0% | 75% | 50% |
| 2026-06-15 06:00:00 | external-evaluation/case-02 | 0% | 40% | 0% |
| 2026-06-15 06:00:00 | external-evaluation/case-03 | 0% | 33% | 0% |

## Mean recall per model (across recorded cases)

| Model | Mean recall | Cases recorded |
|---|---|---|
| `claude-haiku-4-5-20251001` | 47% | 11 |
| `claude-sonnet-4-6` | 75% | 11 |
| `claude-opus-4-8` | 62% | 11 |
