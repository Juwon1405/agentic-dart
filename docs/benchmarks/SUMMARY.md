# Benchmark ledger — self + external

_Record of record. Each row is one case (self **and** external); the left column is the **last time that case was run**. Running a single case — even a single model — updates only that row/cell and its timestamp; everything else is left as-is. Rendered from `ledger.json`. (Run history accumulates separately in `HISTORY.md`.)_

| Last run (UTC) | Case | haiku | sonnet | opus |
|---|---|---|---|---|
| 2026-06-15 16:44:55 | self-evaluation/case-01 | 67% | 67% | 67% |
| 2026-06-15 16:44:55 | self-evaluation/case-02 | 86% | 100% | 100% |
| 2026-06-15 16:44:55 | self-evaluation/case-03 | 57% | 86% | 100% |
| 2026-06-15 16:44:55 | self-evaluation/case-04 | 80% | 100% | 80% |
| 2026-06-15 16:44:55 | self-evaluation/case-05 | 75% | 62% | 100% |
| 2026-06-15 16:44:55 | self-evaluation/case-06 | 89% | 100% | 89% |
| 2026-06-15 16:44:55 | self-evaluation/case-07 | 85% | 85% | 85% |
| 2026-06-15 16:44:55 | self-evaluation/case-08 | 67% | 83% | 92% |
| 2026-06-15 16:30:47 | external-evaluation/case-01 | 0% | 50% | 25% |
| 2026-06-15 16:30:47 | external-evaluation/case-02 | 0% | 80% | 80% |
| 2026-06-15 16:30:47 | external-evaluation/case-03 | 11% | 0% | 0% |

## Mean recall per model (across recorded cases)

| Model | Mean recall | Cases recorded |
|---|---|---|
| `claude-haiku-4-5-20251001` | 56% | 11 |
| `claude-sonnet-4-6` | 74% | 11 |
| `claude-opus-4-8` | 74% | 11 |
