# Benchmark run history

Append-only ledger. Every `python3 -m scripts.eval.self` and `python3 -m scripts.eval.external` run adds one row at the bottom — rows are never overwritten, so this is the trend over time. The snapshot tables (`MODEL-COMPARISON.md`, `SUMMARY.md`) always hold the latest run only.

| Run (UTC) | Tier | Models | Cases | Mean recall | Per-model recall |
|---|---|---|---|---|---|
| 2026-06-15T13:55:33Z | self | haiku, sonnet, opus | 8 | 78.5% | haiku=71.9%, sonnet=85.1%, opus=78.4% |
| 2026-06-15T13:56:44Z | external | haiku, sonnet, opus | 3 | 37.5% | haiku=16.7%, sonnet=48.7%, opus=47.0% |
| 2026-06-15T14:34:04Z | external | haiku, sonnet, opus | 3 | 37.2% | haiku=19.4%, sonnet=48.7%, opus=43.3% |
| 2026-06-15T14:44:59Z | self | haiku, sonnet, opus | 8 | 44.7% | haiku=67.0%, sonnet=0.0%, opus=67.3% |
| 2026-06-15T14:48:05Z | self | haiku, sonnet, opus | 8 | 75.0% | haiku=53.6%, sonnet=79.8%, opus=91.5% |
| 2026-06-15T15:15:10Z | external | haiku, sonnet, opus | 3 | 35.4% | haiku=8.3%, sonnet=50.7%, opus=47.0% |
| 2026-06-15T15:52:48Z | external | haiku, sonnet, opus | 3 | 33.7% | haiku=12.0%, sonnet=55.4%, opus=— |
| 2026-06-15T16:30:47Z | external | haiku, sonnet, opus | 3 | 27.3% | haiku=3.7%, sonnet=43.3%, opus=35.0% |
| 2026-06-15T16:44:55Z | self | haiku, sonnet, opus | 8 | 83.3% | haiku=75.6%, sonnet=85.4%, opus=89.0% |
