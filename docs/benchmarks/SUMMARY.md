# Benchmark Summary

Accuracy of Agentic-DART against measured bundled and external DFIR datasets.

Layer-1 rows are appended only when the runner executes the corresponding
measurement harness. Historical rows for unexecuted synthetic cases were
removed because they duplicated the case-01 measurement instead of scoring
those cases independently.

| Date | Case | Findings | GT | Strict Recall | Lenient Recall | Hallucinations | Audit |
|------|------|---------:|---:|--------------:|---------------:|---------------:|:-----:|
| 2026-06-10 | case-01-ipkvm-insider (realistic) | 2 | 2 | 100.00% | 100.00% | 0 (0.0%) | ✓ |
