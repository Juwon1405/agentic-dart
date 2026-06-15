# Documentation index

| File | Purpose |
|---|---|
| `accuracy-report.md` | Headline accuracy methodology and numbers (reference + realistic variants, recall / FPR / hallucination on F-001, F-013), ground truth, and explicit limitations. |
| `architecture.md` | Five-package layout (audit, mcp, agent, corr, playbook), data flow between them, and the dart-architecture diagram. |
| `comparison.md` | Positioning vs adjacent tools (CrewAI, AutoGen, SuperAGI, etc.) on the DFIR-specific axes. |
| `dataset.md` | Layer 2 external datasets (CFReDS, Ali Hadi, M57 Patents) — what is included, what is downloaded on demand, and license notes. |
| `live-mode.md` | Live-mode agent loop: iteration model, token-usage accounting (input / output / cache-read / cache-creation), and prompt-cache verification. |
| `troubleshooting.md` | Known issues and resolutions. |
| `case-pth-timestomp.md` | Case write-up: pass-the-hash + timestomp narrative used as a worked example. |
| `external-skill-references.md` | References to the Anthropic-Cybersecurity-Skills curated by the playbook and corr layers. |

## Subdirectories

- **`benchmarks/`** — supplementary benchmark write-ups and per-case detail
  (read alongside `accuracy-report.md` and `scripts/eval/README.md`).
- **`img/`** — diagrams (architecture, data flow, etc.) referenced from the
  Markdown above.
- **`screenshots/`** — UI / CLI screenshots used in `README.md` and the
  Devpost submission.
- **`legacy/`** — older write-ups kept for reference but no longer the
  canonical source.
