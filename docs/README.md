# Documentation index

| File | Purpose |
|---|---|
| `accuracy-report.md` | Headline accuracy methodology and numbers (reference + realistic variants, recall / FPR / hallucination on F-001, F-013), ground truth, and explicit limitations. |
| `architecture.md` | Five-package layout (audit, mcp, agent, corr, playbook), data flow between them, and the dfir-architecture diagram. |
| `comparison.md` | Positioning vs adjacent tools (CrewAI, AutoGen, SuperAGI, etc.) on the DFIR-specific axes. |
| `dataset.md` | Evidence datasets: the bundled self-evaluation cases (ground truth in `truth.json`) and the external tier (CFReDS, Ali Hadi, M57 Patents) — what is bundled, what is downloaded on demand, and license notes. |
| `live-mode.md` | Live-mode agent loop: iteration model, token-usage accounting (input / output / cache-read / cache-creation), and prompt-cache verification. |
| `troubleshooting.md` | Known issues and resolutions. |
| `case-pth-timestomp.md` | Case write-up: pass-the-hash + timestomp narrative used as a worked example. |
| `external-skill-references.md` | References to the Anthropic-Cybersecurity-Skills curated by the playbook and corr layers. |

## Subdirectories

- **`benchmarks/`** — supplementary benchmark write-ups and per-case detail
  (read alongside `accuracy-report.md` and `scripts/eval/README.md`).
- **`screenshots/`** — UI / CLI screenshots used in `README.md` and the
  wiki.

The architecture diagram lives at the top level of this directory:
`dfir-architecture.drawio` (editable source) and `dfir-architecture.png`
(rendered).
