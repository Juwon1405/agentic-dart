<p align="center">
  <img src="./agentic-dfir-hero.png" alt="Agentic-DFIR — Autonomous DFIR Agent" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Juwon1405/agentic-dfir/actions/workflows/ci.yml"><img src="https://github.com/Juwon1405/agentic-dfir/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-aligned-4F46E5.svg" alt="MITRE ATT&CK aligned">
  <img src="https://img.shields.io/badge/MCP-read--only-1A73E8.svg" alt="MCP read-only">
  <img src="https://img.shields.io/badge/audit-SHA--256%20chained-22c55e.svg" alt="audit SHA-256 chained">
</p>

# Agentic-DFIR — Autonomous DFIR Agent for the SIFT Workstation

> *An autonomous DFIR agent that thinks like a senior analyst.*
> *Architecture-first, not prompt-first.*

**License:** MIT
**Status:** 🟢 Stable release line (2.0.0); runs end-to-end offline, self-correction path validated.

---

## What it is

Agentic-DFIR is an autonomous AI agent that sits on top of the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation), runs a senior-analyst-style reasoning loop with architectural evidence-integrity guarantees, and produces a courtroom-traceable report of its findings. It is not a replacement for Velociraptor, KAPE, Timesketch, Plaso, or any SIEM/EDR — those are the layers underneath. The agent is given exactly 48 typed, read-only native forensic functions plus 25 SIFT Workstation tool adapters through a custom MCP server; anything outside that surface — `execute_shell`, `write_file`, `mount`, `eval` — does not exist and cannot be called regardless of what the prompt says. Evidence integrity is a property of the system's shape, not a rule the agent is asked to follow. The full account — the pitch, the bet behind it, the target case class and the development approach — is [`docs/overview.md`](./docs/overview.md).

## Architectural guarantees

Each of these is checkable from the repository; the long form is in [`docs/overview.md`](./docs/overview.md#architectural-guarantees).

- **The bypass test is in the demo.** `bash examples/demo-run.sh` ends with the agent attempting to call `execute_shell` and getting `ToolNotFound` — the boundary is architectural, not promised. The adversarial version is [`tests/test_mcp_bypass.py`](./tests/test_mcp_bypass.py).
- **Every claim is auditable.** Every finding carries the `audit_id`s of the MCP calls that produced it; `python3 -m dfir_audit trace examples/out/ref-01/audit.jsonl F-013` resolves a finding in the reference run back to the exact call, source artifact and output hash.
- **The senior-analyst loop is encoded methodology.** [Playbook v3](./dfir_playbook/senior-analyst-v3.yaml) is a ten-phase YAML methodology whose every framework block cites its source — see [`dfir_playbook/README.md`](./dfir_playbook/README.md).
- **The contradiction handler forces revision.** When MFT timestamps disagree with EVTX events the agent halts, flags `UNRESOLVED`, and revises its hypothesis instead of picking a winner — see the [pass-the-hash case study](./docs/case-pth-timestomp.md).
- **73 tools, full suite green, 0 destructive ops.** 48 native forensic functions + 25 SIFT Workstation tool adapters = 73 typed read-only MCP tools; zero destructive operations possible by construction. `bash examples/demo-run.sh` and `python3 -m pytest` confirm it on a fresh clone.

## Quick start

The full copy-paste, three-path guide is **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)**.
The short version:

```bash
# 1. Install — Agentic-DFIR + the collector adapter (auto-detects your OS).
#    Also stages Velociraptor, yara, Volatility 3, Plaso and the Eric Zimmerman Tools; the only option is --help.
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
bash scripts/install.sh

# 2. Test it now — no API key, deterministic, ~5 s.
bash examples/demo-run.sh

# 3. Real analysis — add a key, then run a case.
export ANTHROPIC_API_KEY='sk-...'
python3 analyze.py --case self-evaluation/case-01
```

Downloading the external datasets, or analyzing your own disk image / host
collection (collect → adapt → analyze), are in
[`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Architecture

![Agentic-DFIR Architecture](./docs/dfir-architecture.png)

The custom MCP server (`dfir_mcp`) is the primary enforcement layer — the agent has no `execute_shell()`, destructive commands are not refused but absent — and every call it makes is recorded by `dfir_audit` in a SHA-256-chained JSONL file that fails verification if rewritten. The agent loop (`dfir_agent`), the correlation engine (`dfir_corr`) and the playbook (`dfir_playbook`) sit on top of that boundary, and evidence is mounted read-only at the OS level before the agent is ever started; the five packages, the data flow between them and the design rationale are in [`docs/architecture.md`](./docs/architecture.md).

## Documentation

All long-form documentation lives under [`docs/`](./docs/README.md); each package has its own README.

| Group | Page | What it covers |
|---|---|---|
| Start here | [Documentation index](./docs/README.md) | Every page in `docs/`, grouped, with a one-line description each. |
| | [Quick start](./docs/QUICKSTART.md) | Three ways to run: the deterministic demo, the bundled benchmarks, your own evidence. |
| | [Overview](./docs/overview.md) | What Agentic-DFIR is and is not, why it exists, the target case class, the guarantees, how it is developed. |
| | [Operator guide](./docs/operator-guide.md) | Install, requirements, evidence-mounting discipline, both run modes, reading and verifying the output, running the tests. |
| | [Running on SIFT](./docs/running-on-sift.md) | SIFT-specific setup from a fresh VM to a verified run. |
| | [Troubleshooting](./docs/troubleshooting.md) | Known issues and resolutions, grouped by install, runtime and evidence handling. |
| | [FAQ](./docs/faq.md) | Short answers to the first questions, each linking to the page that goes deeper. |
| | [Glossary](./docs/glossary.md) | DFIR, agent and MCP terms as the project uses them. |
| Concepts | [About the name](./docs/about-the-name.md) | What the name says and the four-phase plan it is built to outlast. |
| | [The Memex bet](./docs/memex-bet.md) | Why the durable artifact is the analyst's reasoning, not the report. |
| | [Architecture-first vs prompt-first](./docs/architecture-first-vs-prompt-first.md) | The central design claim, its failure mode in prompt-first systems, and the test that makes it executable. |
| | [Threat model](./docs/threat-model.md) | What the read-only boundary makes impossible, what it does not address, what the audit chain proves. |
| | [Comparison with adjacent tools](./docs/comparison.md) | Where Agentic-DFIR sits relative to Velociraptor, KAPE, Plaso, Timesketch, SIEM/EDR and AI agent frameworks. |
| Architecture and tool surface | [Architecture](./docs/architecture.md) | The five packages, the repository layout, DuckDB and the audit chain, the three evidence-protection layers. |
| | [MCP function catalog](./docs/mcp-function-catalog.md) | Every one of the 48 native functions: artifact, purpose, MITRE mapping, reference. |
| | [SIFT Workstation adapter layer](./docs/sift-adapter-layer.md) | The 25 adapters over Volatility 3, Eric Zimmerman tools, YARA and Plaso, and the contract each must satisfy. |
| | [Platform support](./docs/platform-support.md) | Host and target platforms, functions by platform, adapters by tool family, MITRE tactic coverage. |
| | [Live mode](./docs/live-mode.md) | Claude driving `dfir-mcp` over stdio: authentication, the loop, outputs, token accounting, wire-level tests. |
| | [`dfir_mcp`](./dfir_mcp/README.md) | The read-only MCP server: surface registration, guards, running it, the tests that hold the boundary. |
| | [`dfir_agent`](./dfir_agent/README.md) | The wrapper loop: CLI, iteration controller, deterministic and live modes, credentials, playbook wiring. |
| | [`dfir_audit`](./dfir_audit/README.md) | The SHA-256-chained audit log: entry format, integrity properties, `verify` / `lookup` / `trace` / `summary`. |
| | [`dfir_corr`](./dfir_corr/README.md) | The DuckDB correlation engine: timeline joins, `UNRESOLVED` contradictions, the rule pack. |
| | [`dfir_playbook`](./dfir_playbook/README.md) | The senior-analyst playbooks: the three bundled YAMLs, the v3 schema, forking for a new case class. |
| | [`dfir_sigma`](./dfir_sigma/README.md) | The versioned Sigma detection pack matched by `match_sigma_rules`. |
| Evaluation and case studies | [Accuracy report](./docs/accuracy-report.md) | Metrics, ground truth, per-run invariants, representative outputs, and the limitations that weight the numbers. |
| | [Benchmarks](./docs/benchmarks/README.md) | Recall by model, self vs external, rendered from the per-case ledger. |
| | [Dataset](./docs/dataset.md) | The bundled self-evaluation tier and the on-demand external tier, with licenses. |
| | [Case study: IP-KVM remote-hands insider](./docs/case-ip-kvm.md) | The bundled executable case: finding → artifact → command → hash, on the committed reference run. |
| | [Case study: Pass-the-Hash with timestomp](./docs/case-pth-timestomp.md) | The conceptual walkthrough of a run, stage by stage, through a contradiction and a revision. |
| | [Writing case studies](./docs/writing-case-studies.md) | Adding a bundled case: layout, `truth.json`, validation, scoring, what a PR needs. |
| | [Evidence and case studies](./examples/README.md) | The `examples/` tree: canonical evidence, case tiers, reference output. |
| | [Evaluation suite](./scripts/eval/README.md) | `scripts/eval/`: self and external measurement, dataset download, scoring, ground-truth validation. |
| Project | [Roadmap](./docs/roadmap.md) | Phase 1 shipped and open items, Phases 2–4 directions, companion projects, what is not on the roadmap. |
| | [The self-learning loop](./docs/self-learning-loop.md) | Phase 2 design: improving analysis quality from execution traces without loosening read-only. |
| | [External skill references](./docs/external-skill-references.md) | Anthropic-Cybersecurity-Skills candidates tracked for future absorption. |
| | [Tests](./tests/README.md) | The `pytest` suite: what each file covers, how CI runs it. |
| | [Scripts](./scripts/README.md) | Repository tooling: install, health check, evaluation, asset regeneration. |
| | [Changelog](./CHANGELOG.md) | Release history. |

## Companion projects

- **[agentic-dfir-collector-adapter](https://github.com/Juwon1405/agentic-dfir-collector-adapter)** (MIT) — converts Velociraptor offline-collector ZIPs into the `evidence_root` layout this engine reads and seeds the chain-of-custody (`manifest.json` + SHA-256 index).
- **[yushin-mac-artifact-collector](https://github.com/Juwon1405/yushin-mac-artifact-collector)** (MIT, archived) — single-file bash collector for macOS hosts that cannot run Velociraptor; its supply-chain IOC patterns were ported into `dfir_mcp._v05_supply_chain`.

The collection layer is intentionally not part of this repository; the full table and the Phase 1 rollout status are in [`docs/roadmap.md`](./docs/roadmap.md#companion-projects).

## Contributing and security

- Contribution policy, what is and is not accepted, and the PR checklist: [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- Reporting a guardrail bypass (read-only surface, audit chain) or any other vulnerability: [`SECURITY.md`](./SECURITY.md).

## Acknowledgments

Agentic-DFIR is authored and maintained by [@Juwon1405](https://github.com/Juwon1405). All architectural design, the typed MCP tool surface (native pure-Python + SIFT Workstation adapters), the senior-analyst playbook, audit chain, contradiction handler, agent loop, and test suite are original work.

**Community contributions accepted:**

- [@Monibee-Fudgekins](https://github.com/Monibee-Fudgekins) — [PR #42](https://github.com/Juwon1405/agentic-dfir/pull/42), 1-line CI matrix expansion (added Python 3.13). Resolved good-first-issue [#7](https://github.com/Juwon1405/agentic-dfir/issues/7). Thank you for the clean PR and the link back to the issue.

For the contribution policy, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT — see [LICENSE](./LICENSE).

## Author

**Bang Juwon** &nbsp;·&nbsp; 방주원 &nbsp;·&nbsp; 優心 (ゆうしん, *yushin*)

DFIR practitioner & detection engineer based in Tokyo. Goes by **yushin** in shells, terminals, and most places that aren't legal documents.

- 🐙 GitHub &nbsp; &mdash; &nbsp; [github.com/Juwon1405](https://github.com/Juwon1405)
- ✉️ Email &nbsp; &mdash; &nbsp; juwon1405.jp@gmail.com

This project is a **personal, independent project**. Built outside any
employer relationship. All work, opinions, and code in this repository
are my own and do not represent the views of any organization I am
affiliated with.
