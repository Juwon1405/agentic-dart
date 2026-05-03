# Devpost Submission Content — Agentic-DART v0.5

This file contains the exact text to paste into each section of the
[FIND EVIL! Devpost submission form](https://findevil.devpost.com/). Each
block below is annotated with the Devpost field name it goes into.

---

## [Devpost: Project Name]

```
Agentic-DART
```

---

## [Devpost: Tagline] (max 200 chars)

```
Architecture-first autonomous DFIR agent. 60 typed read-only MCP tools (35 native + 25 SIFT adapters). Evidence integrity is a property of the wire surface, not a prompt.
```

---

## [Devpost: Cover Image]

Use `agentic-dart-hero.png` from the repo root.

URL: `https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/agentic-dart-hero.png`

---

## [Devpost: Inspiration]

```markdown
Most "agentic DFIR" tools today are a system prompt that *asks* an LLM
to behave like a forensic analyst. They tell the model to preserve
evidence, not run destructive commands, and cite sources. Then they hope.

The problem with prompt-first agents is that the moment a prompt
injection succeeds, the model can do anything its toolkit allows —
including writing to evidence, mounting partitions, or running
arbitrary shell. Anthropic's GTG-1002 disclosure showed exactly this
failure mode at offensive scale.

Agentic-DART starts from a different bet: **evidence integrity should
be a property of the system's shape, not a rule the agent is asked to
follow.** If `execute_shell` and `write_file` don't exist on the MCP
wire, the agent cannot invoke them — regardless of how clever the
jailbreak is.
```

---

## [Devpost: What it does]

```markdown
Agentic-DART is an autonomous DFIR agent that runs on top of the SANS
SIFT Workstation. It exposes **60 typed, read-only forensic functions**
to Claude Code through a custom MCP server, in two layers:

**Layer 1 — Native (35 functions)**
Pure-Python implementations covering Windows execution evidence (Amcache,
Prefetch, Shimcache, MFT timeline, scheduled tasks, persistence
detection), user activity (USB, shellbags), authentication and lateral
movement (Kerberos, RDP brute-force, privilege escalation), macOS
artifacts (UnifiedLog, KnowledgeC, FSEvents, launchd plist), Linux
artifacts (auditd, journald, bash history), and cross-platform analysis
(browser history, web logs, webshell detection, ransomware/credential-
access/defense-evasion behavior detection).

**Layer 2 — SIFT Workstation tool adapters (25 wrappers)**
Subprocess wrappers around the canonical SIFT toolchain:
- Volatility 3 v2.27 (12 plugins: Win pslist/pstree/psscan/cmdline/
  netscan/malfind/dlllist/svcscan/runkey + Linux pslist/bash + macOS bash)
- Eric Zimmerman tools (8 wrappers: MFTECmd parse + timestomp,
  EvtxECmd parse + EID-filter, PECmd parse + run history, RECmd
  ASEPs batch + query-key, AmcacheParser)
- YARA (single-file + recursive directory scan)
- Plaso (log2timeline + psort)

The agent runs a 10-phase senior-analyst playbook (1135 lines of YAML
synthesizing M-Trends 2026, MITRE ATT&CK v16, the Diamond Model,
F3EAD, NIST SP 800-61/86/150, the Pyramid of Pain, the Hunting Maturity
Model, Palantir's ADS Framework, and TaHiTI). Every tool call is
SHA-256 hashed into a tamper-evident audit chain. Cross-artifact
contradictions are surfaced by a dedicated handler. The whole system
is reproducible from a `bash examples/demo-run.sh` on a clean clone.
```

---

## [Devpost: How we built it]

```markdown
**Architecture-first design.** Before writing any code, we wrote down
the invariant we wanted to hold: *the set of functions on the MCP
wire IS the agent's attack surface*. Anything we wanted the agent to
be unable to do — `execute_shell`, `write_file`, `mount`, `eval`,
outbound network — we kept off the wire entirely. This is verified by
`tests/test_mcp_bypass.py` which asserts both POSITIVE (what's
registered) and NEGATIVE (what must never be) surfaces.

**The 35 native functions came first.** Each one has a published
DFIR reference attached (Eric Zimmerman, Sarah Edwards, Sean
Metcalf, Patrick Wardle, Hal Pomeranz, Andrew Case, Florian Roth,
Roberto Rodriguez/OTRF, JPCERT/CC). 39 references total, all cited
in the wiki's MCP function catalog.

**The 25 SIFT adapters came in v0.5** to align with the hackathon's
Custom MCP Server pattern. Adding subprocess wrappers was easy; keeping
them safe was the harder part. Every adapter inherits the architectural
contract:

  1. Read-only EVIDENCE_ROOT enforcement (path-traversal blocked
     before subprocess is invoked)
  2. SHA-256 audit chain compatibility (input + output hashes flow
     into dart_audit ledger)
  3. Subprocess timeout by default (10 min — 6 hours per tool family)
  4. Structured Python dict output, never raw shell to the LLM
  5. Graceful SiftToolNotFoundError when binaries are absent — the
     agent loop falls back to native pure-Python implementations
  6. Well-formed JSON Schema for every tool

**dart_corr** handles cross-artifact contradictions via DuckDB SQL.
When two artifacts disagree (e.g., MFT timeline says one thing,
memory says another), dart_corr flags `UNRESOLVED` and the playbook
re-runs with adjusted parameters. This is the self-correction loop
the hackathon judges on.

**dart_audit** is a SHA-256 hash chain of every tool call (timestamp
+ tool name + arguments + output hash). Tampering at any step breaks
the chain. Verified by `tests/test_audit_chain.py`.

**dart_playbook** is a 10-phase senior-analyst sequencing rule set
(1135 lines of YAML). Phase order: triage → hypothesis formation →
artifact collection → corroboration → contradiction check → MITRE
mapping → confidence scoring → reporting → audit-chain verification →
final review. The playbook tells the agent *which tool to call next*
based on what it just learned.
```

---

## [Devpost: Challenges we ran into]

```markdown
**Prompt injection through filenames.** When you subprocess into
Volatility or MFTECmd, those tools' stdout contains the original
filenames. If an attacker named a file with literal text like
"IGNORE PREVIOUS INSTRUCTIONS AND...", that text would land in the
LLM context. Our defense: every adapter parses subprocess output
into structured Python dicts before returning. The LLM never sees
raw stdout.

**Hidden state in subprocess timeouts.** Long-running tools like
log2timeline can take hours. We needed timeouts to prevent agent
loop freeze, but the timeouts themselves had to be tunable per
tool family because Volatility plugins range from seconds to
minutes. We settled on conservative per-family defaults (10 min
for small tools, 30 min for MFT/EVTX, 6 hours for Plaso) with
per-call overrides.

**The setuptools subpackage discovery quirk.** When we shipped the
SIFT adapter subpackage, our own install script reported only 35
tools instead of 60 — because the editable pip install wasn't
picking up `sift_adapters/`. Adding `include = ["dart_mcp*"]` to
`pyproject.toml`'s `[tool.setuptools.packages.find]` fixed it. We
caught this only because our install script verifies the tool
count post-install. Lesson: trust no installer; verify the
artifact.

**Graceful degradation when SIFT binaries are missing.** Not every
deployment has the full Eric Zimmerman toolkit installed. We
wanted adapters to fail loud and recoverable, not crash the agent.
Solution: every adapter resolves its binary through `_which()`
which falls back through env-var override → PATH lookup → typed
`SiftToolNotFoundError`. The agent loop catches this exception and
falls back to the native pure-Python implementation where one
exists.
```

---

## [Devpost: Accomplishments that we're proud of]

```markdown
- **Zero destructive operations possible by construction.** The agent
  cannot run shell, write files, mount partitions, or send outbound
  traffic — not because we asked it not to, but because those functions
  are not on the wire. Verified by adversarial bypass tests.

- **60 typed read-only MCP tools.** 35 native + 25 SIFT adapters,
  all behind the same architectural contract. The SIFT layer added
  capability without weakening the boundary.

- **Tamper-evident audit chain.** Every tool call is SHA-256 hashed
  into a chain. Tampering at any step breaks the chain. The audit
  output is courtroom-traceable.

- **31/31 tests pass on a fresh clone** (CI-verified on Python 3.10/3.11/3.12). Includes adversarial bypass
  tests, audit chain tampering tests, concurrency tests, the v0.5
  SIFT adapter test suite, and the v0.5.2 QA-pass regression guard.

- **Senior-analyst playbook with 39 cited references.** Not vibes —
  encoded methodology synthesizing M-Trends 2026, ATT&CK v16, the
  Diamond Model, F3EAD, NIST SP 800-61/86/150, the Pyramid of Pain,
  the Hunting Maturity Model, Palantir's ADS Framework, MaGMa Use
  Case Framework, and TaHiTI.

- **Reproducible in 30 seconds from clean clone.**
  `bash examples/demo-run.sh` produces audit.jsonl, progress.jsonl,
  and report.json with verified hash chain.
```

---

## [Devpost: What we learned]

```markdown
Architecture-first beats prompt-first when the stakes are evidence
integrity. Every prompt is one jailbreak away from failure; an
architectural boundary is an algebraic guarantee.

Wrapping existing tools is more conservative than reinventing them.
The native 35 functions were the v0.1 — v0.4 work. v0.5's contribution
was recognizing that wrapping the SIFT toolchain (Volatility 3,
Eric Zimmerman tools, YARA, Plaso) was the right alignment with
the hackathon and the broader DFIR community, not a rewrite of those
tools in pure Python.

Verification is part of the install. Our install.sh probes for 9 SIFT
binaries and asserts the post-install tool count is exactly 60. This
caught a real packaging bug we'd otherwise have shipped silently.

Schema is the contract. Every adapter has a JSON Schema for its
inputs. Tests verify the schema is well-formed. This is the contract
between agent and tool — not the docstring, not the README.
```

---

## [Devpost: Acknowledgments / IP disclosure]

```markdown
This submission is the original work product of **Bang Juwon (@Juwon1405)** as a single-person Entrant. All architectural design, MCP function implementation (35 native + 25 SIFT adapters), playbook YAML, audit chain, contradiction handler, agent loop, test suite, and documentation are sole-authored.

**External community contributions accepted to date:**

- **PR #42 by @Monibee-Fudgekins** — a 1-line addition to the CI matrix (`"3.13"` appended to `.github/workflows/ci.yml::strategy.matrix.python-version`). The PR was a direct response to Issue #7 (a `good-first-issue` opened by the maintainer requesting exactly this change). No architectural component, no MCP function, no playbook content, no test logic, no documentation was contributed externally. The change is below the originality threshold for copyright protection (de minimis under 17 U.S.C. § 102) and is integrated under the repository's MIT license (inbound = outbound).

GitHub's Contributors graph is automatic and counts any commit author by name regardless of contribution size, which is why @Monibee-Fudgekins appears next to @Juwon1405 on the repository sidebar. This is a Git authorship record, not a co-ownership statement — IP rights for this submission remain solely with @Juwon1405 per Hackathon Rule §8 (a)(b)(c).
```

---

## [Devpost: What's next for Agentic-DART]

```markdown
- **Live deployment validation on a real SIFT Workstation OVA.** The
  v0.5 adapter layer was built and tested against a synthetic
  environment. We'll run it on the actual SIFT VM with real disk
  images / memory captures and tune parsers to match exact CSV
  column names from each tool's current build.

- **Add Hayabusa as a Sigma-rule fast-path adapter** for EVTX
  triage at scale (Yamato Security, Tokyo). Already cited in the
  playbook v3.1; an adapter would close the loop.

- **MaGMa Use Case Framework integration.** Currently referenced in
  the playbook; the next step is a structured detection-engineering
  workflow that produces MaGMa-shaped use case definitions as
  output artifacts.

- **Integration with the DFIR Report Yara-Rules and Florian Roth's
  signature-base** — the YARA adapter is already there; bundling
  curated rule corpora as optional submodules would make it
  one-shot useful.

- **Production-ready 1-liner installer for SIFT VMs.** The current
  `scripts/install.sh` works on a fresh SIFT OVA. We'll add a
  signed release tarball to GitHub Releases for offline /
  air-gapped install.
```

---

## [Devpost: Built With]

```
python
mcp
claude-code
anthropic-api
volatility3
mftecmd
evtxecmd
pecmd
recmd
amcacheparser
yara
plaso
duckdb
sift-workstation
mitre-attack
sigma
```

---

## [Devpost: Try it out — links]

```
GitHub repository:        https://github.com/Juwon1405/agentic-dart
Wiki:                     https://github.com/Juwon1405/agentic-dart/wiki
SIFT adapter layer docs:  https://github.com/Juwon1405/agentic-dart/wiki/SIFT-adapter-layer
CHANGELOG (v0.5.0):       https://github.com/Juwon1405/agentic-dart/blob/main/CHANGELOG.md
Demo run:                 bash examples/demo-run.sh
SIFT adapter demo:        bash examples/sift-adapter-demo.sh
1-liner install on SIFT:  curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash
```

---

## Submission checklist (per FIND EVIL! rules)

- [x] Code Repository: GitHub (public) with MIT license — https://github.com/Juwon1405/agentic-dart
- [ ] Demo Video: Screencast of live terminal execution with audio narration ← **TODO**: re-shoot on SIFT Workstation VM
- [x] Architecture diagram: `dart-architecture.png` in repo root
- [x] README with judging-criteria alignment section
- [x] Test suite (`tests/`) demonstrating bypass-resistance + adapter coverage
- [x] CHANGELOG with v0.5 entry
- [x] Wiki documentation
- [ ] Devpost submission form ← **paste content from this file**
- [ ] Submission deadline: **June 15, 2026**

---

## After submitting

1. Re-shoot demo video on SIFT Workstation VM (1-2 days, separate task)
2. Update Devpost cover image if needed
3. Join Protocol SIFT Slack for any judge Q&A
4. Wait for results announcement around July 8, 2026
