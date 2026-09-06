# Operator guide

This page is for the DFIR engineer who wants to run Agentic-DFIR on a real
case folder, not only the bundled demo. It explains the install, the
evidence-mounting discipline, both run modes, and how to read and verify what
comes out. If you just want the copy-paste path, [Quick start](./QUICKSTART.md)
is faster; this page is the explained version of the same commands.

## Prerequisites

**Operating system — Linux only.** Verified on the **SANS SIFT Workstation
(Ubuntu 22.04)**; other Linux distributions work via their package manager.
macOS and Windows are not supported as the host (see the note on Plaso below).
The default shell is **bash**.

| Requirement | Version / detail | Verified on |
|---|---|---|
| **OS** | Ubuntu 22.04 (SANS SIFT) — primary | SIFT Workstation |
| | RHEL / Rocky / AlmaLinux 8+, Fedora — via `dnf`/`yum` | best-effort |
| **Python** | **3.10 or newer** (CI matrix: 3.10 – 3.13) | 3.10, 3.12 |
| **Shell** | bash | — |
| **Live mode** | an `ANTHROPIC_API_KEY` | — |

| | Minimum | Recommended |
|---|---|---|
| RAM | 4 GB | 16 GB (correlation against multi-million-row MFT timelines) |
| Disk | 5 GB free for evidence + audit | SSD, 50 GB+ |
| Network | None for deterministic mode | Outbound HTTPS for live mode (Claude API) |

The agent does not require Anthropic API access for the deterministic path.
Live mode requires the `ANTHROPIC_API_KEY` environment variable (see
[Live mode](./live-mode.md) for the credential options).

**Third-party Python libraries** (lower bounds in the root `requirements.txt`,
installed automatically by `scripts/install.sh`):

| Library | Minimum | Role |
|---|---|---|
| `anthropic` | ≥ 0.40 | Claude API client (live mode) |
| `mcp` | ≥ 1.0, < 2 | MCP client/server transport (2.x removed the low-level server decorators the stdio server registers with) |
| `duckdb` | ≥ 1.5.3, < 2.0 | in-memory correlation store |
| `python-registry` | ≥ 1.3 | Windows registry hive parsing |
| `PyYAML` | ≥ 6.0 | playbook / Sigma rule loading |
| `requests` | ≥ 2.25 | dataset download (benchmarks) |

`dfir_audit` has no third-party runtime dependencies (stdlib only).

**External forensic tools** (staged by `scripts/install.sh`; SIFT ships most):

| Tool | Package | Used for |
|---|---|---|
| sleuthkit (`mmls`, `tsk_recover`) | `sleuthkit` | partition table + file recovery from disk images |
| `ewfmount` | `ewf-tools` / `libewf-tools` | expose an `.E01` as a raw image |
| Volatility 3 | via installer (pip) | memory analysis |
| Plaso (`log2timeline.py`, `psort.py`) | via installer (pip) | super-timeline generation |
| EZ Tools (EvtxECmd, MFTECmd, PECmd, RECmd, AmcacheParser, SBECmd) | via installer (.NET 9 builds) | Windows artifact parsing |
| YARA | `yara` | signature scanning |
| Velociraptor | staged binary (SHA-256 verified by the collector adapter's installer) | offline-collector / dead-disk adapter |

> **Why Linux only?** The forensic backend — **Plaso** (the
> `log2timeline`/`psort` super-timeline engine) and the **libyal** C libraries
> it depends on (`libewf`, `libvshadow`, …) — does not build cleanly on macOS:
> System Integrity Protection blocks the expected install paths, the bundled
> PyParsing is older than Plaso requires, and `pip`-without-virtualenv breaks
> site-packages. Plaso's own docs assume Ubuntu 22.04 and "strongly encourage"
> Docker on macOS. Rather than ship a host platform we can't stand behind, the
> installer targets Linux. **Windows host support is not on the roadmap.**

Per-platform detail (which functions run against which evidence OS) is in
[Platform support](./platform-support.md).

## One-time setup

### Fresh-clone install

The installer is the supported path. It installs into your current Python
interpreter, clones and installs the collector adapter as a sibling checkout
(`../agentic-dfir-collector-adapter`), stages a SHA-256-verified Velociraptor
binary, and adds the SIFT toolchain (yara, Volatility 3, Plaso) and the Eric
Zimmerman Tools:

```bash
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
bash scripts/install.sh
```

`install.sh` takes no options other than `--help`. It is idempotent: every
run checks each of its nine steps first (repositories, OS base packages,
Python packages, collector adapter, Velociraptor, yara, Volatility 3 + Plaso,
Eric Zimmerman Tools, health check) and skips whatever already works, so
re-running it is always safe. It prints one line per step and keeps the
per-step logs under `/tmp/dfir-install.*` only when a step failed or warned.
Do **not** run it with `sudo` — it refuses, because a root run resolves
packages against root's environment and leaves root-owned files that break
`git pull`. On an interactive terminal it ends by offering to download the
three external benchmark images (about 13 GB; download only, no analysis) and
writes two aliases to `~/.bashrc`: `dfir-pull` (pull both repositories) and
`dfir-auth` (show live-mode credential status).

The Python step installs `dfir_audit`, `dfir_mcp`, `dfir_corr`, and
`dfir_agent` in editable mode into the current interpreter — it does not
create or require a virtualenv. If you want isolation on a shared SIFT VM
(optional), activate one first and run the installer from it:

```bash
python3 -m venv .venv
source .venv/bin/activate
bash scripts/install.sh          # installs into the activated venv
```

Manual editable install (equivalent core, without the toolchain staging):

```bash
pip install --upgrade pip wheel
pip install -r requirements.txt
pip install -e ./dfir_audit -e './dfir_mcp[stdio]' -e ./dfir_corr -e './dfir_agent[live]'
```

> Prefer an isolated environment? Create and activate a virtualenv before
> running either path above — see
> [Troubleshooting](./troubleshooting.md#installing-inside-a-virtual-environment-optional).
> The installer neither creates nor requires one.

Each case resolves its own evidence from `case-XX/evidence_root/`, so no global
`DFIR_EVIDENCE_ROOT` export is needed for `analyze.py`. For the low-level
developer commands (`python3 -m dfir_agent`, direct `dfir_mcp` calls),
`DFIR_EVIDENCE_ROOT` must point to read-only evidence (it defaults to
`/mnt/evidence` when unset) and `DFIR_DERIVED_ROOT` (for generated Plaso
storage and other derived artifacts) should live outside the evidence tree:

```bash
export DFIR_DERIVED_ROOT="${TMPDIR:-/tmp}/agentic-dfir-derived"
```

### Verify the install

```bash
python3 scripts/healthcheck.py
# API-free readiness check: Python >= 3.10, package imports, dependency
# versions, tool-surface count, adapter CLI, case layout, analyze.py fails
# fast without a key.

python3 -c "from dfir_mcp import list_tools; print(len(list_tools()))"
# Should print: 73
```

The 73 read-only functions are 48 native parsers plus 25 SIFT Workstation
adapters. The health check only confirms that the adapters are *registered*;
`python3 scripts/check_sift_tools.py` reports which of the 25 backing binaries
are actually runnable on this host (honouring the `DFIR_*_BIN` overrides such
as `DFIR_VOLATILITY3_BIN` and `DFIR_YARA_BIN`). Missing binaries are not
fatal — the adapter raises `SiftToolNotFoundError` at call time and the native
tools still work. See [SIFT adapter layer](./sift-adapter-layer.md).

Then run the test suite — see [Running the tests](#running-the-tests) below.

## Real-world investigations (your own evidence)

Two machines, clean separation:

- **Incident host** (the box you're investigating) — gets **nothing installed**.
  It runs the **Velociraptor offline collector**: a single standalone binary,
  one-time execution, no agent, no install. It writes one `evidence.zip`.
- **Analysis server** (your SIFT/workstation) — has Agentic-DFIR **and** the
  collector adapter. All reasoning happens here, never on the evidence host.

You bring evidence in one of two ways, then analyse it with `analyze.py
--evidence`:

**A) Live triage — Velociraptor offline collector → ZIP** (the common case)

```bash
# 1. On the incident host (no install): run the collector binary once.
#    Windows:  velociraptor.exe -i artifacts collect Windows.KapeFiles.Targets --output evidence.zip
#    Linux:    ./velociraptor   -i artifacts collect Linux.Search.FileFinder   --output evidence.zip
#    ...then copy evidence.zip back to the analysis server.

# 2. On the analysis server: normalise the ZIP into an evidence_root.
python3 -m dfir_collector_adapter --source zip \
    --input evidence.zip --output ./case-001/evidence_root --case-id case-001

# 3. Analyse it.
export ANTHROPIC_API_KEY='sk-...'
python3 analyze.py --evidence ./case-001/evidence_root --case-id case-001 --max-iterations 25
```

**B) Dead disk — forensic image (`.dd`/`.raw`/`.E01`) → ZIP → evidence_root**

The adapter drives Velociraptor's dead-disk remapping on the analysis server,
so you never run anything on the original media:

```bash
python3 -m dfir_collector_adapter --source image \
    --input /evidence/disk.E01 --output ./case-001/evidence_root --case-id case-001
python3 analyze.py --evidence ./case-001/evidence_root --case-id case-001 --max-iterations 25
```

Notes:

- The adapter writes `evidence_root/manifest.json` (SHA-256 index +
  `source_members` provenance) as the chain-of-custody seed; Agentic-DFIR
  continues that chain in `audit.jsonl`.
- Real cases need more iterations than the bundled demos — start around
  `--max-iterations 25`. That is also the current default ceiling of
  `analyze.py`; the agent stops on its own once it has enough to report, so the
  ceiling only caps runaway loops.
- `--context TEXT` prepends an initial lead (for example `'data exfil suspected
  around 2026-03-15'`) to the agent's brief as a starting hypothesis, not as
  ground truth. It is intended for `--evidence` runs; the bundled benchmarks
  ignore it to measure cold-start capability.
- `--case-id` labels the run; when omitted it defaults to the evidence
  directory's parent name. Output goes to `out/custom/<case-id>/<timestamp>/`.
- Full collection detail (which Velociraptor artifacts to use per OS, shipping
  responder binaries, the `--source image` limitations) is in the
  [collector-adapter README](https://github.com/Juwon1405/agentic-dfir-collector-adapter#readme).

## Mounting your case as read-only

This is the most important discipline in the operator workflow when you point
the low-level commands at an existing evidence tree. The agent never writes to
the evidence tree by construction — every path goes through `_safe_resolve`,
and there is no `write_file` / `mount` / `execute_shell` on the MCP wire — so a
read-only mount is belt-and-braces rather than the thing the safety depends
on. Use it anyway: it is the one layer the OS kernel enforces, independent of
this code base (see [Threat model](./threat-model.md)).

### From an E01 / disk image

```bash
sudo mkdir -p /mnt/case-evidence
sudo mount -o ro,loop /path/to/case.dd /mnt/case-evidence
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence
```

For an `.E01`, expose it as a raw image first with `ewfmount` (from
`ewf-tools` / `libewf-tools`), then loop-mount the raw file the same way — or
skip the manual mount entirely and let the collector adapter's `--source image`
path produce an `evidence_root/` as shown above.

### From an extracted directory

```bash
sudo mkdir -p /mnt/case-evidence
sudo mount --bind -o ro /path/to/extracted /mnt/case-evidence
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence
```

### From an artifact-collector ZIP

A Velociraptor offline-collector ZIP goes through the collector adapter
(`--source zip`, above), which produces the `evidence_root/` and its
`manifest.json`. If you collected with another triage tool, extract first,
then bind-mount as above.

### Verifying the mount

```bash
mount | grep case-evidence
# Should show 'ro' in the options

touch /mnt/case-evidence/test 2>&1
# Should fail with: "Read-only file system"
```

If the touch succeeds, **stop**. The mount is not read-only and the OS-level
guarantee does not hold for this run.

## Running the agent

### Deterministic mode (no API key)

```bash
# Evidence root is set via env var (not a CLI flag)
export DFIR_EVIDENCE_ROOT=/mnt/case-evidence

python3 -m dfir_agent --case CASE-2026-001 \
                     --out ./out/case-2026-001 \
                     --max-iterations 25
```

`--case` is the run label recorded in the audit log; `--out` is the output
directory; `--mode deterministic` is the default. The deterministic mode runs
the senior-analyst loop using the bundled playbook and does not call any
external service. It is suitable for CI, repeatability checks, and for
environments where network egress is forbidden. It is a scripted analyst, not
LLM reasoning — detection-skill numbers come from live runs.

### Live mode (real Claude API)

Live mode connects an actual LLM to the typed MCP surface. The MCP boundary
still applies — the model can only call functions that exist on the surface.
The user-facing entry point is `analyze.py` (live only; it fails fast without
a key):

```bash
export ANTHROPIC_API_KEY='sk-...'
python3 analyze.py --case self-evaluation/case-01              # a bundled case
python3 analyze.py --evidence ./case-001/evidence_root --case-id case-001   # your evidence
python3 analyze.py --model claude-sonnet-4-6 --case self-evaluation/case-01
```

The default model is `claude-haiku-4-5-20251001`; override with `--model` or
the `DFIR_MODEL` environment variable. The lower-level equivalent is
`python3 -m dfir_agent --mode live --case X --out DIR [--model M] [--prompt P]`,
and `--dry-run` runs the same MCP plumbing with a scripted stand-in for Claude
(no key, no network).

The same MCP server can be registered in Claude Code and driven interactively:

```bash
claude mcp add agentic-dfir -s user -- python3 -m dfir_mcp.server_stdio
```

Example calls with the real argument names are in
[Live mode](./live-mode.md#registering-dfir-mcp-with-claude-code); see the same
page for the full integration, including how the
agent loop runs on top of live MCP rather than the deterministic stub, the
credential options, and token-usage accounting.

## Reading the output

A completed `python3 -m dfir_agent` run writes three files into the `--out`
directory:

```
<out>/report.json      Final hypothesis, findings with audit_id citations, MITRE chain
<out>/audit.jsonl      SHA-256 chained step-by-step trace (one entry per MCP call)
<out>/progress.jsonl   Iteration-by-iteration hypothesis, confidence and open gaps
```

`analyze.py` (live mode only) writes `findings.json` (typed findings: id,
confidence, evidence summary), `report.json` and `summary.json` (run
metadata: model, evidence_root, usage) under `out/<tier>/<case-id>/<timestamp>/`,
plus the live-mode record `live_summary.json`, `live_tool_calls.jsonl` (one
line per MCP call) and `live_transcript.txt`. `audit.jsonl` and
`progress.jsonl` are written by `python3 -m dfir_agent` in deterministic mode. The committed reference run is
[`examples/out/ref-01/`](../examples/out/ref-01/).

### Verifying the audit chain

```bash
python3 -m dfir_audit verify <out>/audit.jsonl
# -> chain verified: <entry-count> entries, tail=<sha256-prefix>...
```

This re-hashes every entry and checks the chain. Tampering with any
entry — by the agent, by the operator, by anyone — will fail
verification with a `prev_hash mismatch` or `entry_hash mismatch` line.

### Tracing a finding back to evidence

```bash
python3 -m dfir_audit trace <out>/audit.jsonl F-013
```

`F-013` is the finding ID from `<out>/report.json`. The trace command walks
the audit chain and emits every entry whose `finding_ids` reference that
finding — the underlying MCP calls, which include the file path and byte
offset of the source artifact. `python3 -m dfir_audit lookup <audit.jsonl>
<audit_id>` returns one entry by id, and `summary` prints chain statistics.

### Reviewing unresolved contradictions

`dfir_corr` keeps its DuckDB store in memory for the duration of a call; there
is no on-disk database to open afterwards. Contradictions reach you two ways:

- as the result of the `correlate_timeline` / `correlate_events` MCP calls,
  recorded verbatim in `audit.jsonl`, each with `"status": "UNRESOLVED"`;
- as the `unresolved` list in `report.json`, which the agent must either
  resolve with additional evidence or carry into the final report with both
  sources cited.

`UNRESOLVED` rows are the reasoning forks the agent had to handle. Reviewing
them is the fastest way to gauge whether the agent's final verdict is sound.
The patterns that produce them are operator-tunable in
[`dfir_corr/correlation-rules.yaml`](../dfir_corr/correlation-rules.yaml)
(see [dfir_corr](../dfir_corr/README.md)).

## Running the tests

```bash
export DFIR_EVIDENCE_ROOT="$PWD/examples/case-studies/self-evaluation/case-01/evidence_root"

# After the editable install above:
python3 -m pytest tests/ dfir_corr/tests/
```

For a PYTHONPATH-only run without installing the packages:

```bash
export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"
pip install duckdb PyYAML python-registry "mcp<2" anthropic requests
python3 -m pytest tests/ dfir_corr/tests/
```

The same suite can also be run file-by-file while debugging:

```bash
python3 tests/test_audit_chain.py                       # chain integrity + tamper detection
python3 tests/test_mcp_surface.py                       # surface is the exact positive set
python3 tests/test_mcp_bypass.py                        # destructive ops are blocked
python3 tests/test_sift_adapters.py                     # v0.5 SIFT adapter layer guarantees
python3 tests/test_agent_self_correction.py             # end-to-end self-correction
python3 tests/test_live_mcp.py                          # JSON-RPC stdio wire tests
python3 tests/test_live_truncation.py                   # live result truncation (24k cap)
python3 tests/test_live_usage_tracking.py               # live token-usage accounting
python3 tests/test_live_findings_extraction.py          # live-mode findings parsed from the final REPORT block
python3 tests/test_evtxecmd_oom.py                      # EvtxECmd OOM-safe streaming reads
python3 tests/test_concurrency_and_edge_cases.py        # concurrent audit writes + path safety
python3 tests/test_qa_pass_regressions.py               # QA-pass regression guard
python3 tests/test_parse_registry_hive.py               # registry hive parsing (v0.5.4 CFReDS gap closure)
python3 tests/test_v05_supply_chain.py                  # cross-platform supply-chain IOC sweeps (v0.6.0)
python3 tests/test_v06_macos_linux.py                   # macOS quarantine + Linux cron + DNS tunneling (v0.6.1)
python3 tests/test_parse_linux_dfir.py                  # Linux text-log + shell-history + cron parsing (v0.7.1)
python3 tests/test_sigma_matcher.py                     # Sigma pack matcher against the real dfir_sigma/ rules (v1.1.0)
python3 tests/test_eval_layout.py                       # tiered case-study layout + analyze.py contracts (no API)
python3 tests/test_download.py                          # offline tests for scripts/eval/download.py
python3 -m pytest dfir_corr/tests/                      # dfir_corr extracted engine

# Or run the whole suite at once (the authoritative count comes from here):
python3 -m pytest tests/ dfir_corr/tests/
```

The full suite passes on a clean checkout once the dependencies above are
installed. The repo also contains `tests/_pending/` — tests for Phase 2
functions not yet on the MCP surface. Those are intentionally not part of the
shipping suite. Test categories and layout notes are in
[`tests/README.md`](../tests/README.md).

## Common operational issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `ToolNotFound: 'parse_X' is not exposed by dfir-mcp` | Function not registered (typo, or a function that is intentionally absent) | `python3 -c "from dfir_mcp import list_tools; print([t['name'] for t in list_tools()])"` |
| `PathTraversalAttempt: path escapes evidence root` | Path arg tried to leave the evidence tree | Check the offending tool call's input — likely a `..` or absolute path |
| Audit chain verify fails (`prev_hash mismatch` / `entry_hash mismatch`) | The audit log was edited (or written by a non-`dfir_audit` writer) | Re-run; do not edit `audit.jsonl` by hand |
| Agent loops at max-iterations without convergence | Hypothesis is too underspecified for the typed tools | Increase `--max-iterations`, or give a more specific lead with `--context` |
| `dfir_corr` returns no contradictions on a known dirty case | Time-proximity window too tight | Tune `window_seconds` in `dfir_corr/correlation-rules.yaml` |

The longer list, one section per symptom, is in
[Troubleshooting](./troubleshooting.md).

## Performance notes from the field

- A SIFT VM with 8 GB RAM completes the bundled IP-KVM case in ~14 seconds
  (deterministic mode), ~90 seconds (live mode with an earlier Claude Sonnet
  release, 3.7).
- Large MFT correlations (5M+ rows) finish in 3-6 seconds with DuckDB if the
  host has SSD. On HDD, count on 10x.
- Memory overhead is dominated by parsed MFT in DataFrame form; ~600 MB for a
  5M-row MFT. Free that immediately after `dfir_corr` ingests it
  (`del df; gc.collect()`).

## What the agent will *not* do for you

- **It will not modify, quarantine, or block anything.** Supervised response
  is a later roadmap phase (see [Roadmap](./roadmap.md)); the current surface
  is read-only.
- **It will not contact external services in deterministic mode.** No TI
  lookups, no IP-WHOIS, no VirusTotal hits. If you want enrichment, pipe
  `audit.jsonl` to your own enrichment tooling.
- **It will not give you a confident verdict on out-of-corpus cases.** The
  accuracy report is calibrated against the bundled corpus — 8
  self-evaluation cases and 3 external datasets. Anything outside those is
  reported with whatever the loop converges on, which may be wrong. Treat
  low-confidence verdicts as low-confidence.

## See also

- [Quick start](./QUICKSTART.md) — the copy-paste version of this page
- [Running on the SIFT Workstation](./running-on-sift.md) — the SIFT-specific setup
- [Troubleshooting](./troubleshooting.md) — issues already seen and how they were resolved
- [Live mode](./live-mode.md) — credentials, agent loop over live MCP, usage accounting
- [Threat model](./threat-model.md) — what "read-only" means at each layer
- [Architecture](./architecture.md) — the five packages and the data flow between them
