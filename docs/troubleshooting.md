# Troubleshooting

Known issues and their resolutions, one section per symptom, grouped by where
they show up: installation, runtime, evidence handling. Each entry says what the
message means, whether it is a fault or a designed refusal, and the fix. For the
normal setup path see [Quick start](./QUICKSTART.md); for the explained version
see the [Operator guide](./operator-guide.md).

## Installation

### `scripts/install.sh` fails or reports a warning

- Run it as your normal user. The installer refuses to run under `sudo` / as
  root: a root run resolves packages against root's environment (so the final
  health check reports dependencies "missing" even when they are installed for
  your user) and leaves root-owned files in the repo that break `git pull`.
  If a previous root run already did that, fix ownership with
  `sudo chown -R <your-user> .` and re-run.
- Confirm outbound HTTPS to `github.com` (both repositories), `pypi.org`
  (Python packages), `download.ericzimmermanstools.com` (EZ Tools) and the
  Velociraptor release host.
- The installer is idempotent — re-running it is always safe and only redoes
  the steps that failed. When a step fails or warns, its per-step logs are kept
  under `/tmp/dfir-install.*` and the path is printed at the end; read the
  tail of the failing step's log first.
- The installer needs `apt-get`, `dnf`, or `yum` for the OS base packages
  (`python3 python3-pip git curl unzip sleuthkit` plus `ewf-tools` /
  `libewf-tools`). On another package manager install those by hand, then
  re-run; the step is skipped once the binaries are present.

### Python version mismatch

Agentic-DFIR targets Python 3.10 or newer (CI runs 3.10 – 3.13). Check:

```bash
python3 --version
```

If the SIFT Workstation default is older, use pyenv or a system-level install.
`python3 scripts/healthcheck.py` performs the same check as its first step.

### Installing inside a virtual environment (optional)

The installer and every entry-point script run against your current Python
interpreter. They neither create nor require a virtualenv. If you prefer to
keep Agentic-DFIR's dependencies isolated, create and activate one *before*
installing, then run everything from that activated shell:

```bash
python3 -m venv .venv
source .venv/bin/activate
bash scripts/install.sh           # installs into the activated venv
python3 analyze.py --case self-evaluation/case-01
```

The key rule is consistency: install and run with the *same* interpreter.
If you install inside a venv, keep that venv activated when you run
`analyze.py`, `scripts/healthcheck.py`, or the benchmark scripts.

### `ImportError: No module named dfir_mcp` (or `dfir_audit`, `dfir_agent`, `dfir_corr`)

The packages are not importable from the interpreter you are using. Either
install them (`bash scripts/install.sh`, from the same shell and venv you run
from) or, for a PYTHONPATH-only run from a bare checkout:

```bash
export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"
```

### `No module named dfir_mcp.server_stdio`

The agent launches `dfir_mcp` as an MCP subprocess using the *same* Python
that started the run. This error means the packages were installed into a
different interpreter than the one you invoked. Fix it by installing and
running with one interpreter — e.g. re-run `bash scripts/install.sh` from
the same shell (and the same activated venv, if any) you use to launch
`analyze.py`.

### `Velociraptor binary not found` (external benchmarks)

`--source image` needs the Velociraptor binary staged by the collector
adapter. Re-run the adapter's installer, which downloads and SHA-256-verifies
it into `./bin/`:

```bash
( cd ../agentic-dfir-collector-adapter && bash scripts/install.sh )
```

Then re-run the benchmark. Alternatively, point the adapter at an existing
binary with `DFIR_VELOCIRAPTOR_BIN=/path/to/velociraptor` or
`--velociraptor-bin /path/to/velociraptor`. (`--source zip` does not need
Velociraptor at all.)

### A SIFT adapter raises `SiftToolNotFoundError`

The 25 SIFT adapters shell out to external binaries (yara, `vol`, MFTECmd, …).
`scripts/healthcheck.py` only confirms that the adapters are *registered*, not
that their backing binaries are installed. Run
`python3 scripts/check_sift_tools.py` for an available / missing table, install
the missing tool (or re-run `bash scripts/install.sh`, which stages yara,
Volatility 3, Plaso and the EZ Tools), or point the adapter at an existing
binary with the matching `DFIR_*_BIN` override (`DFIR_VOLATILITY3_BIN`,
`DFIR_YARA_BIN`, `DFIR_MFTECMD_BIN`, `DFIR_EVTXECMD_BIN`, `DFIR_PECMD_BIN`,
`DFIR_RECMD_BIN`, `DFIR_AMCACHEPARSER_BIN`, `DFIR_LOG2TIMELINE_BIN`,
`DFIR_PSORT_BIN`). A missing binary is not fatal: the native `dfir_mcp` tools
still work.

### Live mode credentials

For real Claude calls, export an Anthropic API key before running live mode:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

`analyze.py` is live-only and fails fast — before any expensive work — when the
key is unset. For CI or offline reproduction, use `python3 -m dfir_agent
--case test --out /tmp/out --mode live --dry-run` instead of providing
credentials. Dry-run still
exercises the MCP subprocess, stdio handshake, and real tool calls with a
scripted mock model. Other credential options are in [Live mode](./live-mode.md).

## Runtime

### `ToolNotFound: 'execute_shell' is not exposed by dfir-mcp` (or similar)

This is **by design**. Agentic-DFIR does not expose `execute_shell`.
Destructive or unconstrained functions are not part of the MCP surface. If the
agent attempts to call one, the call fails with this `KeyError`. This is one of
the system's architectural guardrails — not a bug. `bash examples/demo-run.sh`
ends by provoking exactly this message as its bypass test.

### `ToolNotFound: 'parse_X' is not exposed by dfir-mcp` for a function you expected

Either a typo, or the function is not on the surface (for example something in
`tests/_pending/` that is not shipped yet). List what is registered:

```bash
python3 -c "from dfir_mcp import list_tools; print([t['name'] for t in list_tools()])"
```

The catalog with one line per function is
[MCP function catalog](./mcp-function-catalog.md).

### `PathTraversalAttempt: path escapes evidence root`

One of the tool call's path arguments tried to leave the evidence tree — a
`..` component, an absolute path, a null byte, or a path longer than 1024
characters. Every path goes through `_safe_resolve`, which resolves it against
`DFIR_EVIDENCE_ROOT` and refuses anything that lands outside. Check the
offending call's inputs; paths are always relative to the evidence root.

### Agent hits `--max-iterations` cap

The iteration controller exits cleanly with a structured closeout report listing:

- The current hypothesis
- Confidence score at termination
- Unresolved gaps
- Suggested next steps

This is also by design. Runaway execution is worse than a bounded early exit.
If a real case keeps hitting the cap without converging, the hypothesis is too
underspecified for the typed tools: raise `--max-iterations` (the `analyze.py`
default is 25), or give the agent a more specific lead with
`analyze.py --context '...'`.

### Context-window exhaustion

`dfir-mcp` pre-parses tool output and returns cursor-paginated JSON. If context exhaustion still occurs:

- Reduce `--max-iterations`
- Narrow the time window on `extract_mft_timeline`
- Split the case into per-artifact runs and combine reports

### `dfir_corr` returns no contradictions on a known dirty case

The time-proximity window is too tight for the artifacts involved. The
patterns are operator-tunable without touching Python: adjust `window_seconds`
(per rule, or the `correlate_timeline` default of 300 s) in
[`dfir_corr/correlation-rules.yaml`](../dfir_corr/correlation-rules.yaml).

### Slow MFT correlation

SIFT VMs default to 4 GB RAM. Bump to 8 GB for MFTs above 2M rows; 5M+ row
correlations take 3-6 seconds on SSD and roughly 10x that on HDD. See
[Performance notes from the field](./operator-guide.md#performance-notes-from-the-field).

### MCP server not connected in Claude Code

```bash
claude mcp list
```

If `agentic-dfir` is not listed, re-run the registration step:

```bash
claude mcp add agentic-dfir -s user -- python3 -m dfir_mcp.server_stdio
```

## Evidence

### Audit chain verification fails (`prev_hash mismatch` / `entry_hash mismatch`)

`python3 -m dfir_audit verify <out>/audit.jsonl` re-hashes every entry and
checks the SHA-256 chain. A mismatch means the log was edited after it was
written — by anyone — or was produced by a writer other than `dfir_audit`.
Re-run the case; never edit `audit.jsonl` by hand.

### `evidence unchanged FAIL` from `python3 -m scripts.eval.demo`

The demo scorer hashes every file under the case-01 evidence tree before and
after the deterministic run and exits 1 if any digest differs. The agent itself
never writes into the evidence root, so a mismatch means something else on the
workstation touched it. Check:

- Was the evidence path mounted `ro,noload`?  `mount | grep evidence`
- Did another process on the workstation touch the mount?
- Is the disk itself healthy?  `dmesg | tail`

If all three check out and the mismatch persists, open a GitHub issue with the `audit.jsonl` excerpt.

### Agent cannot read an evidence file

Check ownership and mode on the mount. `ro,noload` prevents writes, not reads. If reads are also failing, the mount options are likely stricter than intended.

## Reporting issues

Open an issue at https://github.com/Juwon1405/agentic-dfir/issues with:

- `audit.jsonl` excerpt (last 20 entries)
- `progress.jsonl` (full file)
- Relevant portion of stderr
- SIFT Workstation version (`cat /etc/os-release`)

Security-relevant reports follow [`SECURITY.md`](../SECURITY.md) instead.

## See also

- [Quick start](./QUICKSTART.md)
- [Operator guide](./operator-guide.md)
- [Running on the SIFT Workstation](./running-on-sift.md)
- [Live mode](./live-mode.md)
- [FAQ](./faq.md)
