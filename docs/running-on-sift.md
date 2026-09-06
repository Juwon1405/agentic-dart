# Running on the SIFT Workstation

A short setup guide for getting Agentic-DFIR running on a SANS SIFT Workstation
VM — from a fresh SIFT image to a verified run against your own evidence. It is
the SIFT-specific version of the [Operator guide](./operator-guide.md); the
commands are the same, the notes are about what SIFT already provides and where
its defaults get in the way.

## Why SIFT is the primary target

SANS SIFT Workstation v22.04 is the de-facto open-source DFIR distribution,
used by every SANS FOR-class student and most working analysts. It ships with:

- The forensic toolchain Agentic-DFIR expects (Volatility, Plaso, Eric Zimmerman
  tools, hindsight)
- Mounted-evidence conventions (`/mnt/case-evidence`, read-only by default)
- Python 3.10+

The project is primarily validated on SIFT v22.04. Other Linux distros work;
this is just the most reproducible path. The 25 SIFT adapters on the MCP
surface (12 Volatility 3, 9 Eric Zimmerman tools, 2 YARA, 2 Plaso) shell out
to these binaries; when one is missing the adapter fails loudly with
`SiftToolNotFoundError` and the 48 native parsers keep working
(see [SIFT adapter layer](./sift-adapter-layer.md)).

## Step 1 — Get SIFT

If you don't have it, download it from https://www.sans.org/tools/sift-workstation/.
It is a large VM image; VMware, VirtualBox, and Parallels images all work.

Default user: `sansforensics` (SIFT) — we'll create / use `analyst` for
Agentic-DFIR so the prompt matches the documentation:

```bash
sudo adduser analyst
sudo usermod -aG sudo analyst
su - analyst
```

(Or just stay as `sansforensics`. The docs reference `analyst@siftworkstation`
for visual consistency, not as a hard requirement.)

## Step 2 — Install Agentic-DFIR

The installer installs into whatever Python environment is active (it never
forces a private venv — activate one first if you want isolation), clones and
installs the collector adapter as a sibling checkout, stages a SHA-256-verified
Velociraptor binary, and adds the SIFT toolchain (yara, Volatility 3, Plaso)
and the Eric Zimmerman Tools. It has no options other than `--help`; it checks
each step and skips what SIFT already provides:

```bash
cd ~
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir
bash scripts/install.sh
```

Run it as your normal user, not with `sudo` — the installer refuses a root run
(see the [Operator guide](./operator-guide.md#fresh-clone-install) for why).

The installer ends with an API-free health check and a table of which SIFT
adapter binaries resolve on this host. You can re-run both anytime:

```bash
python3 scripts/healthcheck.py
python3 scripts/check_sift_tools.py
```

## Step 3 — Authenticate

```bash
export ANTHROPIC_API_KEY='sk-...'
```

Only live analysis needs this; the offline demo and the test suite run without
it. Other credential options are in [Live mode](./live-mode.md).

## Step 4 — Run the bundled demo and a case

```bash
# Offline demo — no credentials needed (full loop + audit chain + bypass test)
bash examples/demo-run.sh

# A real evaluation case (needs the auth from Step 3)
python3 analyze.py --case self-evaluation/case-01
```

Offline-demo output ends with the architectural bypass proof:

```
[dfir-agent] audit chain: chain verified: 3 entries, tail=<sha256-prefix>...
[demo] PASS — "ToolNotFound: 'execute_shell' is not exposed by dfir-mcp"
```

The demo writes to `examples/out/demo/`; the committed reference run
[`examples/out/ref-01/`](../examples/out/ref-01/) is left untouched. The full
expected output and stills from a live run are in
[Quick start](./QUICKSTART.md#a-test-mode-no-api-key).

## Step 5 — Run the full test suite

```bash
export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"
python3 -m pytest tests/ dfir_corr/tests/
```

After the editable install the `PYTHONPATH` export is optional; it is what
makes the suite run from a bare checkout too.

## Step 6 — Run against your own case

The incident host gets **nothing installed** — it runs the Velociraptor
**offline collector** (one standalone binary, one execution) and produces an
`evidence.zip` you copy back here. On this analysis server, convert it to an
`evidence_root/` and analyse it with `analyze.py --evidence`:

```bash
# A) from a Velociraptor collection ZIP shipped from the incident host
python3 -m dfir_collector_adapter --source zip \
    --input evidence.zip --output ./case-001/evidence_root --case-id case-001

# B) or from a forensic disk image (dead-disk, processed here — not on the host)
python3 -m dfir_collector_adapter --source image \
    --input /path/to/case.E01 --output ./case-001/evidence_root --case-id case-001

# then analyse (real cases want more iterations than the bundled demos;
# 25 is also analyze.py's default ceiling)
python3 analyze.py --evidence ./case-001/evidence_root --case-id case-001 --max-iterations 25
```

The agent never writes to the evidence tree — that guarantee is architectural
(every path goes through `_safe_resolve`, and there is no `write_file` /
`mount` / `execute_shell` on the MCP wire), so a read-only mount is belt-and-
braces rather than the thing the safety depends on. The collector commands to
run on the incident host, the `manifest.json` chain-of-custody seed, and the
`--context` lead option are explained in the
[Operator guide](./operator-guide.md#real-world-investigations-your-own-evidence).

## Step 7 — Look at what came out

Each run writes a timestamped directory:

```
out/<tier>/<case-id>/<timestamp>/
├── findings.json         typed findings (id, confidence, evidence summary)
├── report.json           full run report + primary hypothesis
├── summary.json          run metadata (model, evidence_root, usage)
├── live_summary.json     iterations, tool_call_count, token usage
├── live_tool_calls.jsonl one line per MCP call: iteration, tool, input
└── live_transcript.txt   the model's final narrative
```

`<tier>` is `self-evaluation`, `external-evaluation`, or `custom` for
`--evidence` runs. The SHA-256-chained `audit.jsonl` and the per-iteration
`progress.jsonl` are written by the deterministic runner
(`python3 -m dfir_agent --mode deterministic`, which is what the demo uses);
how live calls are recorded is in [Live mode](./live-mode.md#outputs).

Verify the audit chain of the demo run:

```bash
python3 -m dfir_audit verify examples/out/demo/audit.jsonl
# -> chain verified: 3 entries, tail=<sha256-prefix>...
```

Tracing a finding back to the MCP call that produced it, and reviewing the
`UNRESOLVED` contradictions, are covered in
[Reading the output](./operator-guide.md#reading-the-output).

## Common SIFT-specific gotchas

| Symptom | Fix |
|---|---|
| `ImportError: dfir_mcp` | `export PYTHONPATH="$PWD/dfir_audit/src:$PWD/dfir_mcp/src:$PWD/dfir_agent/src:$PWD/dfir_corr/src"` — or re-run `bash scripts/install.sh` from the same shell (and venv) you run from |
| Slow MFT correlation | SIFT VMs default to 4 GB RAM. Bump to 8 GB for >2M-row MFTs. |
| `PathTraversalAttempt` error | One of your tool args has a `..` or absolute path. Check the call inputs. |
| Verify says `mismatch` | Audit log was edited. Re-run; never edit `audit.jsonl` by hand. |
| A SIFT adapter raises `SiftToolNotFoundError` | The backing binary is not on `PATH`. Run `python3 scripts/check_sift_tools.py`; point the adapter at an existing binary with the matching `DFIR_*_BIN` variable (for example `DFIR_VOLATILITY3_BIN`, `DFIR_YARA_BIN`, `DFIR_MFTECMD_BIN`). |

More symptoms, one section each, are in [Troubleshooting](./troubleshooting.md).

## See also

- [Operator guide](./operator-guide.md) — distro-agnostic version of this guide
- [Quick start](./QUICKSTART.md) — the copy-paste path
- [SIFT adapter layer](./sift-adapter-layer.md) — how the 25 adapters wrap the SIFT toolchain
- [Platform support](./platform-support.md) — which functions apply to which evidence OS
- [Architecture](./architecture.md)
