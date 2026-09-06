# SIFT Workstation adapter layer

This page is the reference for the **SIFT adapter layer** (`dfir_mcp/sift_adapters/`): the 25 typed, read-only MCP adapters that wrap the SIFT Workstation DFIR toolchain — Volatility 3, the Eric Zimmerman tools, YARA and Plaso — behind the same MCP boundary, with the same architectural guarantees, as the 48 native pure-Python functions. It covers what is exposed, how each adapter resolves its binary, the design contract every adapter must satisfy, and how to verify the layer. The native functions themselves are documented in the [MCP function catalog](./mcp-function-catalog.md); installing and running on a real SIFT box is covered in [Running on SIFT](./running-on-sift.md).

---

## Why the adapter layer exists

The native `dfir_mcp` functions are pure Python: they parse artifacts directly and need nothing installed beyond the package, which keeps a fresh-clone run self-contained. They do not, however, reach the toolchain the SIFT Workstation already ships — Volatility 3, the Eric Zimmerman tools, YARA, Plaso — which is what working analysts use for memory images, raw `$MFT` and EVTX at scale, and super-timelines.

The adapter layer closes that gap without changing the boundary. Each adapter is a typed MCP tool registered in the same table as the native functions, so Volatility or MFTECmd output reaches the agent through the same read-only, schema-validated, audit-chained surface: no shell, no raw stdout, no new destructive verb. If a SIFT binary is missing, the adapter raises `SiftToolNotFoundError` and the agent loop falls back to the native pure-Python implementation covering the same artifact. The live-mode system prompt (`dfir_agent.live`) states this rule to the model explicitly — for example, native `get_amcache` instead of `sift_amcacheparser_parse`.

### Why this matters

Wrapping SIFT tools by giving the LLM a shell means the LLM can in principle run `rm -rf` if a prompt injection succeeds. Agentic-DFIR's adapter layer keeps the read-only invariant intact even while wrapping `vol`, `MFTECmd`, `log2timeline`, and friends. **Adding tools did not weaken the boundary.** Because the adapters are optional, Agentic-DFIR works on a fresh clone without SIFT *and* upgrades transparently when run on a real SIFT Workstation.

---

## What's exposed (25 adapters)

The layer was added in v0.5.0. Every adapter carries the `sift_` prefix, so `list_tools()` separates the two layers by name. Counts per tool family, as registered:

| Tool family | Source | Adapters |
|---|---|:---:|
| **Volatility 3** | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) v2.27 | 12 |
| **Eric Zimmerman tools** | [EricZimmerman](https://ericzimmerman.github.io/) — MFTECmd 2, EvtxECmd 2, PECmd 2, RECmd 2, AmcacheParser 1 | 9 |
| **YARA** | [VirusTotal/yara](https://github.com/VirusTotal/yara) | 2 |
| **Plaso** | [log2timeline/plaso](https://github.com/log2timeline/plaso) | 2 |
| **Total SIFT adapters** | | **25** |

### Volatility 3 (12 adapters)

Wraps `vol` from Volatility Foundation's Volatility 3, v2.27 (the version on the current SIFT Workstation). All twelve adapters return Volatility's CSV-rendered output parsed into Python dicts; the model never sees the column-aligned text, which is hard to disambiguate when filenames contain spaces. Every adapter takes `image_path`; `sift_vol3_windows_dlllist` also takes an optional `pid`, and `sift_vol3_windows_runkey` an optional `key`.

| Adapter | Plugin | Use case |
|---|---|---|
| `sift_vol3_windows_pslist` | `windows.pslist.PsList` | Active Windows process list (PID, PPID, ImageFileName, offset, threads, handles, session, Wow64, create/exit time) |
| `sift_vol3_windows_pstree` | `windows.pstree.PsTree` | Parent-child chain (catch macro execution patterns such as `cmd.exe` parented by `WINWORD.EXE`) |
| `sift_vol3_windows_psscan` | `windows.psscan.PsScan` | **Hidden processes** (DKOM / unlinked `_EPROCESS` — diff vs. pslist) |
| `sift_vol3_windows_cmdline` | `windows.cmdline.CmdLine` | Per-process command lines (`-EncodedCommand`, comsvcs.dll MiniDump, other LotL signatures) |
| `sift_vol3_windows_netscan` | `windows.netscan.NetScan` | Active TCP/UDP connections, sockets, listeners |
| `sift_vol3_windows_malfind` | `windows.malfind.Malfind` | RWX injected code regions (each finding includes the hex-dump start) |
| `sift_vol3_windows_dlllist` | `windows.dlllist.DllList` | Loaded DLLs per process |
| `sift_vol3_windows_svcscan` | `windows.svcscan.SvcScan` | Service install (PsExec lateral movement — random 8-char service names) |
| `sift_vol3_windows_runkey` | `windows.registry.printkey.PrintKey` on `Software\Microsoft\Windows\CurrentVersion\Run` | Run-key persistence |
| `sift_vol3_linux_pslist` | `linux.pslist.PsList` | Linux active processes |
| `sift_vol3_linux_bash` | `linux.bash.Bash` | **In-memory bash history** (recovers wiped `~/.bash_history`) |
| `sift_vol3_mac_bash` | `mac.bash.Bash` | macOS in-memory bash history |

### Eric Zimmerman tools (9 adapters)

Wraps the .NET cross-platform builds of [Eric Zimmerman's tools](https://ericzimmerman.github.io/). The SIFT Workstation bundles them under `/opt/EricZimmermanTools/`; `scripts/install.sh` also stages the .NET 9 single-file builds into `bin/zimmerman/<Tool>/<Tool>` in the repository, where the adapters find them with no environment setup.

| Adapter | Tool | Use case |
|---|---|---|
| `sift_mftecmd_parse` | MFTECmd | Full $MFT to structured rows with both `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps |
| `sift_mftecmd_timestomp` | MFTECmd | $SI < $FN anomaly detection (T1070.006); `tolerance_seconds` (default 1) absorbs clock resolution, `executables_only` narrows to `.exe`/`.dll`/`.ps1` and similar; severity escalates for executables and for deltas over 1 hour |
| `sift_evtxecmd_parse` | EvtxECmd | EVTX (single file or directory) to structured rows — TimeCreated, EventID, Channel, Computer, EventData |
| `sift_evtxecmd_filter_eids` | EvtxECmd | Filtered to the "heavy hitter" EIDs by default — Security 4624 / 4625 / 4634 / 4647 / 4648 / 4672 / 4688 / 4697 / 4698 / 4702 / 4720 / 4732 / 4769 / 5140 / 5145, Sysmon 1 / 3 / 11 / 13, PowerShell 4104; pass `event_ids` to override |
| `sift_pecmd_parse` | PECmd | Prefetch (`.pf`) records with ExecutableName, RunCount, LastRun, PreviousRun0..6, FilesLoaded |
| `sift_pecmd_run_history` | PECmd | Per-executable last-8 runs sorted by RunCount (surfaces "this binary ran 47 times in 2 hours") |
| `sift_recmd_run_batch` | RECmd | Run a batch file — `ASEPs` (default, `RECmd_Batch_MC.reb`: 50+ persistence locations — Run, RunOnce, IFEO, Services, Scheduled Tasks, Winlogon Userinit, AppInit_DLLs), `kroll` (`Kroll_Batch.reb`), `USB`, `All` |
| `sift_recmd_query_key` | RECmd | Targeted registry key query (`key_path`) — all values and subkeys |
| `sift_amcacheparser_parse` | AmcacheParser | Amcache.hve full parse with file SHA-1 (`include_associated_files`, default true) |

### YARA (2 adapters)

Wraps the [YARA](https://github.com/VirusTotal/yara) C binary (pre-installed on SIFT at `/usr/bin/yara`). Both take `rules_path` and run with `fast_mode` on by default; pair them with rule corpora such as The DFIR Report's Yara-Rules, Florian Roth's signature-base, or Mandiant's capa-rules.

| Adapter | Use case |
|---|---|
| `sift_yara_scan_file` | Scan a single file (`target_path`) with a rules file; returns matched rule names |
| `sift_yara_scan_dir` | Recursive directory scan (`target_dir`, optional `max_file_size`); returns `{rule, path}` per match |

### Plaso (2 adapters)

Wraps [log2timeline + psort](https://github.com/log2timeline/plaso) — the heavyweight super-timeline tool.

| Adapter | Use case |
|---|---|
| `sift_plaso_log2timeline` | Generate `.plaso` storage from a disk image / mount / single artifact (`source_path`, written to `output_storage_path` under `DFIR_DERIVED_ROOT`); scope with a comma-separated `parsers` preset such as `mft,evtx,prefetch`. A full-disk run can take hours |
| `sift_plaso_psort` | Filter (`filter_expression`) + render an existing `.plaso` (`storage_path`) to L2T CSV (`output_format` default `l2tcsv`; also `json_line`, `dynamic`) |

Plaso is the one family that needs a persistent derived artifact. `sift_plaso_log2timeline` writes its `.plaso` storage under `DFIR_DERIVED_ROOT` (or a temp-derived root, `<tmp>/agentic-dfir-derived`, when the variable is unset), never inside the evidence root; `sift_plaso_psort` reads storage from either root.

---

## How each adapter resolves its binary

Every adapter resolves its binary through `_which()` in `_common.py`, which follows this order:

1. **Environment variable override** — e.g. `DFIR_VOLATILITY3_BIN=/opt/volatility3/vol.py` — but only when it points at an executable file. A stale or wrong override is ignored with a warning on stderr and resolution falls through, so a leftover `DFIR_*_BIN` never hides a working binary on PATH.
2. **`shutil.which()` lookup on PATH.**
3. **Installer-staged repository bin directories** — `bin/`, `bin/zimmerman/` (EZ Tools land at `bin/zimmerman/<Tool>/<Tool>`), and the sibling collector-adapter checkout's `bin/`, searched up to two levels deep for `<name>`, `<name>.exe`, `<name>.dll`.
4. **`SiftToolNotFoundError`** naming the env var to set and suggesting `scripts/install.sh` to stage the tool.

Override env vars (one per tool):

| Adapter family | Env var |
|---|---|
| Volatility 3 | `DFIR_VOLATILITY3_BIN` |
| MFTECmd | `DFIR_MFTECMD_BIN` |
| EvtxECmd | `DFIR_EVTXECMD_BIN` |
| PECmd | `DFIR_PECMD_BIN` |
| RECmd | `DFIR_RECMD_BIN` |
| AmcacheParser | `DFIR_AMCACHEPARSER_BIN` |
| YARA | `DFIR_YARA_BIN` |
| Plaso | `DFIR_LOG2TIMELINE_BIN` + `DFIR_PSORT_BIN` |

This gives you three deployment options:

- **SIFT Workstation default** — tools at canonical SIFT paths; install Agentic-DFIR and the adapters work. `bash scripts/install.sh` also pip-installs Volatility 3 and Plaso, installs YARA through the package manager, and stages the EZ Tools into `bin/zimmerman/`, skipping whatever is already working.
- **Custom install location** — set the env var per tool.
- **No SIFT** — adapters raise `SiftToolNotFoundError`; the agent loop falls back to native pure-Python implementations.

---

## Architectural contract every adapter must satisfy

This is the contract that makes the SIFT adapter layer non-trivial. Anyone adding a new adapter to `sift_adapters/` must satisfy all six:

### 1. Read-only EVIDENCE_ROOT enforcement

Input paths flow through `safe_evidence_input()` (which delegates to the parent package's `_safe_resolve()`). Path traversal, null bytes, and absolute escapes are blocked before subprocess is invoked. The agent cannot reach `/etc`, `~/`, or anywhere outside `DFIR_EVIDENCE_ROOT` regardless of layer. Derived outputs (Plaso storage) go to `DFIR_DERIVED_ROOT`, not into the evidence tree.

### 2. SHA-256 audit-chain compatibility

Every adapter returns:

```python
{
    "metadata": {
        "tool": "...",
        "<input>_sha256": "<sha256>",   # input file hash, e.g. mft_sha256, image_sha256, target_sha256
        "csv_sha256": "<sha256>",        # output artifact hash (also in output_files)
        "duration_ms": 1234,
    }
}
```

These hashes plug straight into dfir_audit's chain, so downstream evidence integrity is provable across both layers without changing the ledger.

### 3. Subprocess timeout by default

All `run_tool()` calls have a hard timeout. Defaults, from the module constants: 10 min for the small tools (`DEFAULT_TIMEOUT_SECONDS` 600, PECmd, AmcacheParser), 15 min for RECmd, 20 min for Volatility, 30 min for MFTECmd, EvtxECmd directories and YARA directory scans, 1 hour for psort, and 6 hours for log2timeline. `sift_plaso_log2timeline` exposes `timeout_seconds` in its schema so a run can override the default. Commands are passed as argument lists, never as shell strings, so there is no shell interpolation.

### 4. Structured output, not raw stdout

Tool stdout/CSV is parsed into Python dicts before reaching the LLM. The agent never sees raw shell output. This is critical because filenames in evidence may contain attacker-controlled text — feeding raw stdout to the LLM is a prompt-injection vector.

### 5. Graceful degradation

Missing binary → `SiftToolNotFoundError` with the env-var name and install hint. A non-zero exit or a timeout → `SiftToolFailedError` with the stderr tail. Both are typed so the agent loop can catch them and fall back to native pure-Python implementations (for example `extract_mft_timeline` if `sift_mftecmd_parse` is unavailable).

### 6. Schema parity

Each adapter is registered via `@tool(name, description, schema)`. The schema is well-formed JSON Schema with `type: object`, declared `properties`, and `required`. This is verified by `tests/test_sift_adapters.py::test_each_sift_adapter_has_valid_schema`.

---

## Verification

```bash
export PYTHONPATH=dfir_audit/src:dfir_mcp/src:dfir_agent/src:dfir_corr/src

# Tool count — the full typed MCP surface (48 native + 25 SIFT adapters)
python3 -c "from dfir_mcp import list_tools; print(len(list_tools()))"
# → 73

# SIFT-adapter suite: registration, no collision with native names, schema
# validity, path-traversal and null-byte blocking, Plaso derived-root
# placement, clean missing-binary error, and the 25 / 73 counts
python3 -m pytest tests/test_sift_adapters.py -q

# Full surface: exact positive set, forbidden names absent, unregistered call
# raises, advertised schema enforced
python3 -m pytest tests/test_mcp_surface.py tests/test_mcp_bypass.py -q
```

`scripts/healthcheck.py` reports the tool-surface count with its native / SIFT split (among other readiness checks) without needing an API key.

---

## What this does NOT change

- The native pure-Python forensic functions are **untouched**. They remain the fresh-clone path.
- The negative surface (`execute_shell`, `write_file`, `mount`, `umount`, `eval`, etc.) is **unchanged**. No destructive primitive was added — `tests/test_mcp_bypass.py` asserts the same forbidden set for both layers.
- dfir_corr contradiction triggers, the dfir_audit hash chain, and the senior-analyst playbook all work identically — they consume tool outputs by structure, not by which layer produced them.
- MITRE ATT&CK coverage is **deepened**, not broadened: the adapters add depth to tactics the native functions already cover rather than new tactics. See [Platform support](./platform-support.md#mitre-attck-coverage--broad-enterprise-tactic-coverage).

---

## See also

- [Architecture](./architecture.md) — the read-only MCP boundary in detail
- [MCP function catalog](./mcp-function-catalog.md) — every native function with artifact, MITRE mapping and references
- [Platform support](./platform-support.md) — analysis-target matrix and functions by platform
- [Running on SIFT](./running-on-sift.md) — installing and running on the SIFT Workstation
- [FAQ — How is this different from "just give the LLM bash"?](./faq.md#how-is-this-different-from-just-give-the-llm-bash) — the rationale for wrapping tools behind typed adapters
- [dfir-mcp package README](../dfir_mcp/README.md)
