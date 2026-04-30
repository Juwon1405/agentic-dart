# Troubleshooting

## Installation

### `curl ... install.sh | bash` fails

- Confirm outbound HTTPS to `raw.githubusercontent.com` and `github.com`
- Re-run with verbose output: `curl -fsSL <url> | bash -x`
- Alternative: `git clone https://github.com/Juwon1405/agentic-dart.git && cd agentic-dart && bash scripts/install.sh`

### Python version mismatch

Agentic-DART targets Python 3.11+. Check:

```bash
python3 --version
```

If the SIFT Workstation default is older, use pyenv or a system-level install.

### `ANTHROPIC_API_KEY` not set

`dart-agent` talks to Claude through Claude Code, which reads this environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Runtime

### `ToolNotFound: execute_shell` (or similar)

This is **by design**. Agentic-DART does not expose `execute_shell`. Destructive or unconstrained functions are not part of the MCP surface. If the agent attempts to call one, the call fails. This is one of the system's architectural guardrails — not a bug.

### Agent hits `--max-iterations` cap

The iteration controller exits cleanly with a structured closeout report listing:

- The current hypothesis
- Confidence score at termination
- Unresolved gaps
- Suggested next steps

This is also by design. Runaway execution is worse than a bounded early exit.

### Context-window exhaustion

`dart-mcp` pre-parses tool output and returns cursor-paginated JSON. If context exhaustion still occurs:

- Reduce `--max-iterations`
- Narrow the time window on `extract_mft_timeline`
- Split the case into per-artifact runs and combine reports

### MCP server not connected in Claude Code

```bash
claude mcp list
```

If `dart-mcp` is not listed, re-run the registration step:

```bash
claude mcp add dart-mcp --transport stdio --command dart-mcp-server
```

## Evidence

### SHA-256 mismatch at finalization

This indicates evidence was modified during the run. Agentic-DART aborts the report. Check:

- Was the evidence path mounted `ro,noload`?  `mount | grep evidence`
- Did another process on the workstation touch the mount?
- Is the disk itself healthy?  `dmesg | tail`

If all three check out and the mismatch persists, open a GitHub issue with the `audit.jsonl` excerpt.

### Agent cannot read an evidence file

Check ownership and mode on the mount. `ro,noload` prevents writes, not reads. If reads are also failing, the mount options are likely stricter than intended.

## Reporting issues

Open an issue at https://github.com/Juwon1405/agentic-dart/issues with:

- `audit.jsonl` excerpt (last 20 entries)
- `progress.jsonl` (full file)
- Relevant portion of stderr
- SIFT Workstation version (`cat /etc/os-release`)
