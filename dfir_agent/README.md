# dfir-agent

Claude Code wrapper. Loads the senior-analyst system prompt, maintains the hypothesis tracker, and runs the iteration controller.

## Responsibilities

- Load playbook YAML from `dfir_playbook/`
- Build the senior-analyst system prompt
- Run the iteration loop with `--max-iterations` hard cap
- Write `progress.jsonl` after every iteration (hypothesis, confidence, unresolved gaps)
- Emit the final analyst-readable report

## Not responsible for

- Security boundaries (those live in `dfir-mcp` + OS mount)
- Tool execution (delegated to `dfir-mcp`)
- Correlation logic (delegated to `dfir-corr`)

## CLI

```bash
export DFIR_EVIDENCE_ROOT=/path/to/evidence_root
python3 -m dfir_agent \
    --case <case-id> \
    --out ./out/<case-id>/ \
    --mode deterministic \
    --max-iterations 10

# live mode (Claude API over MCP stdio); --dry-run swaps in a scripted mock, no key needed
python3 -m dfir_agent --case <case-id> --out ./out/<case-id>/ --mode live [--model <id>] [--dry-run]
```

The playbook is loaded from `dfir_playbook/` by path; the run writes
`audit.jsonl`, `progress.jsonl` and `report.json` into `--out`.

## Status

Implemented — deterministic, live and dry-run modes (see the root README, § Live mode).
