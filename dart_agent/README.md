# dart-agent

Claude Code wrapper. Loads the senior-analyst system prompt, maintains the hypothesis tracker, and runs the iteration controller.

## Responsibilities

- Load playbook YAML from `dart-playbook/`
- Build the senior-analyst system prompt
- Run the iteration loop with `--max-iterations` hard cap
- Write `progress.jsonl` after every iteration (hypothesis, confidence, unresolved gaps)
- Emit the final analyst-readable report

## Not responsible for

- Security boundaries (those live in `dart-mcp` + OS mount)
- Tool execution (delegated to `dart-mcp`)
- Correlation logic (delegated to `dart-corr`)

## CLI (draft)

```bash
dart-agent \
    --case <case-id> \
    --image <path-to-disk-image> \
    --memory <path-to-memory-capture> \
    --playbook dart-playbook/senior-analyst-v1.yaml \
    --max-iterations 10 \
    --out ./out/<case-id>/
```

## Status

Scaffolding. First working loop targets end of April 2026.
