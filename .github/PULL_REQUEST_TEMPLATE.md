<!--
Thanks for opening a PR. The checklist below is intentionally short
but each item exists for a reason. If something doesn't apply to your
change, strike it out (~~like this~~) and explain why.
-->

## What this PR does

<!-- 2-3 sentences. What problem does this solve? -->

## Why now

<!-- One sentence. What forced this? Bug? Hackathon milestone? Idle curiosity? -->

## Type of change

- [ ] Bug fix (existing function returns wrong / crashes / leaks)
- [ ] New MCP function (proposed in an issue first?)
- [ ] Playbook YAML
- [ ] Documentation / case study
- [ ] CI / tooling
- [ ] Refactor (no behavior change)
- [ ] Architecture (boundary, audit chain, agent loop)

## Architecture-first checklist

<!--
The whole project's claim is that guardrails are architectural, not
prompt-based. PRs that move guardrails into the prompt are off-mission
and will not be merged.
-->

- [ ] No new function writes to evidence / disk / network
- [ ] No `execute_shell`, `eval`, or general-purpose escape introduced
- [ ] If MCP surface changed: schema is typed, `_safe_resolve` is used,
      bypass test added in `tests/test_mcp_bypass.py`
- [ ] If audit chain code changed: `tests/test_audit_chain.py` still
      produces the same tail hash on the canonical input

## Test evidence

<!--
Paste the relevant `python3 tests/test_*.py` output here.
Or for measurement PRs, paste the per-tactic numbers before/after.
-->

```
$ python3 tests/test_mcp_surface.py
test_registered_tools_are_exact_set OK
test_destructive_functions_are_not_exposed OK
test_calling_unregistered_function_raises OK
```

## Related issues

<!-- Closes #N, refs #N, etc. -->
