# Contributing to Agentic-DART

Agentic-DART's architecture — especially the MCP surface — is deliberately
minimal. Contributions that expand what the agent can CALL require
extra scrutiny; contributions that expand what the agent can SEE are
welcomed.

## Ways to contribute

- **New playbook YAML** — add a sequencing profile for a case class
  (LOTL, ransomware staging, etc.) under `dart_playbook/`. No Python
  change required.
- **New typed MCP function** — add a parser under `dart_mcp/`. Must
  be read-only, must use `_safe_resolve`, must have a Pydantic/JSON
  schema, must include a bypass test.
- **New IP-KVM / remote-hands signature** — extend `IP_KVM_VID_PID` in
  `dart_mcp/src/dart_mcp/__init__.py`. Include a CVE, advisory, or
  observed-in-wild reference in the PR description.
- **Documentation and cases** — case studies under
  `examples/case-studies/` following the pattern of
  `case-01-ipkvm-insider/`.

## What we will not accept

- Any function that writes to the evidence tree
- Any function whose MCP schema is missing
- `execute_shell`, `eval`, or any equivalent general-purpose escape
- Contributions that move guardrails from architecture to prompt

## PR checklist

- [ ] `tests/test_mcp_surface.py` still passes (surface drift check)
- [ ] `tests/test_mcp_bypass.py` still passes
- [ ] If you added an MCP function, `tests/test_mcp_bypass.py`
      `test_surface_is_exact_positive_and_negative_set` is updated
- [ ] If you touched the agent loop,
      `tests/test_agent_self_correction.py` still passes
- [ ] `python3 scripts/measure_accuracy.py` still produces recall ≥ prior
