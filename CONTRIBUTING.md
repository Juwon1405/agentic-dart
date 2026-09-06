# Contributing to Agentic-DFIR

Agentic-DFIR's architecture — especially the MCP surface — is deliberately
minimal. Contributions that expand what the agent can CALL require
extra scrutiny; contributions that expand what the agent can SEE are
welcomed.

## Ways to contribute

- **New playbook YAML** — add a sequencing profile for a case class
  (LOTL, ransomware staging, etc.) under `dfir_playbook/`. No Python
  change required.
- **New typed MCP function** — add a parser under `dfir_mcp/`. Must
  be read-only, must use `_safe_resolve`, must have a Pydantic/JSON
  schema, must include a bypass test.
- **New IP-KVM / remote-hands signature** — extend `IP_KVM_VID_PID` in
  `dfir_mcp/src/dfir_mcp/__init__.py`. Include a CVE, advisory, or
  observed-in-wild reference in the PR description.
- **Case studies** — new bundled cases under `examples/case-studies/`
  following the pattern of `self-evaluation/case-01/`. The layout,
  the `truth.json` schema and validation, scoring, and what the PR
  needs to carry are in
  [`docs/writing-case-studies.md`](./docs/writing-case-studies.md).
- **Documentation** — every page lives under [`docs/`](./docs/README.md)
  (one page per topic, indexed in `docs/README.md`); each package
  documents itself in its own `README.md`. Fix or extend the existing
  page rather than adding a parallel one.

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
- [ ] `python3 -m scripts.eval.demo` still produces recall ≥ prior

## AI-assisted contributions

AI-assisted or automated PRs are reviewed on the same terms as
human-authored ones. Add a one-line disclosure in the PR body that
the contribution is automated or AI-assisted. The architecture
checklist above still applies in full.
