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

## Competition-period contribution policy (through 2026-06-15)

This repo is an active submission to the
[SANS FIND EVIL! 2026 hackathon](https://findevil.devpost.com/)
through **2026-06-15**. To keep authorship attribution clean for
the judging panel during this window, contribution acceptance is
narrower than usual:

- ✅ **Accepted**: small, focused PRs against issues that carry
  the `good-first-issue` label *without* `post-sans` (typically
  CI / packaging / typo / documentation drift fixes).
- ⏸️ **Deferred**: any issue carrying the `post-sans` label.
  These are intentionally held until after the deadline. If you
  comment offering to work on a `post-sans` issue, expect a
  polite decline and a re-invitation in mid-June.
- ❌ **Not accepted during this window**: new MCP functions,
  playbook YAML changes, dart_agent loop modifications, dart_mcp
  surface expansions. These are core IP areas.

After 2026-06-15 the policy reverts to standard OSS — `post-sans`
labels will be dropped, `good-first-issue` will be re-applied
where appropriate, and architectural PRs will be reviewed on
merit. If you opened a `post-sans` issue comment in good faith
during this window, thank you for your patience — please come
back in mid-June and ping the same issue.

### Maintainer post-window checklist (2026-06-19)

For the maintainer's reference — actions to run on the day the
judging window opens (submission frozen; contribution restrictions
can lift):

- [ ] Re-add `good-first-issue` to issues #4, #30, #35, #38, #40
- [ ] Ping `@Tanayqq` on issue #40 inviting the wiki PR
- [ ] Drop `post-sans` label on completed issues (#43 detection
      patterns, #44 v3 framework runtime activation)
- [ ] Update this `CONTRIBUTING.md` section — replace the dated
      policy with standard OSS contribution flow
- [ ] Update README's "Acknowledgments" section as new
      contributors land
- [ ] Re-run `scripts/measure_accuracy.py` after issues #43
      and #44 land, update Phase-1 release-history baseline
