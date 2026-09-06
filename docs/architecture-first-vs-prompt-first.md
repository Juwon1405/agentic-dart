# Architecture-first vs prompt-first

This is the central design claim of the project, and this page states it, shows what the prompt-first alternative looks like and why it fails, describes what architecture-first means concretely in Agentic-DFIR, walks through the bypass test that makes the claim executable, and records what architecture cannot do. The concern-by-concern table against a prompt-first baseline agent is in [`comparison.md`](./comparison.md#the-agentic-dfir-thesis--where-it-differs-from-a-prompt-first-agent) and is not repeated here.

## The claim

> *Safety properties of an LLM agent should be enforced by the **shape of what it can call**, not by **what we tell it not to do**.*

## What "prompt-first" looks like (and why it fails)

A prompt-first agent looks like this:

```
You are a forensic analyst. You MUST NOT modify any evidence.
You MUST NOT execute shell commands. You MUST NOT write to disk.
You have access to a tool called `query_evidence(sql)` that
runs arbitrary SQL against the case database.
```

The failure mode is obvious to anyone who has watched an LLM under time pressure:

1. The agent sees a hard problem.
2. The system prompt is far away in the context.
3. The MCP surface offers `query_evidence(sql)`.
4. The agent emits `query_evidence("UPDATE findings SET ...")` because, mechanically, that is a thing the surface can do.
5. The "MUST NOT" was a guideline. The MCP server didn't actually stop it.

Prompt-first safety is **convention**. Any sufficiently motivated agent — or a confused one, or one that got bad training data, or a prompt-injected one — will defeat it.

## What "architecture-first" looks like

An architecture-first agent looks like this:

- The MCP surface is exactly the typed function set, by name — 48 native forensic functions plus 25 SIFT Workstation adapters, 73 tools in total. They are read-only by construction. The list is in [`mcp-function-catalog.md`](./mcp-function-catalog.md).
- `execute_shell`, `write_file`, `mount`, `eval`, `exec`, `spawn`, `system`, `os.system`, `subprocess.run` — none of them exist on the surface.
- Trying to call any of them produces `ToolNotFound`. Verified by an explicit bypass test ([`tests/test_mcp_bypass.py`](../tests/test_mcp_bypass.py)).
- The evidence directory is mounted **read-only at the OS level**. Even if a function in `dfir-mcp` had a bug, the mount would refuse the write.
- Every call goes through `_safe_resolve`, which rejects path-traversal attempts (`..`, absolute paths outside the evidence root, NUL bytes, over-long paths) and raises `PathTraversalAttempt`. The evidence root is `EVIDENCE_ROOT`, read from the `DFIR_EVIDENCE_ROOT` environment variable.

The agent **cannot** modify evidence — not because the prompt told it not to, but because **the function does not exist and the filesystem is mounted ro**.

That's the difference. A guarantee, not a guideline.

## The bypass test, concretely

[`tests/test_mcp_bypass.py`](../tests/test_mcp_bypass.py) actively tries to bypass each of the architectural guarantees. The first test calls every destructive name an agent might emit and requires a hard failure:

```python
def test_unregistered_destructive_function_raises_ToolNotFound():
    """Calling anything not in the registry must fail hard."""
    for forbidden in ["execute_shell", "write_file", "mount", "umount",
                      "network_egress", "eval", "exec_python",
                      "delete_file", "system"]:
        try:
            call_tool(forbidden, {})
        except KeyError as e:
            assert "ToolNotFound" in str(e), f"wrong error for {forbidden}"
            continue
        raise AssertionError(
            f"SECURITY: call_tool({forbidden!r}) did not raise — "
            f"forbidden function is somehow exposed")
```

The same file also asserts that:

- relative path traversal (`../../../etc/passwd`, `disk/../../../../etc/hosts`) raises `PathTraversalAttempt`;
- absolute paths outside the evidence root (`/etc/passwd`, `/root/.ssh/authorized_keys`) raise `PathTraversalAttempt`;
- a NUL byte smuggled into a path (`disk/Amcache.hve\x00/etc/passwd`) raises `PathTraversalAttempt`;
- the registered surface is an exact set — both the positive set (every function that must be registered) and the negative set (every name that must never be) are asserted, so any drift in either direction fails the test.

This is not a code-coverage test. It is the architectural claim made executable. Every PR that lands on `main` must pass this. Any contribution that adds a function to the MCP surface must add a corresponding bypass test; see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Why this matters for reviewers

Anyone can write a system prompt that says "be safe". Architectural guarantees are testable. Reviewers don't have to take the project's word that the agent is read-only — they can clone the repo, run `bash examples/demo-run.sh`, and watch the bypass test fire on the way through: the demo script ends by calling `execute_shell` against the MCP registry and printing the `ToolNotFound` error it gets back.

## What architecture cannot do

Honest accounting:

- **Architecture cannot prevent the agent from drawing wrong conclusions.** That's an accuracy concern, not a safety one. `dfir-corr` and the playbook help, but the agent can still be confidently wrong. Measuring that is what `scripts/eval/` is for; see [`scripts/eval/README.md`](../scripts/eval/README.md).
- **Architecture cannot prevent leakage.** If a tool legitimately reads data and the agent puts it in the report, the data is in the report. Confidentiality is a separate concern, addressed by what evidence you choose to mount.
- **Architecture cannot self-update.** New attack patterns require new tools. Phase 2 — Sigma synthesis — is partly about closing this gap by giving the agent a way to *propose* new detections without granting it write access to existing ones. See [`about-the-name.md`](./about-the-name.md#phase-2--agentic-detection-engineering).

## See also

- [`tests/test_mcp_bypass.py`](../tests/test_mcp_bypass.py) — the bypass test
- [`dfir_mcp/README.md`](../dfir_mcp/README.md) — the typed surface, its schema, and `_safe_resolve`
- [`threat-model.md`](./threat-model.md) — what is in scope and what is not
- [`comparison.md`](./comparison.md) — the prompt-first baseline versus Agentic-DFIR, concern by concern
- [`overview.md`](./overview.md) — the design principle in the context of the whole project
