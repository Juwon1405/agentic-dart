# dart_sigma — Sigma detection rules (separate, versioned)

Sigma rules are **detection signatures**: declarative patterns that say "if an
event matches this shape, raise an alert." They are distinct from the playbook.

| | role | when it acts |
|---|---|---|
| **Playbook** (`dart_playbook/`) | the *investigation methodology* — what order to look in, which tools to call per phase, when to form hypotheses | drives the agent loop end-to-end |
| **Sigma rules** (`dart_sigma/`) | *detection signatures* — point patterns that flag a specific known-bad event shape (a USB VID/PID, a task action) | matched against parsed events, one rule at a time |

The playbook decides *how to investigate*; a sigma rule decides *whether one
specific event is suspicious*. A mature SOC keeps both, versioned separately,
because they change for different reasons (methodology vs. new threat patterns).

## Why these live here and NOT in any case's evidence_root

These rules were previously shipped inside `examples/.../case-01/evidence_root/
sigma-rules/`. That was wrong: the evidence inventory the agent sees would then
list a file whose name and contents point straight at the answer (e.g. "USB
insertion → T1200"), which is a hint the agent shouldn't get. The cases are
scored on detecting the incident from *raw* evidence (setupapi logs, Amcache,
task definitions) using the MCP tools — never from a bundled detection rule.
So the rules were removed from evidence and preserved here as the detection
asset they are.

## Status

Authoring + storage only. A sigma *matcher* (apply these against parsed events
inside the agent loop) is not yet wired — see `tests/_pending/
test_sigma_matcher.py`. Until then these are reference signatures, versioned
here so they can mature independently of the playbook and the cases.

Note: this is different from `dart_corr/correlation-rules.yaml`, which IS live —
that pack drives `correlate_timeline`'s cross-source contradiction detection.
