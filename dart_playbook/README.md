# dart-playbook

Senior-analyst sequencing rules, expressed as YAML. Community-extensible.

## Why YAML

Because the sequencing logic of a senior analyst is not Python. It is a small set of decisions about what to look at first, when to stop and challenge yourself, and what constitutes "enough" to form a hypothesis. Encoding those as YAML lets another responder contribute their own senior-analyst DNA without touching the codebase.

## Contents

- `senior-analyst-v1.yaml` — initial playbook, targeting insider-threat and DPRK IT-worker patterns

## Contributing

Fork, add a new YAML playbook under a descriptive filename, and open a PR. The playbook must include:

- A `target_case_class:` block
- An ordered `sequence:` of phases (volatile → timeline → anomaly → hypothesis → validate → report)
- A `self_challenge:` block describing when to stop and question the current hypothesis
- A `termination:` block defining what "done" looks like

See `senior-analyst-v1.yaml` for the canonical shape.
