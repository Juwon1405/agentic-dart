# dfir_sigma — consolidated Sigma detection pack (versioned)

Sigma rules are **detection signatures**: declarative patterns that say "if an
event matches this shape, raise an alert." They are distinct from the playbook.

| | role | when it acts |
|---|---|---|
| **Playbook** (`dfir_playbook/`) | the *investigation methodology* — phase order, which tools to call, when to form hypotheses, plus technique-classification guidance | drives the agent loop end-to-end |
| **Sigma pack** (`dfir_sigma/`) | *detection signatures* — point patterns that flag a specific known-bad event shape | applied to parsed events by the `match_sigma_rules` MCP tool |

The playbook decides *how to investigate* and how to *classify* what's found; a
sigma rule decides *whether one specific event matches a known-bad pattern*. A
mature SOC keeps both, versioned separately, because they change for different
reasons (methodology vs. new threat patterns).

## Structure — one consolidated, versioned pack (not per-case files)

```
dfir_sigma/
  pack.yml                 # manifest: version (v1, v2…), sources, rules_dir
  rules/
    initial_access_hid_device_insertion.yml      # T1200  (IP-KVM / BadUSB)
    persistence_suspicious_scheduled_task.yml     # T1053.005
    credential_access_kerberoasting.yml           # T1558.003
    lateral_movement_remote_exec.yml              # T1021.002 (PsExec/WMIexec)
```

Rules are **general behavioural patterns**, sourced from / modelled on reputable
public detection content (SigmaHQ's 3000+ rules, detection.fyi). They match on
event *shape* — an HID/keyboard device class, a `schtasks` action referencing a
script interpreter, an RC4 Kerberos TGS — **never** a specific case's answer
(no hardcoded VID/PID, hostname, or task name). The matcher therefore corroborates
without leaking: feeding it the parsed events and seeing which signatures fire is
exactly what a SOC analyst does at the console.

Versioning mirrors the playbook: bump `version` in `pack.yml` and add/revise
rules over time. The matcher loads the highest-version pack. To extend, drop a
new general rule into `rules/` and (when the semantics warrant) cut `v2`.

## The matcher

`match_sigma_rules` (registered in `dfir_mcp`, native tool) loads this pack and
evaluates each rule's `detection` block against a JSONL event log under
`evidence_root`, returning the matches with their MITRE technique tags. It
supports the sigma subset these packs use: named selections combined by a
parenthesis-free `condition` (`A`, `A and B`, `A or B`), field equality and the
`|contains` / `|startswith` / `|endswith` modifiers, and list-of-maps OR. It is
a corroboration tool, not a full sigma backend.

## Why these rules are NOT in any case's evidence_root

An earlier build shipped a sigma rule *inside* a case's `evidence_root/`. That
leaked: the evidence inventory the agent sees would list a file whose name and
contents point straight at the verdict. The cases are scored on reconstructing
the incident from RAW evidence via the tools — so detection signatures live here
and are *applied as a tool*, never planted as a clue.

Note: this is different from `dfir_corr/correlation-rules.yaml`, which drives
`correlate_timeline`'s cross-source contradiction detection — a separate live
mechanism.
