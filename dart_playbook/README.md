# dart-playbook

YAML sequencing rules for the senior-analyst loop. Operator-tunable; lives outside the model prompt.

## Bundled playbooks

- **`senior-analyst-v1.yaml`** — initial playbook, targeting insider-threat and DPRK IT-worker patterns. Compact (128 lines), 4 phases.
- **`senior-analyst-v2.yaml`** ⭐ — comprehensive senior-analyst methodology (845 lines, 10 phases). Synthesizes:
  - Mandiant M-Trends 2026 + Targeted Attack Lifecycle
  - SANS PICERL + Lockheed Cyber Kill Chain + David Bianco's Pyramid of Pain & Hunting Maturity Model
  - MITRE ATT&CK Enterprise v16 + Diamond Model + F3EAD
  - The DFIR Report 2024–2026 case studies (BlackSuit, Akira, Fog, Lynx, BlueSky)
  - Field practice from Sean Metcalf, Sarah Edwards, Patrick Wardle, Hal Pomeranz, Eric Zimmerman, Andrew Case, Florian Roth, JPCERT/CC

  Covers 10 case classes: insider-threat, ransomware-recovery-denial, vishing, exploit, third-party, cloud-hybrid, division-of-labour-handoff, identity-centric, remote-hands, LotL.

  v2 is the recommended playbook for any new case in 2026.

## Schema

```yaml
version: 2
target_case_classes: [...]
posture:                    # M-Trends priors (dwell time, attacker speed)
sequence:                   # Phase definitions with rationale, MCP calls, exit criteria
next_call_decisions: [...]  # State → tool routing
contradiction_triggers: [...]  # When dart-corr flags UNRESOLVED
stop_conditions: [...]      # When to emit findings
references: {...}           # Every claim is grounded in a published source
```

See `senior-analyst-v2.yaml` for the canonical shape.

## Forking for your case class

1. Copy `senior-analyst-v2.yaml` to `dart_playbook/<your-name>-v1.yaml`
2. Update `target_case_classes` and `next_call_decisions`
3. Add environment-specific `contradiction_triggers`
4. Run with `--playbook dart_playbook/<your-name>-v1.yaml`

The architectural guarantees (read-only MCP boundary, audit chain, contradiction enforcement) apply to every playbook. Forking cannot loosen them.
