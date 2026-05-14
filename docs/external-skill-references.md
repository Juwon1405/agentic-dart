# External skills reference — Anthropic-Cybersecurity-Skills

The community-maintained [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) library (754 skills, Apache-2.0) follows the [agentskills.io](https://agentskills.io) open standard. Agentic-DART's `dart_mcp` and `dart_playbook` were developed independently, but the two converge on similar primitives. This document tracks the candidates we will evaluate for future absorption (`Phase 2` and beyond) so contributors can see *what is already covered* vs *what could be ported*.

## How to read this table

- **Phase mapping** — which Agentic-DART playbook phase the skill maps to (`senior-analyst-v3.yaml`).
- **Status** — `covered` (we already have a native equivalent), `candidate` (worth porting), `consider` (lower priority).
- **Notes** — what specifically would need to land if absorbed.

## P0 — scope_and_volatility

| Skill | Status | Notes |
|---|:-:|---|
| `collecting-volatile-evidence-from-compromised-host` | candidate | RFC 3227 ordering helper for the Live workflow. Pair with collector-adapter. |
| `acquiring-disk-image-with-dd-and-dcfldd` | consider | Pre-collection step; not part of the analysis surface. |

## P1 — initial_access_vector_triage

| Skill | Status | Notes |
|---|:-:|---|
| `analyzing-supply-chain-malware-artifacts` | **covered** | Six v0.6 functions (`scan_pth_files_for_supply_chain_iocs` et al.) ported from yushin-mac-artifact-collector. |
| `detecting-typosquatting-packages-in-npm-pypi` | **covered** | `detect_pypi_typosquatting` (v0.6, Levenshtein-based). |
| `detecting-supply-chain-attacks-in-ci-cd` | candidate | GitHub Actions workflow scanner. Useful sibling to `detect_nodejs_install_hooks`. |
| `hunting-for-supply-chain-compromise` | **covered** | All 6 v0.6 supply-chain functions together. |
| `analyzing-web-server-logs-for-intrusion` | **covered** | `analyze_web_access_log` + `detect_webshell`. |
| `analyzing-email-headers-for-phishing-investigation` | candidate | Email header parser. Phase 2 candidate (current playbook is host-centric). |
| `performing-adversary-in-the-middle-phishing-detection` | consider | EvilProxy / Modlishka pattern detection; needs IDP log integration. |

## P2 — timeline_reconstruction

| Skill | Status | Notes |
|---|:-:|---|
| `analyzing-windows-amcache-artifacts` | **covered** | `get_amcache` (native). |
| `analyzing-windows-prefetch-with-python` | **covered** | `parse_prefetch` (native). |
| `analyzing-mft-for-deleted-file-recovery` | **covered** | `extract_mft_timeline` + SIFT `sift_mftecmd_parse`. |
| `analyzing-windows-shellbag-artifacts` | **covered** | `parse_shellbags` (native). |
| `analyzing-lnk-file-and-jump-list-artifacts` | candidate | Native LNK parser would close a small gap. |
| `analyzing-prefetch-files-for-execution-history` | **covered** | Same as `parse_prefetch`. |
| `performing-timeline-reconstruction-with-plaso` | **covered** | `sift_plaso_log2timeline` + `sift_plaso_psort` adapters. |
| `building-incident-timeline-with-timesketch` | candidate | UI for the analyst, not the agent. Forensics-platform companion repo territory. |

## P3 — anomaly_surfacing

| Skill | Status | Notes |
|---|:-:|---|
| `detecting-living-off-the-land-attacks` | candidate | LOLBin / LOLBAS detector. Phase 2 priority — pairs well with playbook P3. |
| `detecting-living-off-the-land-with-lolbas` | candidate | Specific LOLBAS pattern matcher. |
| `hunting-for-living-off-the-land-binaries` | candidate | Hunt mode (broader than detect). |
| `hunting-for-persistence-mechanisms-in-windows` | **covered** | `detect_persistence` (native). |
| `hunting-for-registry-run-key-persistence` | **covered** | Subset of `detect_persistence`. |
| `hunting-for-scheduled-task-persistence` | **covered** | `list_scheduled_tasks` + `detect_persistence`. |
| `hunting-for-startup-folder-persistence` | **covered** | Subset of `detect_persistence`. |
| `detecting-wmi-persistence` | candidate | WMI subscription is a known gap. |
| `hunting-for-persistence-via-wmi-subscriptions` | candidate | Same. |
| `analyzing-persistence-mechanisms-in-linux` | **covered** | `parse_systemd_journal`, `parse_auditd_log`. |
| `analyzing-malware-persistence-with-autoruns` | consider | Sysinternals-specific; Velociraptor artifact more portable. |

## P5 — kill_chain_assembly

| Skill | Status | Notes |
|---|:-:|---|
| `detecting-credential-dumping-techniques` | **covered** | `detect_credential_access`. |
| `detecting-pass-the-hash-attacks` | **covered** | Subset of `detect_credential_access` + `analyze_windows_logons`. |
| `detecting-pass-the-ticket-attacks` | **covered** | `analyze_kerberos_events`. |
| `detecting-kerberoasting-attacks` | **covered** | `analyze_kerberos_events`. |
| `detecting-golden-ticket-forgery` | **covered** | `analyze_kerberos_events` (RC4 + sid mismatch). |
| `detecting-dcsync-attack-in-active-directory` | candidate | Event ID 4662 specialization. |
| `detecting-lateral-movement-in-network` | **covered** | `detect_lateral_movement`. |
| `detecting-lateral-movement-with-splunk` | consider | Splunk-specific; out of scope for native MCP. |
| `detecting-lateral-movement-with-zeek` | candidate | Zeek log parser would extend Phase 2 network coverage. |
| `hunting-for-dcom-lateral-movement` | candidate | MMC20.Application / ShellWindows specialization. |
| `hunting-for-lateral-movement-via-wmi` | **covered** | Subset of `detect_lateral_movement`. |
| `extracting-iocs-from-malware-samples` | candidate | Phase 2 candidate (current playbook does not malware-analyze samples). |
| `automating-ioc-enrichment` | candidate | Phase 3 (agentic SOC) — needs TI platform integration. |
| `analyzing-indicators-of-compromise` | **covered** | `correlate_events` + audit chain `source_tool_call`. |

## P6 — contradiction_handling (meta)

| Skill | Status | Notes |
|---|:-:|---|
| `building-threat-hunt-hypothesis-framework` | **covered** | Native to `dart_agent` (Hypothesis state machine). |
| `building-incident-response-playbook` | **covered** | `senior-analyst-v3.yaml` itself (the senior-analyst playbook). |

## P7 — attribution_and_diamond_model

| Skill | Status | Notes |
|---|:-:|---|
| `analyzing-cyber-kill-chain` | **covered** | Playbook P5 explicitly assembles the kill chain. |
| `implementing-diamond-model-analysis` | **covered** | Playbook P7. |
| `mapping-mitre-attack-techniques` | **covered** | MITRE references in every tool description. |

## P8 — recovery_denial_check

| Skill | Status | Notes |
|---|:-:|---|
| `detecting-evasion-techniques-in-endpoint-logs` | **covered** | `detect_defense_evasion`. |
| `hunting-for-shadow-copy-deletion` | candidate | Specific VSS-deletion signature; small primitive. |
| `hunting-for-defense-evasion-via-timestomping` | candidate | Pairs with `extract_mft_timeline` ($STANDARD_INFORMATION vs $FILE_NAME). |

## Collector alignment

| Skill | Status | Notes |
|---|:-:|---|
| `implementing-velociraptor-for-ir-collection` | **covered** | [agentic-dart-collector-adapter](https://github.com/Juwon1405/agentic-dart-collector-adapter) is the operational answer. |

---

## Summary

- **Total candidates surveyed**: 51 (Phase 1 + Phase 2 scope).
- **Already covered by Agentic-DART**: 26.
- **Phase 2 absorption candidates**: 18.
- **Out-of-scope / consider later**: 7.

For the full skill index see https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/index.json.
