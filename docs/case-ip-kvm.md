# Case study: IP-KVM remote-hands insider

This page walks through the bundled, executable case study — self-evaluation
case-01, the case `bash examples/demo-run.sh` runs and the one the committed
reference run in `examples/out/ref-01/` was produced from. It shows what
`dfir-agent` does at each iteration, what `audit.jsonl` records, how a finding
traces back to the tool call, source artifact and output hash that produced it,
and how the senior-analyst playbook was tuned for this case class. The scenario
is a physical-access insider threat: an IP-KVM appliance inserted into a
workstation gives an outside actor keyboard-and-mouse access under an
operator's credentials, and the case must be made by correlating low-signal
evidence across artifacts rather than by any malware signature.

This is the *original* case the senior-analyst playbook
(`senior-analyst-v1.yaml`) was tuned for. The USB-history rule shown at the end
was first encoded in v1 as a phase-level call and is carried forward in v2 and
v3 (the current default) as a `next_call_decisions` entry.

---

## The scenario

An IP-KVM (KVM-over-IP) device is an out-of-band remote-access appliance that
emulates a USB keyboard, mouse, and display. Physical insertion of an IP-KVM
into a workstation gives an outside actor keyboard-and-mouse access to the
locked session — often indistinguishable from the legitimate user's activity in
application-layer logs alone. The bundled case (`truth.json`,
`case_metadata`) records it as an insider threat with a remote-hands physical
access vector on a Windows host, incident window 2026-03-15 14:19–14:30 UTC.

The challenge for the agent: the actions look legitimate at every individual
artifact. There are no malware signatures, no failed logins, no obvious lateral
movement. The diagnostic is in the **timeline**: the IP-KVM's USB insertion
signature arrives seconds to minutes *before* the operator logon it enabled.
That temporal ordering is what Agentic-DFIR looks for, and it only becomes
visible by **correlating low-signal evidence across artifacts**.

---

## The artifacts

The case runs against the bundled, byte-stable evidence tree at
`examples/case-studies/self-evaluation/case-01/evidence_root/` — a categorized,
read-only tree in the `evidence_root/` shape the agent consumes. The committed
tree holds eight files:

| Path under `evidence_root/` | Consumed by |
|---|---|
| `disk/Windows/INF/setupapi.dev.log` | `analyze_usb_history` — the IP-KVM insertion signature (ATEN VID `0557` PID `2419`) among benign USB noise records |
| `disk/Windows/System32/config/SYSTEM` | `analyze_usb_history` — system hive passed alongside the setupapi log |
| `disk/Windows/AppCompat/Programs/Amcache.hve` | `get_amcache` — first-execution record of the unusual binary |
| `disk/Windows/System32/Tasks/RemoteHandsSync` | `list_scheduled_tasks` — the persistence task |
| `disk/Windows/System32/config/NTUSER.DAT.runkeys.csv` | run-key persistence records |
| `disk/Windows/System32/config/SYSTEM.services.csv` | service install records |
| `disk/Windows/System32/config/SYSTEM.shimcache.csv` | ShimCache execution records |
| `event-logs/unified_events.jsonl` | USB-insert (event 2003) and logon (event 4624) records — the logon side of the `ip_kvm_precedes_logon` join |

The IP-KVM VID/PID pairs `dfir-mcp` recognises live in `IP_KVM_VID_PID` in
`dfir_mcp/src/dfir_mcp/__init__.py`; `CONTRIBUTING.md` explains how to extend
the list.

Ground truth lives in the case's `truth.json` — **5 findings** under
`ground_truth_findings`:

| ID | Category | Claim | Expected function | MITRE |
|---|---|---|---|---|
| F-001 | initial_access | IP-KVM device (ATEN VID 0557 PID 2419) inserted before operator logon | `analyze_usb_history` | T1200 |
| F-002 | execution | Unusual binary first-executed shortly after suspicious logon | `get_amcache` | T1059 |
| F-003 | persistence | Scheduled task `RemoteHandsSync` created for persistence | `list_scheduled_tasks` | T1053.005 |
| F-004 | contradiction_handling | USB insertion vs. logon ordering is UNRESOLVED until cross-source validation | `correlate_events` | — |
| F-005 | audit_chain | SHA-256 audit chain links every MCP call from F-001 through F-004 | — | — |

The run's own finding IDs differ from these: `report.json` labels the Amcache
finding `F-001` and the IP-KVM insertion `F-013`. By claim text, the run's
`F-001` corresponds to ground-truth F-002 and the run's `F-013` to ground-truth
F-001. The reference-run table below uses the run's IDs, because those are what
`audit.jsonl` carries.

---

## What the agent does

Five iterations, as recorded in `examples/out/ref-01/progress.jsonl` and
`audit.jsonl`:

1. **Iteration 1 — timeline reconstruction.** Loads the case context and calls
   `get_amcache()` on `disk/Windows/AppCompat/Programs/Amcache.hve`. Surfaces
   an unusual binary first-executed shortly after the reported logon. Finding
   `F-001` is recorded and one audit entry is chained (`audit_id 7f311676`).

2. **Iteration 2 — hypothesis formation.** Two competing hypotheses are written
   to `progress.jsonl`:
   - **H-primary (0.55):** Unauthorized interactive login followed by unusual binary execution
   - **H-alt (0.25):** Legitimate admin maintenance activity

   The playbook forbids the agent from concluding on Amcache-only evidence.
   Cross-source validation is required.

3. **Iteration 3 — cross-source validation via USB history.** Calls
   `analyze_usb_history()` on `disk/Windows/INF/setupapi.dev.log` plus the
   `SYSTEM` hive with the default window (`audit_id e4f5009a`). The
   correlation engine flags **one UNRESOLVED contradiction**:

   ```
   rule:           ip_kvm_precedes_logon
   usb_event:      { ts: 2026-03-15 14:19:47, vid: 0557, pid: 2419 (ATEN) }
   logon_event:    ~14:22 (3 minutes later)
   severity:       high
   status:         UNRESOLVED
   ```

   The rule is `ip_kvm_precedes_logon` in `dfir_corr/correlation-rules.yaml`:
   a USB IP-KVM insertion followed within 600 seconds by a console logon,
   severity high. The agent is architecturally forbidden from smoothing this
   over. It must address the contradiction or declare it unreachable.

4. **Iteration 4 — self-correction.** The agent widens the USB parser time
   window (`time_window_start 2026-03-01T00:00:00Z`,
   `time_window_end 2026-03-31T23:59:59Z`) and re-runs
   `analyze_usb_history()` (`audit_id 9ec86afe`). The contradiction is
   confirmed: the IP-KVM insertion is real and the operator logon came 3
   minutes later. The primary hypothesis is **replaced**, not reinforced:
   - **H-primary (0.82):** Remote-hands insider access via IP-KVM; operator credentials misused
   - **H-alt (0.05):** Legitimate admin maintenance — now contradicted by F-013

   A second audit entry is chained, also tagged with `F-013`.

5. **Iteration 5 — finalization.** The structured report is emitted with two
   findings, each carrying its `audit_id`s. The `unresolved` list in
   `report.json` keeps the contradiction statement on record: "USB timeline
   contradicts login telemetry: IP-KVM insertion (VID=0557 PID=2419) precedes
   the operator logon by ~3 minutes." `dfir-audit verify` confirms the chain
   is intact (3 entries) and `dfir-audit trace F-013` resolves in three clicks
   to the two underlying `analyze_usb_history` calls.

The same Amcache finding in isolation would support either hypothesis. The USB
timeline is the **falsifying evidence** that only fits one. This is why the
loop is structured around cross-source validation — not because it produces
prettier reports, but because it refuses to conclude on confirmation-only
evidence.

---

## Why this case is good for testing the architecture

- **No malware signatures** — pure behavioral analysis. The agent must reason
  from first principles.
- **Cross-artifact correlation is mandatory** — single-artifact analysis would
  conclude "everything looks normal".
- **Time-proximity matters** — the `dfir-corr` time-window join
  (`ip_kvm_precedes_logon`, 600-second window) is load-bearing.
- **The contradiction is physical** — a USB insertion at 14:19:47 precedes the
  logon it enabled by about three minutes. The contradiction is mechanically
  detectable by `dfir-corr`, not subjective.

---

## Finding → artifact → command → hash (reference run)

Every finding traces to the exact tool call that produced it. Pulled from the
committed reference run
[`examples/out/ref-01/audit.jsonl`](../examples/out/ref-01/audit.jsonl),
produced in deterministic mode with no API key:

| Finding | What it says | Command (MCP tool) | Source artifact | `audit_id` | Output SHA-256 |
|---|---|---|---|---|---|
| **F-001** | Unusual binary first-executed shortly after reported login | `get_amcache` | `disk/Windows/AppCompat/Programs/Amcache.hve` | `7f311676` | `sha256:46a1479e…` |
| **F-013** | IP-KVM device inserted ~3 min before operator logon (remote-hands) | `analyze_usb_history` | `disk/Windows/INF/setupapi.dev.log` + `disk/Windows/System32/config/SYSTEM` | `e4f5009a` → `9ec86afe` | `sha256:560d9655…` |

`F-013`'s two `audit_id`s **are** the self-correction: iteration 3 runs
`analyze_usb_history` with a default window and flags the gap `UNRESOLVED`;
iteration 4 re-runs it with an explicit window and lands the finding. Every
finding carries the `audit_id`s of the MCP calls that produced it, so any claim
in the report traces back to the tool call, source artifact, and output hash.
Resolve `F-013` back to raw evidence yourself with
`python3 -m dfir_audit trace examples/out/ref-01/audit.jsonl F-013`.

Each audit entry also records `iteration`, `prev_hash`, `entry_hash`,
`token_count_in`/`token_count_out` and `ts`. The chain starts from an all-zero
`prev_hash`, and `python3 -m dfir_audit verify examples/out/ref-01/audit.jsonl`
reports `chain verified: 3 entries`. A fresh run reproduces the same tool
sequence, inputs, iteration numbers and finding IDs; the `audit_id`s, entry
hashes and timestamps are generated per run, so yours will differ from the
table.

---

## Measured accuracy

`python3 -m scripts.eval.demo` runs the deterministic case-01 pipeline and
scores it against the two findings its harness expects:

```
[1] accuracy       : recall 100%  TP=['F-001', 'F-013']  FN=[]
    hallucinations : 0 (PASS)
[2] integrity      : evidence unchanged PASS  | audit chain 3 entries
[3] containment    : unregistered destructive call refused PASS
```

Iterations to verdict: 5. Audit chain entries: 3 (verified). The integrity
check hashes every file under the evidence tree with SHA-256 before and after
the run and passes only if nothing changed; the containment check attempts an
unregistered destructive call and passes only if `dfir-mcp` refuses it. This is
a toolchain check on one deterministic case, not a model benchmark. To measure
a model across the bundled or external cases, run `python3 -m scripts.eval.self`
or `python3 -m scripts.eval.external` (see
[`scripts/eval/README.md`](../scripts/eval/README.md)).

---

## Reproducing

```bash
git clone https://github.com/Juwon1405/agentic-dfir.git
cd agentic-dfir

# Full reproduction — deterministic, no API key, under 5 seconds
bash examples/demo-run.sh
```

After the run completes (output lands in `examples/out/demo/`; the committed
reference run in `examples/out/ref-01/` is left untouched):

```bash
# Measured accuracy (recall, hallucination count, integrity, containment)
python3 -m scripts.eval.demo

# Verify chain integrity
python3 -m dfir_audit verify examples/out/demo/audit.jsonl

# Trace a finding back to evidence (the "3 clicks" claim)
python3 -m dfir_audit trace examples/out/demo/audit.jsonl F-013
python3 -m dfir_audit trace examples/out/demo/audit.jsonl F-001

# Bypass tests — architectural guardrails
python3 tests/test_mcp_bypass.py
```

To run the same case with a model in live mode (API key required), use the
primary runner: `python3 analyze.py --case self-evaluation/case-01`.

---

## How the playbook was tuned for this case

`dfir_playbook/senior-analyst-v1.yaml` schedules the USB check as a phase-level
call in its `cross_source_validation` phase:

```yaml
  - phase: cross_source_validation
    rationale: |
      Validate the primary hypothesis against a source that was
      not used to form it. If disk formed the hypothesis, test
      against memory. And vice versa.
    mcp_calls:
      - analyze_usb_history
      - correlate_events
    exit_criteria:
      - contradictions_resolved_or_flagged: true
```

`senior-analyst-v2.yaml` and `senior-analyst-v3.yaml` (the default) carry the
same intent as a `next_call_decisions` rule; v3 additionally tags it with its
MaGMa use-case ID:

```yaml
  - when_state: "case_class includes physical access AND USB not yet checked"
    call: analyze_usb_history
    confidence_gain: 0.15
    magma_uc: AP-008
```

The playbook is the only place the rule "look at USB history early in
physical-access cases" lives. It's data, not Python — operators can fork the
playbook for their own case classes without touching code. Live mode loads the
highest-versioned `senior-analyst-v*.yaml` in `dfir_playbook/` and renders its
phase sequence into the agent's brief; the deterministic analyst used by the
demo runs a fixed phase sequence in code (`DeterministicAnalyst` in
`dfir_agent`), which is what keeps the demo reproducible.

---

## See also

- [Case study: Pass-the-Hash with timestomp pre-existence](./case-pth-timestomp.md) — the conceptual walkthrough
- [`dfir-playbook`](../dfir_playbook/README.md) — how playbooks work
- [`dfir-corr`](../dfir_corr/README.md) — the correlation engine
- [`dfir-audit`](../dfir_audit/README.md) — the audit-chain entry schema behind `verify` and `trace`
- [Writing case studies](./writing-case-studies.md) — how to add a new bundled case
- [Case library](../examples/case-studies/README.md) — all eleven bundled cases
