# Case Study 01 — IP-KVM Remote-Hands Insider Pattern

**Scenario class:** Insider threat with remote-hands physical access vector
**Evidence:** `examples/sample-evidence/` (bundled, reproducible)
**Command:** `bash examples/demo-run.sh`
**Expected runtime:** under 5 seconds on any Python 3.10+ host

## The attack pattern

An IP-KVM (KVM-over-IP) device is an out-of-band remote-access appliance
that emulates a USB keyboard, mouse, and display. Physical insertion of
an IP-KVM into a workstation gives an outside actor keyboard-and-mouse
access to the locked session — often indistinguishable from the
legitimate user's activity in application-layer logs alone.

The diagnostic is in the **timeline**: the IP-KVM's USB insertion
signature arrives seconds to minutes BEFORE the operator logon it
enabled. That temporal ordering is what Agentic-DART looks for.

## How Agentic-DART walks the case

### Iteration 1 — Timeline reconstruction

The agent calls `get_amcache()` and surfaces an unusual binary first-
executed shortly after the reported logon.

- Finding F-001 recorded with confidence 0.55
- One audit entry chained (audit_id resolves via `dart-audit trace F-001`)

### Iteration 2 — Hypothesis formation

Two competing hypotheses are written to `progress.jsonl`:

- **H-primary (0.55):** Unauthorized interactive login followed by unusual binary execution
- **H-alt     (0.25):** Legitimate admin maintenance activity

The playbook forbids the agent from concluding on Amcache-only evidence.
Cross-source validation is required.

### Iteration 3 — Cross-source validation via USB history

The agent calls `analyze_usb_history()`. The correlation engine flags
**one UNRESOLVED contradiction**:

```
rule:           ip_kvm_precedes_logon
usb_event:      { ts: 2026-03-15 14:19:47, vid: 0557, pid: 2419 (ATEN) }
logon_event:    ~14:22 (3 minutes later)
severity:       high
status:         UNRESOLVED
```

The agent is architecturally forbidden from smoothing this over. It
MUST address the contradiction or declare it unreachable.

### Iteration 4 — Self-correction

The agent widens the USB parser time window and re-correlates.
The contradiction is confirmed: the IP-KVM insertion is real and the
operator logon came 3 minutes later. The primary hypothesis is
**replaced**, not reinforced:

- **H-primary (0.82):** Remote-hands insider access via IP-KVM; operator credentials misused
- **H-alt     (0.05):** Legitimate admin maintenance — now contradicted by F-013

A second audit entry is chained, also tagged with F-013.

### Iteration 5 — Finalization

The structured report is emitted. `dart-audit verify` confirms the
chain is intact. `dart-audit trace F-013` resolves in ≤3 clicks to
the two underlying `analyze_usb_history` calls.

## What makes this diagnostically useful

The same Amcache finding (F-001) in isolation would support either
hypothesis. The USB timeline is the **falsifying evidence** that only
fits one. This is why Agentic-DART structures the loop around cross-source
validation — not because it produces prettier reports, but because it
refuses to conclude on confirmation-only evidence.

## What the judges should run

```bash
# Full reproduction
bash examples/demo-run.sh

# Measured accuracy (recall, FP rate, hallucination count)
python3 scripts/measure_accuracy.py

# Audit chain integrity
python3 -m dart_audit verify examples/out/find-evil-ref-01/audit.jsonl

# Trace from finding to raw evidence (the "3 clicks" claim)
python3 -m dart_audit trace examples/out/find-evil-ref-01/audit.jsonl F-013
python3 -m dart_audit trace examples/out/find-evil-ref-01/audit.jsonl F-001

# Bypass tests — architectural guardrails
python3 tests/test_mcp_bypass.py
```

All of the above run in under 10 seconds combined.
