# Demo Screencast — Production Storyboard

**Target deliverable:** ~3-minute screencast video for SANS FIND EVIL! 2026 Devpost submission.
**Recording environment:** SANS SIFT Workstation OVA running in VirtualBox/VMware.
**Audio:** Voiceover narration in English (or your preference). Keep it conversational; no slide-deck cadence.
**Recording tool suggestions:** OBS Studio (free, cross-platform), or Loom for quick capture.

---

## Pre-recording checklist

- [ ] Fresh SIFT Workstation VM booted, terminal open
- [ ] `juwon@siftworkstation:~$` shell prompt visible (matches `yushin@siftworkstation` design choice — that's intentional brand consistency, leave as-is)
- [ ] Terminal font sized large enough that 1080p capture is readable (e.g., 16-18pt)
- [ ] Browser open in second monitor with: GitHub repo, Devpost page (so you can demonstrate hyperlinks if needed)
- [ ] `ANTHROPIC_API_KEY` exported in shell (for live mode segment, if included)
- [ ] All other apps closed; no notifications on screen

---

## Scene-by-scene outline

### Scene 1 — Cold open (0:00 → 0:15) — 15 seconds

**Action:** Black terminal. Type:

```bash
cat << 'EOF'
Agentic-DART
Architecture-first autonomous DFIR.
61 read-only MCP tools. Zero destructive operations possible.
EOF
```

**Voiceover:**

> "Agentic-DART is an autonomous DFIR agent built on the SANS SIFT
> Workstation. It exposes sixty typed, read-only forensic tools to Claude
> Code through a custom MCP server. The agent cannot run shell commands,
> cannot write files, cannot mount partitions — not because we asked it
> not to, but because those functions don't exist on the wire."

---

### Scene 2 — One-line install (0:15 → 0:45) — 30 seconds

**Action:** Run the install script.

```bash
curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash
```

**Camera:** Don't speed up. Let the script run in real-time. The 7 stages
each print colored headers — that's the show.

**Voiceover during runtime:**

> "One-line install on a clean SIFT Workstation. The script verifies
> Python, clones the repo, installs the dart_mcp package, and probes
> the SIFT toolchain — Volatility 3, MFTECmd, EvtxECmd, PECmd, RECmd,
> AmcacheParser, YARA, log2timeline, psort. Whichever binaries are on
> PATH get wired up automatically; missing ones get clear env-var
> override hints. Then it verifies that exactly sixty MCP tools are
> registered: thirty-five native plus twenty-five SIFT adapters."

**Pause point:** When the script prints

```
[ok] MCP surface verified: 36 native + 25 SIFT adapters = 61 tools
```

freeze the cursor for 1 second so the viewer reads it.

---

### Scene 3 — The architectural boundary (0:45 → 1:30) — 45 seconds

**Action:** Show the bypass tests pass.

```bash
cd ~/agentic-dart
source .venv/bin/activate
python3 tests/test_mcp_bypass.py
```

Then:

```bash
python3 tests/test_sift_adapters.py
```

**Voiceover:**

> "Most agentic DFIR tools are a system prompt that asks an LLM to
> behave. We removed the ability to misbehave. The bypass test suite
> verifies that destructive operations — execute_shell, write_file,
> mount, eval — are not registered, and that path-traversal attempts
> against EVIDENCE_ROOT are blocked at the MCP boundary itself.
> The SIFT adapter test suite verifies the same guarantees hold for
> all twenty-five subprocess wrappers. Adding tools didn't weaken
> the boundary."

**Pause point:** When `test_sift_adapters.py` prints
`✓ All SIFT adapter tests passed` — freeze for 1 second.

---

### Scene 4 — The SIFT adapter demo (1:30 → 2:15) — 45 seconds

**Action:** Run the SIFT adapter demo end-to-end.

```bash
bash examples/sift-adapter-demo.sh
```

**Camera:** Let it run. The five sections each print colored headers
that read out loud.

**Voiceover during runtime:**

> "The SIFT adapter demo proves the wire-up end-to-end. Section one:
> all sixty tools register. Section two: the script probes for SIFT
> binaries — on a clean VM all nine are there. Section three: every
> adapter family is invoked against sample evidence and either runs
> the underlying SIFT tool or fails gracefully through
> SiftToolNotFoundError. Section four: path-traversal attacks
> against the SIFT layer are still blocked. Section five: the
> NEGATIVE surface — the things the agent must never be able to
> do — is verified empty."

**Pause point:** Final summary box prints. Freeze for 2 seconds.

---

### Scene 5 — Live agent run (2:15 → 2:55) — 40 seconds — OPTIONAL

This scene is OPTIONAL. Include only if Anthropic API key is configured
and you have time. If skipped, extend Scene 4 narration.

**Action:**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export DART_EVIDENCE_ROOT="$PWD/examples/sample-evidence"
export PYTHONPATH="$PWD/dart_audit/src:$PWD/dart_mcp/src:$PWD/dart_agent/src"
python3 -m dart_agent --case find-evil-live-demo --mode live --max-iterations 8 --out /tmp/live-demo-out
```

(`--case` takes a case-ID string, not a path. Evidence is mounted via the `DART_EVIDENCE_ROOT` env var, identical to how `examples/demo-run.sh` works.)

**Camera:** Show the agent's iterations stream by. The agent will:
- Call typed forensic tools
- Form hypotheses
- Hit a contradiction (because sample evidence is engineered to contain one)
- Self-correct
- Emit a final REPORT JSON

**Voiceover:**

> "Live mode against the Anthropic API. The agent runs the
> senior-analyst playbook — eleven-hundred-and-eighty-two lines of
> YAML synthesizing M-Trends 2026, MITRE ATT&CK v16, the Diamond
> Model, F3EAD, and the Pyramid of Pain. It builds a timeline,
> hits a contradiction, refines its hypothesis, and produces a
> report. Every tool call is SHA-256 hashed into a tamper-evident
> audit chain."

**Pause point:** REPORT JSON appears. Freeze for 2 seconds.

---

### Scene 6 — Audit chain verification (2:55 → 3:15) — 20 seconds

**Action:**

```bash
python3 -m dart_audit verify examples/out/find-evil-ref-01/audit.jsonl
```

Expected output:

```
chain verified: N entries, tail=<sha256-prefix>...
```

**Voiceover:**

> "Every tool call landed in the audit chain. Each entry hashes the
> previous one. Tampering at any step breaks the chain. The output
> is courtroom-traceable."

---

### Scene 7 — Closing card (3:15 → 3:30) — 15 seconds

**Action:** Type:

```bash
clear
echo "Agentic-DART"
echo "github.com/Juwon1405/agentic-dart"
echo ""
echo "  61 read-only MCP tools  (36 native + 25 SIFT adapters)"
echo "  SHA-256 audit chain"
echo "  Custom MCP Server pattern (Pattern 2)"
echo "  Submission for SANS FIND EVIL! 2026"
```

**Voiceover:**

> "Sixty read-only tools. Tamper-evident audit chain. The whole
> system is open source, MIT licensed, and reproducible from a
> clean clone in under a minute. Repo link is on screen. Thank you."

---

## What NOT to do during recording

- **Do not say "let me show you" or "as you can see"** — show, don't narrate the act of showing.
- **Do not apologize** for anything (slow runs, typos, unexpected output). Re-record instead.
- **Do not zoom in/out during recording** — distracting on playback. Set zoom once, leave.
- **Do not narrate during long-running commands** beyond what's scripted — silence is fine, viewers can read the output.
- **Do not include sensitive data** in any prompt or filename. (`yushin@siftworkstation` is fine — that's intentional. Real evidence files with attacker IPs / hashes / company names are NOT.)

---

## Post-recording

- [ ] Trim cold open to start sharply at the typing animation
- [ ] Add fade-to-black at end (1 second)
- [ ] Export at 1080p, H.264, 8 Mbps minimum bitrate
- [ ] Upload to YouTube as **unlisted** (Devpost prefers YouTube embeds)
- [ ] Paste the YouTube URL into Devpost's "Demo Video" field
- [ ] Cross-post to LinkedIn after submission deadline (good for personal brand, won't spoil judging)

---

## Backup plan if SIFT VM is uncooperative

If the SIFT Workstation OVA throws issues during recording (Volatility
errors, network glitches, etc.), record the demo on your own dev box
instead. The adapter layer is designed to fail gracefully when binaries
are missing — Scene 4 will show clean `SiftToolNotFoundError` results
which still demonstrate the architectural guarantee. Just adjust the
voiceover for Scene 2 to say "the install script detects which SIFT
binaries are present and which need env-var configuration".

The demo is fundamentally about the **architectural boundary**, not
about whether vol.py is on PATH. Don't chase a demo-environment perfect
state. Ship the recording.

---

## File checksum / submission record

When you record, immediately note:

- Recording date:
- Tool used:
- Output filename + size:
- YouTube URL (after upload):
- Devpost field updated on:

Keep this in your case journal so you can re-link if YouTube takes the
unlisted video down for any reason.
