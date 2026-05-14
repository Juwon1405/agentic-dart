# Demo Screencast — Production Storyboard v2 (v0.6.1)

**Target deliverable:** ~3-minute screencast for SANS FIND EVIL! 2026 Devpost submission.
**Recording environment:** SANS SIFT Workstation OVA running in VirtualBox/VMware/UTM.
**Audio:** Voiceover in **British English**. Recommended voice — `say -v Daniel` (built into macOS, formal British male) or `say -v Oliver (Premium)` (warmer, more natural). See `voiceover/say_voiceover.sh` for the one-shot synthesis script.
**Recording tool:** OBS Studio (free, cross-platform) or Loom.

---

## Headline numbers — v0.6.1 (locked at recording time)

- **Typed read-only MCP surface:** 70 tools = 45 native pure-Python forensic functions + 25 SIFT Workstation adapters
- **Test suite:** 72 / 72 passing on a fresh clone (CI green on Python 3.10 / 3.11 / 3.12 / 3.13)
- **MITRE ATT&CK enterprise coverage:** 11 / 12 tactics. TA0011 (Command-and-Control) opened in v0.6.1 via `detect_dns_tunneling`. TA0009 (Collection) is collector-side and intentionally out of scope for the analysis engine.
- **Playbook:** ten-phase senior-analyst methodology synthesising Mandiant + Bianco + Diamond + Palantir ADS + MaGMa UCF + TaHiTI hunt cycle
- **Zero destructive operations possible by construction**

Keep slogan **"70 / 72 / 72 / 0"** consistent with the README Hero L259.

---

## Pre-recording checklist

- [ ] Fresh SIFT Workstation VM booted, single terminal full-screen
- [ ] `yushin@siftworkstation:~$` shell prompt visible (intentional brand consistency)
- [ ] Terminal font 16-18pt for 1080p readability
- [ ] Browser on second monitor: GitHub repo + Devpost page open
- [ ] `ANTHROPIC_API_KEY` exported in shell (only if Scene 5 live mode is recorded)
- [ ] All other apps closed, system notifications silenced
- [ ] OBS / Loom set to 1080p @ 30fps, audio off (voiceover added in post)
- [ ] `agentic-dart` already cloned to `~/agentic-dart` and `pip install -e ./dart_mcp/` done — Scene 2 reinstalls fresh to demonstrate, but you don't want first-run latency artefacts

---

## Scene-by-scene outline (target 3:00 ± 0:15)

### Scene 1 — Cold open (0:00 → 0:15) — 15 seconds

**Action.** Black terminal. Type slowly:

```bash
cat << 'EOF'
  Agentic-DART
  Architecture-first autonomous DFIR.
  70 typed read-only MCP tools.
  Zero destructive operations possible.
EOF
```

**Voiceover (British English, calm, ~0.95× speed):**

> Agentic-DART is an autonomous DFIR agent built on the SANS SIFT Workstation.
> It exposes seventy typed, read-only forensic tools to Claude Code through
> a custom MCP server. The agent cannot run shell commands. It cannot write
> files. It cannot mount partitions. Not because we asked it not to — because
> those functions do not exist on the wire.

---

### Scene 2 — One-line install (0:15 → 0:45) — 30 seconds

**Action.** Run the installer on the fresh SIFT VM:

```bash
curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash
```

**Camera.** Do not speed up. Let it run real-time. Seven colour-headed sections scroll past — that's the visual.

**Voiceover (during runtime):**

> One-line install on a clean SIFT Workstation. The script verifies Python,
> clones the repository, installs the dart underscore m c p package, and probes
> the SIFT toolchain — Volatility 3, MFTECmd, EvtxECmd, PECmd, RECmd,
> AmcacheParser, YARA, log2timeline, psort. Whichever binaries are on the
> system path get wired up automatically. Missing ones get clear environment-
> variable override hints. Then it verifies the full MCP tool surface is
> registered — native pure-Python plus SIFT Workstation adapters.

**Pause point.** When the script prints:

```
[ok] MCP surface verified: 45 native + 25 SIFT adapters = 70 tools
```

freeze the cursor for one beat so the viewer reads it.

---

### Scene 3 — The architectural boundary (0:45 → 1:30) — 45 seconds

**Action.** Show the bypass test suite passing.

```bash
cd ~/agentic-dart
source .venv/bin/activate
python3 -m pytest tests/test_mcp_bypass.py -v
```

Then the SIFT adapter surface test:

```bash
python3 -m pytest tests/test_sift_adapters.py -v
```

Let the green dots flow. The audience sees both files terminate with `passed`.

**Voiceover:**

> Most agentic DFIR tools are a system prompt asking an LLM to behave well.
> We removed the ability to misbehave. The bypass test suite verifies that
> destructive operations — execute underscore shell, write underscore file,
> mount, eval — are not registered, and that path-traversal attempts against
> the evidence root are blocked at the MCP boundary itself. The SIFT adapter
> test suite verifies the same guarantees hold for all twenty-five subprocess
> wrappers. Adding tools never weakens the boundary, because the boundary
> *is* the canonical name set.

---

### Scene 4 — End-to-end run on a case (1:30 → 2:20) — 50 seconds

**Action.** Run a deterministic case study. Recommended: **case-04 phishing → download → execution → exfiltration**, because it touches infection vector, persistence, lateral movement, AND exfiltration — judges see breadth in one shot.

```bash
python3 -m dart_agent \
    --evidence-root examples/case-studies/case-04-phishing-to-exfil/evidence_root \
    --playbook dart_playbook/senior-analyst-v3.yaml \
    --output /tmp/case-04-out
```

Let it stream. Phase markers should print: `[P0]`, `[P1]`, `[P2]` ... up to `[P9]`. Each phase emits findings + audit entries in real time.

**Voiceover (during the run, narrating phases as they appear):**

> Phase zero — scope and volatility. Phase one — initial access vector
> triage. Phase two — timeline reconstruction. Phase three — anomaly
> surfacing. Phase four — hypothesis formation. Phase five — kill-chain
> assembly. Phase six — contradiction handling. Phase seven — attribution
> and Diamond Model. Phase eight — recovery and denial check. Phase nine —
> finding emission. Each phase emits typed findings into findings dot json,
> and every MCP call is hashed into audit dot j s o n l — a tamper-evident
> chain of custody you can verify after the fact.

When the run terminates, show:

```bash
head -30 /tmp/case-04-out/findings.json
wc -l /tmp/case-04-out/audit.jsonl
python3 -m dart_audit verify /tmp/case-04-out/audit.jsonl
```

The audit verifier should print `OK — chain intact, N entries, SHA-256 hash X...`

---

### Scene 5 — The new v0.6.1 capabilities (2:20 → 2:50) — 30 seconds

**Action.** Call one of the three new v0.6.1 functions directly. DNS tunneling is the most visually striking — TA0011 entry point — so default to that:

```bash
python3 -c "
from dart_mcp import call_tool
import json
result = call_tool('detect_dns_tunneling', {
    'dns_log_path': 'examples/sample-evidence-realistic/dns/query.log',
    'entropy_threshold': 3.8,
})
print(json.dumps(result['flagged_queries'][:5], indent=2))
print(f\"Total flagged: {result['total_flagged']}\")
print(f\"High-volume parent domains: {len(result['high_volume_domains'])}\")
"
```

(Have a pre-prepared `examples/sample-evidence-realistic/dns/query.log` with both clean and Iodine-pattern queries seeded.)

**Voiceover:**

> v0.6.1 ships three new native functions. parse underscore m a c o s underscore
> quarantine reads the LSQuarantineEvent SQLite database — Sarah Edwards's
> standard macOS download-provenance artefact. parse underscore linux underscore
> cron underscore jobs enumerates every cron path with attacker-pattern
> flagging — curl-pipe-shell, base64 decode, at-reboot triggers, slash temp
> shell scripts. And detect underscore d n s underscore tunnelling — shown
> here — opens MITRE tactic TA-zero-zero-one-one, Command and Control, via
> Shannon entropy, query volume, and Iodine and dnscat2 signature detection.

---

### Scene 6 — Closing slate (2:50 → 3:00) — 10 seconds

**Action.** Slow zoom on terminal showing:

```bash
cat << 'EOF'

  Agentic-DART
  github.com/Juwon1405/agentic-dart
  SANS FIND EVIL! 2026

  Architecture-first.
  Audit-chained.
  Zero destructive operations possible.

EOF
```

**Voiceover:**

> Agentic-DART. Sole-authored entry for SANS FIND EVIL! 2026. Code, tests,
> playbook, and audit chain all on GitHub. Thanks for watching.

---

## Post-production checklist

- [ ] Voiceover synthesized via `voiceover/say_voiceover.sh` (run on your macOS host)
- [ ] Six scene MP3s aligned with the recorded screencast in Final Cut / iMovie / DaVinci Resolve / kdenlive
- [ ] Background music: **none.** Quiet luxury — terminal + narration only
- [ ] Captions burned in for accessibility (auto-generated from the voiceover transcript files)
- [ ] Export 1080p H.264, audio AAC 128 kbps, total ≤ 200 MB (Devpost-friendly)
- [ ] Upload to YouTube (unlisted) and link from Devpost — Devpost video player can be flaky; YouTube embed is more reliable

---

## Voiceover word-count sanity check (British TTS at ~155 wpm)

| Scene | Words | Target seconds | Comfortable? |
|---|---:|---:|:-:|
| 1 Cold open | 67 | 15 | ✅ ~26s nominal — speed up slightly or trim "Not because we asked it not to" |
| 2 Install | 90 | 30 | ✅ ~35s nominal — fits while install runs |
| 3 Bypass | 100 | 45 | ✅ ~39s nominal |
| 4 End-to-end | 95 | 50 | ✅ ~37s nominal — leaves room for command output |
| 5 v0.6.1 | 95 | 30 | ✅ ~37s nominal — trim the slowly-spoken hyphenated function names |
| 6 Closing | 22 | 10 | ✅ ~9s nominal |
| **Total** | **469** | **180** | ✅ |

If the recorded narration runs long, the safest cuts (in order) are: Scene 1 last sentence, Scene 5 last sentence, Scene 3 final sentence.
