# Demo video assets — Agentic-DART v0.6.1

This folder contains everything needed to produce the SANS FIND EVIL! 2026
demo screencast: rendered slides, virtual terminal frames, the silent video
composition, and the scripts that regenerate them all from source.

## What's here

```
docs/demo_assets/
├── README.md                                    (this file)
├── slides/                                      6 title slides (1920x1080)
│   ├── scene1_cold_open.png
│   ├── scene2_install.png
│   ├── scene3_boundary.png
│   ├── scene4_end_to_end.png
│   ├── scene5_v061.png
│   └── scene6_closing.png
├── terminal/                                    17 virtual-terminal frames
│   ├── s2_01..06_*.png                          Scene 2 install demo
│   ├── s3_01..04_*.png                          Scene 3 bypass tests
│   ├── s4_01..05_*.png                          Scene 4 end-to-end run + P6 self-correction
│   └── s5_01..02_*.png                          Scene 5 v0.6.1 DNS tunneling
├── scripts/
│   ├── slide_generator.py                       regenerate slides
│   ├── terminal_scene_renderer.py               regenerate terminal frames
│   └── compose_video.sh                         ffmpeg concat → silent MP4
└── output/
    └── agentic-dart-demo-silent.mp4             ready-to-mux silent video
```

## How the final video gets made

The video is split into two halves so different machines can do what they're
best at:

1. **Silent video composition** (Linux container or macOS) — ffmpeg concats
   slides + terminal frames into a 1920x1080 silent MP4 at 30 fps with a
   fade-in / fade-out polish.

2. **Voiceover synthesis** (macOS host only) — macOS `say` reads the six
   British-English scene scripts (in `docs/voiceover/scenes/`) using
   `Daniel` (default) or `Oliver (Premium)` / `Kate` / `Serena (Premium)`.

Then your video editor — iMovie, Final Cut, DaVinci Resolve, or kdenlive —
muxes the audio onto the silent video with scene-level alignment.

## Reproducing from source

```bash
cd docs/demo_assets

# 1. Regenerate slides (only needed if you change slide_generator.py)
python3 scripts/slide_generator.py

# 2. Regenerate terminal frames (only needed if you change terminal_scene_renderer.py)
python3 scripts/terminal_scene_renderer.py

# 3. Recompose the silent video
bash scripts/compose_video.sh
```

## Scene-by-scene timing

| Scene | Visual content                                       | Duration |
|-------|------------------------------------------------------|---------:|
| 1     | Cold-open slide                                      |  0:00–0:15 |
| 2     | Install slide → 6 install frames                     |  0:15–0:45 |
| 3     | Boundary slide → 4 bypass-test frames                |  0:45–1:30 |
| 4     | End-to-end slide → 5 playbook frames (incl. P6 self-correction) | 1:30–2:20 |
| 5     | v0.6.1 slide → 2 DNS-tunneling frames                |  2:20–2:50 |
| 6     | Closing slate                                        |  2:50–3:00 |
| **Total** |                                                  | **~3:00** |

(The current silent output is 3:09 because slide-hold timings round up.
Cut Scene 6 from 10s to 5s, or shave one beat off Scene 4's audit-verify
frame, to land exactly on 3:00 if you need it tighter.)

## SANS rubric coverage

The video deliberately demonstrates each of the six SANS Find Evil! 2026
judging criteria:

| Criterion                  | Where it shows up |
|----------------------------|---|
| Autonomous execution       | Scene 4 — full 10-phase playbook run, no human intervention between phases |
| IR accuracy                | Scene 4 — output count, confidence scoring, MITRE chain at end |
| **Hallucination management** | **Scene 4 P6 — the agent retracts an earlier H1 hypothesis when `parse_registry_hive` evidence contradicts it. This is the self-correction event SANS asks for explicitly.** |
| Architectural guardrails   | Scenes 2-3 — install probe + bypass test suite + "not on the wire" slide |
| Audit trail quality        | Scene 4 — `dart_audit verify` shows SHA-256 chain intact, 143 entries |
| Documentation              | Scene 5 — three new v0.6.1 functions each with reference + MITRE mapping |

## Voiceover word-count check (British TTS ~155 wpm)

| Scene | Words | Target | Audio fit |
|-------|------:|-------:|:-:|
| 1     |  67   | 15s    | tight     |
| 2     |  90   | 30s    | fits      |
| 3     | 100   | 45s    | fits      |
| 4     |  95   | 50s    | fits with room for command output |
| 5     |  95   | 30s    | fits      |
| 6     |  22   | 10s    | fits      |
| **Total** | **469** | **3:00** | ✅ |

If voiceover lands long, trim in this order: Scene 1 last sentence,
Scene 5 last sentence, Scene 3 final sentence.

## Why generated rather than recorded?

A SANS hackathon judge sees ~50 submissions. Two failure modes erode trust:

- **Inconsistent screen state** — terminal flicker, copy-paste cursor lag,
  ambient notifications, a fan kicking in.
- **Outdated narration** — the README has been updated since the recording.

Generated frames are deterministic. The terminal output matches `list_tools()`
to the byte. Re-recording when v0.6.1 → v0.7.0 ships is a single
`python3 scripts/terminal_scene_renderer.py` away rather than a half-day
re-recording session. **This is the architecture-first principle applied to
the deliverable itself.**
