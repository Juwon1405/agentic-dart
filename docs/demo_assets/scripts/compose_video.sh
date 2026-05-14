#!/usr/bin/env bash
# compose_v4.sh — PPT-then-demo flow + Piper male voice
#
# Key changes from v3:
#   1. PPT and terminal-demo are now temporally separated within each scene:
#      slide stays on screen for the FULL voiceover, then terminal frames
#      run as silent demonstration. This matches how a real presenter would
#      walk through slides first, then switch to the live demo.
#   2. Voice swapped from gTTS (female UK) to Piper Ryan medium (US male,
#      lower register, more natural — sounds like a real narrator).
#   3. Total runtime ~5:55, longer than v3 (4:49) but clearer pacing.

set -euo pipefail
cd "$(dirname "$0")"

SLIDES=slides_v2
TERM=terminal
mkdir -p output

# ─── Build concat list ───────────────────────────────────────────────────────
LIST=output/concat_v4.txt
> "$LIST"
add() { echo "file '$(realpath "$1")'" >> "$LIST"; echo "duration $2" >> "$LIST"; }

# Scene 1: cover slide only (Piper voice 19s, hold for 25s with breathing room)
add $SLIDES/slide1_cover.png 25

# Scene 2 — PPT phase (37s, voice 32s) then demo phase (33s silent)
add $SLIDES/slide2_install.png 37
add $TERM/s2_01_empty.png      3
add $TERM/s2_02_typed.png      5
add $TERM/s2_03_stages_1_2.png 6
add $TERM/s2_04_stages_3_5.png 7
add $TERM/s2_05_surface_ok.png 8
add $TERM/s2_06_done.png       4

# Scene 3 — PPT phase (35s, voice 31s) then demo phase (35s silent)
add $SLIDES/slide3_boundary.png 35
add $TERM/s3_01_typed.png      3
add $TERM/s3_02_running.png    10
add $TERM/s3_03_complete.png   12
add $TERM/s3_04_sift_adapters.png 10

# Scene 4 — PPT phase (33s, voice 28s) then demo phase (47s silent)
add $SLIDES/slide4_end_to_end.png 33
add $TERM/s4_01_typed.png            4
add $TERM/s4_02_p0_p3.png            10
add $TERM/s4_03_p4_p6_correction.png 16
add $TERM/s4_04_p7_p9_done.png       10
add $TERM/s4_05_audit_verify.png     7

# Scene 5 — PPT phase (43s, voice 39s) then demo phase (52s silent)
add $SLIDES/slide5_v061.png 43
add $TERM/s5_01_typed.png   18
add $TERM/s5_02_output.png  34

# Scene 6 — closing slate (15s, voice 8s)
add $SLIDES/slide6_closing.png 15

# Concat demuxer requires last file repeated
echo "file '$(realpath $SLIDES/slide6_closing.png)'" >> "$LIST"

# ─── Silent video render ─────────────────────────────────────────────────────
echo "[render] composing silent video (PPT-then-demo flow)"
ffmpeg -y -loglevel error -stats \
    -f concat -safe 0 -i "$LIST" \
    -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=out:st=353:d=2" \
    -c:v libx264 -preset slow -crf 20 \
    -movflags +faststart \
    -r 30 \
    output/agentic-dart-demo-silent-v4.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-silent-v4.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-silent-v4.mp4 | cut -f1)
echo "[silent v4] duration=${duration}s  size=${size}"

# ─── Audio scene-start timings (ms) ──────────────────────────────────────────
# Scene 1:    1000 ms       (1s after start, voice 19s, fits in 25s cover)
# Scene 2:   26000 ms       (1s after Scene 2 PPT starts at 25s)
# Scene 3:   96000 ms       (1s after Scene 3 PPT starts at 95s; 25+37+33=95)
# Scene 4:  166000 ms       (1s after Scene 4 PPT; 95+35+35=165)
# Scene 5:  246000 ms       (1s after Scene 5 PPT; 165+33+47=245)
# Scene 6:  341000 ms       (1s after Scene 6 closing; 245+43+52=340)

echo ""
echo "[mux] adding Piper Ryan medium voice (US male, lower register)"
ffmpeg -y -loglevel error -stats \
    -i output/agentic-dart-demo-silent-v4.mp4 \
    -i audio_piper/scene1.wav \
    -i audio_piper/scene2.wav \
    -i audio_piper/scene3.wav \
    -i audio_piper/scene4.wav \
    -i audio_piper/scene5.wav \
    -i audio_piper/scene6.wav \
    -filter_complex "
        [1:a]adelay=1000|1000[a1];
        [2:a]adelay=26000|26000[a2];
        [3:a]adelay=96000|96000[a3];
        [4:a]adelay=166000|166000[a4];
        [5:a]adelay=246000|246000[a5];
        [6:a]adelay=341000|341000[a6];
        [a1][a2][a3][a4][a5][a6]amix=inputs=6:duration=longest:normalize=0,
        volume=1.5[aout]
    " \
    -map 0:v -map "[aout]" \
    -c:v copy \
    -c:a aac -b:a 192k \
    -ac 2 \
    -movflags +faststart \
    -t 355 \
    output/agentic-dart-demo-v4.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-v4.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-v4.mp4 | cut -f1)
echo ""
echo "[final v4]"
echo "  path:     output/agentic-dart-demo-v4.mp4"
echo "  duration: ${duration}s"
echo "  size:     ${size}"
echo ""
echo "  voice:    Piper Ryan medium (US male, lower register, natural cadence)"
echo "  flow:     slide → voiceover full → silent terminal demo → next slide"
