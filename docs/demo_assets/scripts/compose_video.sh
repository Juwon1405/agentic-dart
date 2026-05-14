#!/usr/bin/env bash
# compose_v3.sh — Final demo video composition with premium light-theme slides.
#
# Fixes from v2:
#   - Scene 1 no longer renders 0.5s black (removed dangerous fade-in start)
#   - Replaced slides_v1 (dark) with slides_v2 (premium light theme)
#   - Same terminal frames (dark theme is correct for terminal scenes)
#   - Same gTTS UK English voiceover
#   - Same audio scene-aligned timing via adelay

set -euo pipefail
cd "$(dirname "$0")"

SLIDES=slides_v2
TERM=terminal
mkdir -p output

LIST=output/concat_v3.txt
> "$LIST"
add() { echo "file '$(realpath "$1")'" >> "$LIST"; echo "duration $2" >> "$LIST"; }

# Scene 1: 30s cover slide (voice 28s)
add $SLIDES/slide1_cover.png 30

# Scene 2: slide 4s + 6 terminal frames (51s total to match voice 51s)
add $SLIDES/slide2_install.png 4
add $TERM/s2_01_empty.png      3
add $TERM/s2_02_typed.png      6
add $TERM/s2_03_stages_1_2.png 10
add $TERM/s2_04_stages_3_5.png 11
add $TERM/s2_05_surface_ok.png 14
add $TERM/s2_06_done.png       7

# Scene 3: slide 4s + 4 frames (46s to match voice 44s)
add $SLIDES/slide3_boundary.png 4
add $TERM/s3_01_typed.png      4
add $TERM/s3_02_running.png    14
add $TERM/s3_03_complete.png   16
add $TERM/s3_04_sift_adapters.png 12

# Scene 4: slide 4s + 5 frames (51s to match voice 50s)
add $SLIDES/slide4_end_to_end.png 4
add $TERM/s4_01_typed.png            4
add $TERM/s4_02_p0_p3.png            12
add $TERM/s4_03_p4_p6_correction.png 17
add $TERM/s4_04_p7_p9_done.png       11
add $TERM/s4_05_audit_verify.png     7

# Scene 5: slide 4s + 2 frames (56s to match voice 54s)
add $SLIDES/slide5_v061.png 4
add $TERM/s5_01_typed.png   18
add $TERM/s5_02_output.png  38

# Scene 6: 20s closing slate (voice 14s)
add $SLIDES/slide6_closing.png 20

# Concat demuxer requires last file repeated
echo "file '$(realpath $SLIDES/slide6_closing.png)'" >> "$LIST"

# CRITICAL FIX: no fade-in at start (was making Scene 1 dark-fade against
# a now-white slide, creating a perceived black flash). Fade-out at end only.
echo "[render] composing silent video (no startup fade)"
ffmpeg -y -loglevel error -stats \
    -f concat -safe 0 -i "$LIST" \
    -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=out:st=287:d=2" \
    -c:v libx264 -preset slow -crf 20 \
    -movflags +faststart \
    -r 30 \
    output/agentic-dart-demo-silent-v3.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-silent-v3.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-silent-v3.mp4 | cut -f1)
echo "[silent v3] duration=${duration}s  size=${size}"

# ─── Mux voiceover ───────────────────────────────────────────────────────────
echo ""
echo "[mux] adding gTTS UK English voiceover"
ffmpeg -y -loglevel error -stats \
    -i output/agentic-dart-demo-silent-v3.mp4 \
    -i audio_gtts/scene1.mp3 \
    -i audio_gtts/scene2.mp3 \
    -i audio_gtts/scene3.mp3 \
    -i audio_gtts/scene4.mp3 \
    -i audio_gtts/scene5.mp3 \
    -i audio_gtts/scene6.mp3 \
    -filter_complex "
        [1:a]adelay=1000|1000[a1];
        [2:a]adelay=34000|34000[a2];
        [3:a]adelay=89000|89000[a3];
        [4:a]adelay=139000|139000[a4];
        [5:a]adelay=194000|194000[a5];
        [6:a]adelay=252000|252000[a6];
        [a1][a2][a3][a4][a5][a6]amix=inputs=6:duration=longest:normalize=0,
        volume=1.5[aout]
    " \
    -map 0:v -map "[aout]" \
    -c:v copy \
    -c:a aac -b:a 192k \
    -ac 2 \
    -movflags +faststart \
    -t 289 \
    output/agentic-dart-demo-v3.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-v3.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-v3.mp4 | cut -f1)
echo ""
echo "[final v3] duration=${duration}s  size=${size}"
echo "[path]     output/agentic-dart-demo-v3.mp4"
