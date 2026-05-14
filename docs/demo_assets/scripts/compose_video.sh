#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

SLIDES=slides
TERM=terminal
mkdir -p output

LIST=output/concat_v2.txt
> "$LIST"
add() { echo "file '$(realpath "$1")'" >> "$LIST"; echo "duration $2" >> "$LIST"; }

# Scene 1: 30s slide (voice 28s)
add $SLIDES/scene1_cold_open.png 30

# Scene 2: slide 4s + 6 terminal frames totaling 51s (voice 51s)
add $SLIDES/scene2_install.png 4
add $TERM/s2_01_empty.png      3
add $TERM/s2_02_typed.png      6
add $TERM/s2_03_stages_1_2.png 10
add $TERM/s2_04_stages_3_5.png 11
add $TERM/s2_05_surface_ok.png 14
add $TERM/s2_06_done.png       7

# Scene 3: slide 4s + 4 frames totaling 46s (voice 44s)
add $SLIDES/scene3_boundary.png 4
add $TERM/s3_01_typed.png      4
add $TERM/s3_02_running.png    14
add $TERM/s3_03_complete.png   16
add $TERM/s3_04_sift_adapters.png 12

# Scene 4: slide 4s + 5 frames totaling 51s (voice 50s)
add $SLIDES/scene4_end_to_end.png 4
add $TERM/s4_01_typed.png            4
add $TERM/s4_02_p0_p3.png            12
add $TERM/s4_03_p4_p6_correction.png 17
add $TERM/s4_04_p7_p9_done.png       11
add $TERM/s4_05_audit_verify.png     7

# Scene 5: slide 4s + 2 frames totaling 56s (voice 54s)
add $SLIDES/scene5_v061.png 4
add $TERM/s5_01_typed.png   18
add $TERM/s5_02_output.png  38

# Scene 6: 20s closing (voice 14s)
add $SLIDES/scene6_closing.png 20

# Concat demuxer requires last file repeated
echo "file '$(realpath $SLIDES/scene6_closing.png)'" >> "$LIST"

ffmpeg -y -loglevel error -stats \
    -f concat -safe 0 -i "$LIST" \
    -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=in:st=0:d=0.5,fade=t=out:st=268:d=2" \
    -c:v libx264 -preset slow -crf 20 \
    -movflags +faststart \
    -r 30 \
    output/agentic-dart-demo-silent-v2.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-silent-v2.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-silent-v2.mp4 | cut -f1)
echo ""
echo "[silent v2] duration=${duration}s  size=${size}"
