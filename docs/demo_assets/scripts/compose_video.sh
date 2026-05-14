#!/usr/bin/env bash
# compose_v5.sh — Natural-breathing voice timing.
#
# v5 changes from v4:
#   - Texts rewritten in natural breath units (short sentences with periods
#     where a real narrator would pause)
#   - Piper synth params: length_scale=1.15, sentence_silence=0.9s
#   - Slide hold times extended to match longer audio:
#       Scene 1: 25s -> 32s   (voice 25s)
#       Scene 2: 37s -> 50s   (voice 43s)
#       Scene 3: 35s -> 47s   (voice 40s)
#       Scene 4: 33s -> 52s   (voice 45s)
#       Scene 5: 43s -> 55s   (voice 48s)
#       Scene 6: 15s -> 18s   (voice 13s)
#   - Demo phase timings unchanged

set -euo pipefail
cd "$(dirname "$0")"

SLIDES=slides_v2
TERM=terminal
mkdir -p output

LIST=output/concat_v5.txt
> "$LIST"
add() { echo "file '$(realpath "$1")'" >> "$LIST"; echo "duration $2" >> "$LIST"; }

# Scene 1: cover slide  (voice 25s, hold 32s)
add $SLIDES/slide1_cover.png 32

# Scene 2: PPT 50s + demo 33s = 83s
add $SLIDES/slide2_install.png 50
add $TERM/s2_01_empty.png      3
add $TERM/s2_02_typed.png      5
add $TERM/s2_03_stages_1_2.png 6
add $TERM/s2_04_stages_3_5.png 7
add $TERM/s2_05_surface_ok.png 8
add $TERM/s2_06_done.png       4

# Scene 3: PPT 47s + demo 35s = 82s
add $SLIDES/slide3_boundary.png 47
add $TERM/s3_01_typed.png      3
add $TERM/s3_02_running.png    10
add $TERM/s3_03_complete.png   12
add $TERM/s3_04_sift_adapters.png 10

# Scene 4: PPT 52s + demo 47s = 99s
add $SLIDES/slide4_end_to_end.png 52
add $TERM/s4_01_typed.png            4
add $TERM/s4_02_p0_p3.png            10
add $TERM/s4_03_p4_p6_correction.png 16
add $TERM/s4_04_p7_p9_done.png       10
add $TERM/s4_05_audit_verify.png     7

# Scene 5: PPT 55s + demo 52s = 107s
add $SLIDES/slide5_v061.png 55
add $TERM/s5_01_typed.png   18
add $TERM/s5_02_output.png  34

# Scene 6: closing 18s (voice 13s)
add $SLIDES/slide6_closing.png 18

# Concat demuxer requires last file repeated
echo "file '$(realpath $SLIDES/slide6_closing.png)'" >> "$LIST"

# Total: 32 + 83 + 82 + 99 + 107 + 18 = 421s ≈ 7:01

echo "[render] composing silent video (natural breathing pacing)"
ffmpeg -y -loglevel error -stats \
    -f concat -safe 0 -i "$LIST" \
    -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=out:st=419:d=2" \
    -c:v libx264 -preset slow -crf 20 \
    -movflags +faststart \
    -r 30 \
    output/agentic-dart-demo-silent-v5.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-silent-v5.mp4 | cut -d. -f1)
echo "[silent v5] duration=${duration}s"

# Audio start times (ms):
#   S1: 1500  (1.5s into Scene 1 hold)
#   S2: 33500 (2s after Scene 2 PPT begins at 32s)
#   S3: 116500 (2s after Scene 3 PPT begins at 32+83=115s)
#   S4: 199500 (2s after Scene 4 PPT begins at 115+82=197s)
#   S5: 298500 (2s after Scene 5 PPT begins at 197+99=296s)
#   S6: 405500 (2s after Scene 6 begins at 296+107=403s)

echo ""
echo "[mux] adding natural-breathing Piper Ryan voice"
ffmpeg -y -loglevel error -stats \
    -i output/agentic-dart-demo-silent-v5.mp4 \
    -i audio_piper_v2/scene1.wav \
    -i audio_piper_v2/scene2.wav \
    -i audio_piper_v2/scene3.wav \
    -i audio_piper_v2/scene4.wav \
    -i audio_piper_v2/scene5.wav \
    -i audio_piper_v2/scene6.wav \
    -filter_complex "
        [1:a]adelay=1500|1500[a1];
        [2:a]adelay=33500|33500[a2];
        [3:a]adelay=116500|116500[a3];
        [4:a]adelay=199500|199500[a4];
        [5:a]adelay=298500|298500[a5];
        [6:a]adelay=405500|405500[a6];
        [a1][a2][a3][a4][a5][a6]amix=inputs=6:duration=longest:normalize=0,
        volume=1.5[aout]
    " \
    -map 0:v -map "[aout]" \
    -c:v copy \
    -c:a aac -b:a 192k \
    -ac 2 \
    -movflags +faststart \
    -t 421 \
    output/agentic-dart-demo-v5.mp4

duration=$(ffprobe -v error -show_entries format=duration -of csv=p=0 output/agentic-dart-demo-v5.mp4 | cut -d. -f1)
size=$(du -h output/agentic-dart-demo-v5.mp4 | cut -f1)
echo ""
echo "[final v5]"
echo "  path:     output/agentic-dart-demo-v5.mp4"
echo "  duration: ${duration}s"
echo "  size:     ${size}"
echo "  voice:    Piper Ryan medium · length_scale 1.15 · sentence_silence 0.9s"
echo "  pacing:   natural breath units, slower delivery, pauses between sentences"
