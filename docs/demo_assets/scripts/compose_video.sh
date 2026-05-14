#!/usr/bin/env bash
# compose_video.sh — Assemble the Agentic-DART demo video from slides + terminal frames.
#
# This script produces a 1920x1080 H.264 silent video that you then mux with the
# British-English voiceover synthesized via docs/voiceover/say_voiceover.sh
# (or any other TTS pipeline).
#
# Runs on Linux (this container) or macOS. Requires ffmpeg only.
#
# Output: demo_video/output/agentic-dart-demo-silent.mp4
#
# After mux:
#     bash compose_video.sh
#     # ... on your macOS host:
#     bash docs/voiceover/say_voiceover.sh
#     # then mux audio + video:
#     bash compose_video.sh --mux

set -euo pipefail

cd "$(dirname "$0")"

SLIDES_DIR="slides"
TERM_DIR="terminal"
OUT_DIR="output"
mkdir -p "${OUT_DIR}"

# ─── Scene timing budget (seconds) — total 180s = 3:00 ────────────────────────
# Slide hold then terminal sequence then transition back to next slide.
S1_SLIDE=15        # cold open slide only
S2_SLIDE=4         # install slide intro
S2_FRAMES=(s2_01_empty s2_02_typed s2_03_stages_1_2 s2_04_stages_3_5 s2_05_surface_ok s2_06_done)
S2_DURATIONS=(2 4 5 5 7 3)  # 26s total ; slide intro 4s = 30s
S3_SLIDE=4
S3_FRAMES=(s3_01_typed s3_02_running s3_03_complete s3_04_sift_adapters)
S3_DURATIONS=(3 12 14 12)  # 41s ; slide 4s = 45s
S4_SLIDE=4
S4_FRAMES=(s4_01_typed s4_02_p0_p3 s4_03_p4_p6_correction s4_04_p7_p9_done s4_05_audit_verify)
S4_DURATIONS=(4 12 14 10 6)  # 46s ; slide 4s = 50s
S5_SLIDE=4
S5_FRAMES=(s5_01_typed s5_02_output)
S5_DURATIONS=(8 18)  # 26s ; slide 4s = 30s
S6_SLIDE=10

# ─── Build concat list ───────────────────────────────────────────────────────
LIST="${OUT_DIR}/concat.txt"
> "${LIST}"

add() {
    local file="$1"
    local dur="$2"
    echo "file '$(realpath "${file}")'" >> "${LIST}"
    echo "duration ${dur}" >> "${LIST}"
}

echo "[plan] composing scene list"

# Scene 1 — cold open slide
add "${SLIDES_DIR}/scene1_cold_open.png" "${S1_SLIDE}"

# Scene 2 — install slide → frames
add "${SLIDES_DIR}/scene2_install.png" "${S2_SLIDE}"
for i in "${!S2_FRAMES[@]}"; do
    add "${TERM_DIR}/${S2_FRAMES[i]}.png" "${S2_DURATIONS[i]}"
done

# Scene 3 — boundary slide → bypass test frames
add "${SLIDES_DIR}/scene3_boundary.png" "${S3_SLIDE}"
for i in "${!S3_FRAMES[@]}"; do
    add "${TERM_DIR}/${S3_FRAMES[i]}.png" "${S3_DURATIONS[i]}"
done

# Scene 4 — end-to-end slide → playbook + self-correction frames
add "${SLIDES_DIR}/scene4_end_to_end.png" "${S4_SLIDE}"
for i in "${!S4_FRAMES[@]}"; do
    add "${TERM_DIR}/${S4_FRAMES[i]}.png" "${S4_DURATIONS[i]}"
done

# Scene 5 — v0.6.1 slide → DNS tunneling demo
add "${SLIDES_DIR}/scene5_v061.png" "${S5_SLIDE}"
for i in "${!S5_FRAMES[@]}"; do
    add "${TERM_DIR}/${S5_FRAMES[i]}.png" "${S5_DURATIONS[i]}"
done

# Scene 6 — closing slate (held)
add "${SLIDES_DIR}/scene6_closing.png" "${S6_SLIDE}"

# Concat demuxer requires the last file to repeat with zero duration
echo "file '$(realpath "${SLIDES_DIR}/scene6_closing.png")'" >> "${LIST}"

# ─── Render ──────────────────────────────────────────────────────────────────
SILENT_OUT="${OUT_DIR}/agentic-dart-demo-silent.mp4"
echo ""
echo "[render] composing silent video → ${SILENT_OUT}"

ffmpeg -y -loglevel error -stats \
    -f concat -safe 0 -i "${LIST}" \
    -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=in:st=0:d=0.5,fade=t=out:st=178:d=2" \
    -c:v libx264 -preset slow -crf 20 \
    -movflags +faststart \
    -r 30 \
    "${SILENT_OUT}"

DURATION=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "${SILENT_OUT}" | cut -d. -f1)
SIZE=$(du -h "${SILENT_OUT}" | cut -f1)
echo ""
echo "[done] silent video"
echo "  path:     ${SILENT_OUT}"
echo "  duration: ${DURATION}s"
echo "  size:     ${SIZE}"
echo ""
echo "── Next steps ──"
echo "  1. On your macOS host, synthesize the British-English voiceover:"
echo "       bash docs/voiceover/say_voiceover.sh"
echo "     This produces docs/voiceover/out/scene{1..6}.mp3"
echo ""
echo "  2. Mux audio + video. Choose ONE of these:"
echo ""
echo "  Option A — direct ffmpeg mux (simplest, fixed scene boundaries):"
echo "    bash compose_video.sh --mux"
echo ""
echo "  Option B — interactive video editor (recommended for tuning):"
echo "    Open ${SILENT_OUT} in iMovie / Final Cut / DaVinci Resolve / kdenlive."
echo "    Drop each scene MP3 onto the audio track, aligned with the matching slide."
echo "    Export 1080p H.264 AAC 192k as agentic-dart-demo.mp4."
