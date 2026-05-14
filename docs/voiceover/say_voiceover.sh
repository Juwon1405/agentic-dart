#!/usr/bin/env bash
# voiceover/say_voiceover.sh — Synthesize British-English voiceover for the
# Agentic-DART demo screencast using macOS `say`.
#
# USAGE (run on your macOS host, NOT inside the SIFT VM):
#
#     cd ~/agentic-dart
#     bash docs/voiceover/say_voiceover.sh
#
# Output: docs/voiceover/scene1.aiff … scene6.aiff and their .mp3 transcodes.
#
# DEFAULTS to `Daniel` (formal British male). To switch voices, set VOICE env:
#
#     VOICE="Oliver (Premium)" bash docs/voiceover/say_voiceover.sh   # warmer male
#     VOICE="Kate" bash docs/voiceover/say_voiceover.sh                # crisp female
#     VOICE="Serena (Premium)" bash docs/voiceover/say_voiceover.sh    # warmer female
#
# To check what's installed locally:
#
#     say -v ? | grep -E "en_GB|en-GB"
#
# To install premium voices on macOS:
#   System Settings → Accessibility → Spoken Content → System Voice →
#   Manage Voices → check Oliver (Premium) / Serena (Premium) / Kate (Premium)
#
# British speaking-rate sweet spot is ~155-170 wpm. macOS default is ~180-200.
# We slow to 155 wpm via -r 155 so it lands closer to a documentary cadence.
# Slower if you find Daniel sounds rushed — try -r 145.

set -euo pipefail

# ─── Settings ─────────────────────────────────────────────────────────────────
VOICE="${VOICE:-Daniel}"   # override with: VOICE="Oliver (Premium)" bash ...
RATE="${RATE:-155}"        # words per minute
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENES_DIR="${SCRIPT_DIR}/scenes"
OUT_DIR="${SCRIPT_DIR}/out"

mkdir -p "${OUT_DIR}"

# ─── Sanity check ─────────────────────────────────────────────────────────────
if ! command -v say &>/dev/null; then
    echo "[fatal] 'say' not found. This script must be run on macOS." >&2
    exit 1
fi

# Validate voice exists
if ! say -v ? | grep -qiE "^${VOICE}[[:space:]]"; then
    echo "[warn] Voice '${VOICE}' not found in 'say -v ?' output." >&2
    echo "[warn] Available British English voices on this Mac:" >&2
    say -v ? | grep -E "en_GB|en-GB" | sed 's/^/         /' >&2
    echo "" >&2
    echo "[warn] To install premium voices: System Settings → Accessibility →" >&2
    echo "         Spoken Content → System Voice → Manage Voices …" >&2
    echo "" >&2
    echo "Proceeding anyway — 'say' may fall back to a default voice." >&2
fi

echo "[info] Voice: ${VOICE}"
echo "[info] Rate:  ${RATE} wpm"
echo "[info] Scenes dir:  ${SCENES_DIR}"
echo "[info] Output dir:  ${OUT_DIR}"
echo ""

# ─── Synthesize each scene ────────────────────────────────────────────────────
for scene_txt in "${SCENES_DIR}"/scene*.txt; do
    scene_name="$(basename "${scene_txt}" .txt)"
    aiff_out="${OUT_DIR}/${scene_name}.aiff"
    mp3_out="${OUT_DIR}/${scene_name}.mp3"

    echo "[gen] ${scene_name} → ${aiff_out}"
    say -v "${VOICE}" -r "${RATE}" -f "${scene_txt}" -o "${aiff_out}"

    # Transcode to MP3 if ffmpeg present (most macOS hosts have it via brew)
    if command -v ffmpeg &>/dev/null; then
        ffmpeg -y -loglevel error -i "${aiff_out}" \
            -ar 44100 -ac 2 -b:a 192k \
            "${mp3_out}"
        echo "[mp3] ${mp3_out}"
    else
        echo "[skip] ffmpeg not on PATH — leaving .aiff only. brew install ffmpeg to get .mp3"
    fi

    # Report duration
    duration=$(ffmpeg -i "${aiff_out}" 2>&1 | grep -oE "Duration: [0-9:.]+" | sed 's/Duration: //' || true)
    echo "        duration: ${duration:-unknown}"
    echo ""
done

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────────"
echo "Done. Files in ${OUT_DIR}:"
ls -1 "${OUT_DIR}"
echo ""
echo "Next steps:"
echo "  1. Import the .mp3 files into Final Cut / iMovie / DaVinci Resolve / kdenlive"
echo "  2. Align each scene MP3 with the corresponding screencast clip per DEMO_STORYBOARD_v2.md"
echo "  3. Auto-generate captions from the .txt files (most editors offer SRT import)"
echo "  4. Export 1080p H.264 — see DEMO_STORYBOARD_v2.md post-production checklist"
