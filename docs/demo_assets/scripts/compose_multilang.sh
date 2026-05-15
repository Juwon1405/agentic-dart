#!/usr/bin/env bash
# compose_multilang.sh — Build 3 demo videos (en/ko/ja) with separate
# scene timing matched to each language's voice duration.

set -euo pipefail
cd "$(dirname "$0")"

SLIDES=slides_v2
TERM=terminal
mkdir -p output

# ─── Per-language voice durations ────────────────────────────────────────────
# en: 27 46 42 47 49 14 = 225s
# ko: 38 60 60 56 60 19 = 293s
# ja: 42 62 66 60 69 19 = 318s

# ─── Demo phase fixed timings (silent terminal) ──────────────────────────────
# Scene 2 demo: 33s
# Scene 3 demo: 35s
# Scene 4 demo: 47s
# Scene 5 demo: 52s

build_video() {
    local lang="$1"          # en / ko / ja
    local audio_dir="$2"     # audio_en / audio_ko / audio_ja
    local ext="$3"           # wav / mp3
    local s1="$4"   # scene 1 voice duration (sec)
    local s2="$5"
    local s3="$6"
    local s4="$7"
    local s5="$8"
    local s6="$9"

    # PPT phase = voice duration + 5s breathing room
    local p1=$((s1 + 5))
    local p2=$((s2 + 5))
    local p3=$((s3 + 5))
    local p4=$((s4 + 5))
    local p5=$((s5 + 5))
    local p6=$((s6 + 5))

    # Demo phase durations
    local d2=33
    local d3=35
    local d4=47
    local d5=52

    # Total scene durations
    local sd1=$p1
    local sd2=$((p2 + d2))
    local sd3=$((p3 + d3))
    local sd4=$((p4 + d4))
    local sd5=$((p5 + d5))
    local sd6=$p6

    # Audio start times (ms) — 2s into each PPT phase
    local a1_ms=$((2 * 1000))
    local a2_ms=$(((sd1 + 2) * 1000))
    local a3_ms=$(((sd1 + sd2 + 2) * 1000))
    local a4_ms=$(((sd1 + sd2 + sd3 + 2) * 1000))
    local a5_ms=$(((sd1 + sd2 + sd3 + sd4 + 2) * 1000))
    local a6_ms=$(((sd1 + sd2 + sd3 + sd4 + sd5 + 2) * 1000))

    local total=$((sd1 + sd2 + sd3 + sd4 + sd5 + sd6))
    local fade_st=$((total - 2))

    echo ""
    echo "════════ ${lang} ════════"
    echo "  Scene durations: ${sd1} ${sd2} ${sd3} ${sd4} ${sd5} ${sd6}"
    echo "  Total: ${total}s"

    # Build concat list
    local LIST=output/concat_${lang}.txt
    > "$LIST"
    add() { echo "file '$(realpath "$1")'" >> "$LIST"; echo "duration $2" >> "$LIST"; }

    add $SLIDES/slide1_cover.png $p1

    add $SLIDES/slide2_install.png $p2
    add $TERM/s2_01_empty.png      3
    add $TERM/s2_02_typed.png      5
    add $TERM/s2_03_stages_1_2.png 6
    add $TERM/s2_04_stages_3_5.png 7
    add $TERM/s2_05_surface_ok.png 8
    add $TERM/s2_06_done.png       4

    add $SLIDES/slide3_boundary.png $p3
    add $TERM/s3_01_typed.png      3
    add $TERM/s3_02_running.png    10
    add $TERM/s3_03_complete.png   12
    add $TERM/s3_04_sift_adapters.png 10

    add $SLIDES/slide4_end_to_end.png $p4
    add $TERM/s4_01_typed.png            4
    add $TERM/s4_02_p0_p3.png            10
    add $TERM/s4_03_p4_p6_correction.png 16
    add $TERM/s4_04_p7_p9_done.png       10
    add $TERM/s4_05_audit_verify.png     7

    add $SLIDES/slide5_v061.png $p5
    add $TERM/s5_01_typed.png   18
    add $TERM/s5_02_output.png  34

    add $SLIDES/slide6_closing.png $p6

    echo "file '$(realpath $SLIDES/slide6_closing.png)'" >> "$LIST"

    # Silent video render
    echo "  [render] silent"
    ffmpeg -y -loglevel error \
        -f concat -safe 0 -i "$LIST" \
        -vf "scale=1920:1080:flags=lanczos,format=yuv420p,fade=t=out:st=${fade_st}:d=2" \
        -c:v libx264 -preset slow -crf 20 \
        -movflags +faststart \
        -r 30 \
        output/silent_${lang}.mp4

    # Mux audio
    echo "  [mux] audio adelay  a1=${a1_ms}ms  a2=${a2_ms}ms  ...  a6=${a6_ms}ms"
    ffmpeg -y -loglevel error \
        -i output/silent_${lang}.mp4 \
        -i ${audio_dir}/scene1.${ext} \
        -i ${audio_dir}/scene2.${ext} \
        -i ${audio_dir}/scene3.${ext} \
        -i ${audio_dir}/scene4.${ext} \
        -i ${audio_dir}/scene5.${ext} \
        -i ${audio_dir}/scene6.${ext} \
        -filter_complex "
            [1:a]adelay=${a1_ms}|${a1_ms}[a1];
            [2:a]adelay=${a2_ms}|${a2_ms}[a2];
            [3:a]adelay=${a3_ms}|${a3_ms}[a3];
            [4:a]adelay=${a4_ms}|${a4_ms}[a4];
            [5:a]adelay=${a5_ms}|${a5_ms}[a5];
            [6:a]adelay=${a6_ms}|${a6_ms}[a6];
            [a1][a2][a3][a4][a5][a6]amix=inputs=6:duration=longest:normalize=0,
            volume=1.5[aout]
        " \
        -map 0:v -map "[aout]" \
        -c:v copy -c:a aac -b:a 192k -ac 2 \
        -movflags +faststart \
        -t $total \
        output/agentic-dart-demo-${lang}.mp4

    local size=$(du -h output/agentic-dart-demo-${lang}.mp4 | cut -f1)
    echo "  [done] output/agentic-dart-demo-${lang}.mp4  ${total}s  ${size}"
}

# Build all three
build_video "en" "audio_en" "wav" 27 46 42 47 49 14
build_video "ko" "audio_ko" "mp3" 38 60 60 56 60 19
build_video "ja" "audio_ja" "mp3" 42 62 66 60 69 19

echo ""
echo "════════════════════════════════════════"
echo "  All 3 language videos composed."
echo "════════════════════════════════════════"
ls -lh output/agentic-dart-demo-*.mp4
