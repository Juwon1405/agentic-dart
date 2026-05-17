#!/usr/bin/env python3
"""
regenerate_hero.py — Replace the stale stat-block numbers in
agentic-dart-hero.png with evergreen design-principle words.

The original hero embeds 4 stats:
    35       MCP forensic functions
    11/12    MITRE ATT&CK tactics
    20/20    tests passing on fresh clone
    0        destructive ops on the wire

These numbers go stale every time we add a tool, ship a test, or expand
ATT&CK coverage. The "0" is permanent (architectural invariant), but the
other three need to be replaced with words that ARE permanent design
principles, not metrics.

We keep the hero's visual identity (big-text + small-label pattern,
two-color palette: cyan + green) while making it impossible to go stale.
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import sys

HERO_IN = Path("docs/agentic-dart-hero-v0.4.png")  # use the archived original as source
HERO_OUT = Path("agentic-dart-hero.png")
ARCHIVE = Path("docs/agentic-dart-hero-v0.4.png")  # already archived

# Color palette (sampled from original)
BG_TOP    = (9, 20, 37, 255)        # top of stat block (y=60)
BG_BOTTOM = (4, 11, 22, 255)        # bottom of stat block (y=410)
CYAN      = (34, 211, 238, 255)     # #22D3EE — primary accent
GREEN     = (34, 197, 94, 255)      # #22C55E — success accent
LABEL_GRY = (180, 195, 215, 255)    # soft gray for sub-labels

# Stat block region — derived from pixel scan of original.
# Cyan glyphs detected at (1350,120), green glyphs at (1300,390).
# Existing residual label "destructive ops on the wire" extended past y=410,
# so we extend the wipe region down to y=470 to cover all original content
# while staying clear of the bottom red rule line.
STAT_X0, STAT_Y0 = 1040, 45
STAT_X1, STAT_Y1 = 1720, 470


def find_font(candidates, size):
    """Try a list of font paths and return the first that works."""
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except (OSError, IOError):
            continue
    # Fallback to PIL default (poor but won't crash)
    return ImageFont.load_default()


def main():
    if not HERO_IN.exists():
        print(f"ERROR: {HERO_IN} not found", file=sys.stderr)
        sys.exit(1)

    img = Image.open(HERO_IN).convert("RGBA")
    draw = ImageDraw.Draw(img)
    print(f"Loaded hero: {img.size}")

    # ─── 1. Wipe the stat block area with a vertical gradient ──────────
    # The original background isn't a flat color — it gradually darkens
    # from top to bottom. Flat-fill rectangles look like patches; a
    # gradient blends in seamlessly.
    h = STAT_Y1 - STAT_Y0
    for dy in range(h):
        t = dy / max(h - 1, 1)
        r = round(BG_TOP[0] + t * (BG_BOTTOM[0] - BG_TOP[0]))
        g = round(BG_TOP[1] + t * (BG_BOTTOM[1] - BG_TOP[1]))
        b = round(BG_TOP[2] + t * (BG_BOTTOM[2] - BG_TOP[2]))
        draw.line([(STAT_X0, STAT_Y0 + dy), (STAT_X1, STAT_Y0 + dy)],
                  fill=(r, g, b, 255))

    # ─── 2. Pick fonts ──────────────────────────────────────────────────
    bold_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]
    regular_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    ]
    big_font   = find_font(bold_candidates, 44)   # for primary words
    label_font = find_font(regular_candidates, 19)  # for sub-labels

    # ─── 3. Four evergreen entries (replace the stat block content) ─────
    # Layout: 4 entries vertically, equal spacing
    # Original was 4 entries stacked: 35 / 11/12 / 20/20 / 0
    # We keep the same vertical rhythm but with words.
    entries = [
        ("READ-ONLY",     "MCP boundary",                    CYAN),
        ("ARCHITECTURAL", "guardrails, not prompts",         CYAN),
        ("VERIFIABLE",    "SHA-256 audit chain",             GREEN),
        ("ZERO",          "destructive ops on the wire",     GREEN),
    ]

    # Vertical spacing inside the stat block region
    block_height = STAT_Y1 - STAT_Y0
    entry_height = block_height // len(entries)

    for i, (big, sub, color) in enumerate(entries):
        # Entry top — give a small top padding within each cell
        ey0 = STAT_Y0 + i * entry_height + 12

        # Big word — left-aligned, with a comfortable left margin
        draw.text((STAT_X0 + 30, ey0), big, font=big_font, fill=color)

        # Sub-label one line below (matches font height of 44 → ~52px below)
        sub_y = ey0 + 52
        draw.text((STAT_X0 + 32, sub_y), sub, font=label_font, fill=LABEL_GRY)

    # ─── 4. Source is the archived original — no need to re-archive ─────
    # (HERO_IN already points to docs/agentic-dart-hero-v0.4.png)

    # ─── 5. Save ────────────────────────────────────────────────────────
    img.save(HERO_OUT, optimize=True)
    print(f"Saved evergreen hero → {HERO_OUT}")
    print(f"   Size: {HERO_OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
