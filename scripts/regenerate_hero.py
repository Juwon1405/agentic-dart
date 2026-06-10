#!/usr/bin/env python3
"""
regenerate_hero.py — Surgical, v0.4-design-preserving hero regeneration.

The v0.4 hero (docs/legacy/agentic-dart-hero-v0.4.png) has the strong
design — the dartboard target, the dark-blue palette, the typography.
We keep all of that. We only fix two real problems:

  (1) Fake CLI '$dart-agent --hunt' in the top-left terminal banner.
      That command does not exist in this package. Wipe and replace it with
      the documented module invocation.

  (2) Stat-block numbers that drift between releases (35 / 11/12 /
      20/20). Wipe and replace with evergreen design-principle words.

Then derive thumbnail (1280x720) and wiki-banner (1200x300) from the
same hero, so the three surfaces share visual identity.

Run: python3 scripts/regenerate_hero.py
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("ERROR: Pillow not installed. pip install Pillow", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
HERO_BASELINE = ROOT / "docs" / "legacy" / "agentic-dart-hero-v0.4.png"
HERO_OUT = ROOT / "agentic-dart-hero.png"
THUMB_OUT = ROOT / "agentic-dart-thumbnail.png"
WIKI_OUT = ROOT / "docs" / "wiki-banner.png"

BG_TOP = (9, 20, 37)
BG_BOTTOM = (4, 11, 22)
CYAN = (34, 211, 238)
GREEN = (34, 197, 94)
LABEL_GRY = (180, 195, 215)


def _font(size, bold=False, mono=False):
    if mono:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        ]
    else:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def _wipe(draw, x0, y0, x1, y1):
    """Wipe with the v0.4 vertical gradient so the patch blends."""
    h = y1 - y0
    for dy in range(h):
        t = dy / max(h - 1, 1)
        r = round(BG_TOP[0] + t * (BG_BOTTOM[0] - BG_TOP[0]))
        g = round(BG_TOP[1] + t * (BG_BOTTOM[1] - BG_TOP[1]))
        b = round(BG_TOP[2] + t * (BG_BOTTOM[2] - BG_TOP[2]))
        draw.line([(x0, y0 + dy), (x1, y0 + dy)], fill=(r, g, b, 255))


def make_hero():
    if not HERO_BASELINE.exists():
        print(f"ERROR: baseline not found at {HERO_BASELINE}", file=sys.stderr)
        sys.exit(1)

    img = Image.open(HERO_BASELINE).convert("RGBA")
    draw = ImageDraw.Draw(img)
    w, h = img.size
    print(f"  baseline loaded: {w}×{h}")

    # (1) Wipe the fake CLI banner and replace with a real command.
    # OCR pinpointed '$dart-agent --hunt' at x=55-265, y=18-50.
    # Wipe generously to avoid old-text artefacts.
    _wipe(draw, 55, 18, 360, 52)
    mono = _font(20, mono=True)
    draw.text((63, 22), "$ python3 -m dart_agent --case case-04",
              fill=CYAN, font=mono)

    # (2) Wipe stat block, write evergreen words.
    STAT_X0, STAT_Y0 = 1040, 45
    STAT_X1, STAT_Y1 = 1720, 470
    _wipe(draw, STAT_X0, STAT_Y0, STAT_X1, STAT_Y1)

    big = _font(44, bold=True)
    label = _font(19)
    entries = [
        ("READ-ONLY",     "MCP boundary",                    CYAN),
        ("ARCHITECTURAL", "guardrails, not prompts",         CYAN),
        ("VERIFIABLE",    "SHA-256 audit chain",             GREEN),
        ("ZERO",          "destructive ops on the wire",     GREEN),
    ]
    block_h = STAT_Y1 - STAT_Y0
    entry_h = block_h // len(entries)
    for i, (big_word, sub, color) in enumerate(entries):
        ey0 = STAT_Y0 + i * entry_h + 12
        draw.text((STAT_X0 + 30, ey0), big_word, font=big, fill=color)
        draw.text((STAT_X0 + 32, ey0 + 52), sub, font=label, fill=LABEL_GRY)

    img.save(HERO_OUT, optimize=True)
    print(f"  ✓ hero      → {HERO_OUT.name}  "
          f"({HERO_OUT.stat().st_size // 1024} KB, {w}×{h})")
    return img


def _fit_to_aspect(img, target_w, target_h, bg=BG_BOTTOM):
    """Fit (not crop) the source into target aspect ratio by letterbox
    padding. Preserves ALL content — text and the dartboard never get
    cropped off."""
    hw, hh = img.size
    src_ratio = hw / hh
    tgt_ratio = target_w / target_h
    if src_ratio > tgt_ratio:
        # Source wider — letterbox top/bottom
        new_h = int(hw / tgt_ratio)
        canvas = Image.new("RGB", (hw, new_h), bg)
        y_offset = (new_h - hh) // 2
        canvas.paste(img.convert("RGB"), (0, y_offset))
    else:
        # Source taller — pillarbox left/right
        new_w = int(hh * tgt_ratio)
        canvas = Image.new("RGB", (new_w, hh), bg)
        x_offset = (new_w - hw) // 2
        canvas.paste(img.convert("RGB"), (x_offset, 0))
    return canvas.resize((target_w, target_h), Image.LANCZOS)


def make_thumbnail(hero):
    thumb = _fit_to_aspect(hero, 1280, 720)
    thumb.save(THUMB_OUT, "PNG", optimize=True)
    print(f"  ✓ thumbnail → {THUMB_OUT.name}  "
          f"({THUMB_OUT.stat().st_size // 1024} KB, 1280×720)")


def make_wiki_banner(hero):
    banner = _fit_to_aspect(hero, 1200, 300)
    banner.save(WIKI_OUT, "PNG", optimize=True)
    print(f"  ✓ wiki      → docs/{WIKI_OUT.name}  "
          f"({WIKI_OUT.stat().st_size // 1024} KB, 1200×300)")


if __name__ == "__main__":
    print("[regenerating from v0.4 baseline — surgical fixes only]\n")
    hero = make_hero()
    make_thumbnail(hero)
    make_wiki_banner(hero)
    print("\nDesign preserved from v0.4:")
    print("  - dartboard symbol (the 'DART' in Agentic-DART)")
    print("  - dark navy + cyan/green palette")
    print("  - title typography and gradients")
    print("\nFixed:")
    print("  - $dart-agent --hunt   ->   $ python3 -m dart_agent --case case-04")
    print("  - 35 / 11-12 / 20-20   →   READ-ONLY / ARCHITECTURAL /")
    print("                              VERIFIABLE / ZERO  (evergreen)")
    print("\nThumbnail and wiki-banner are derived from the same hero,")
    print("so the three surfaces share identical visual identity.")
