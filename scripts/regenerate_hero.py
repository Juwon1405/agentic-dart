#!/usr/bin/env python3
"""
regenerate_hero.py — draw the Agentic-DFIR hero image from scratch.

The hero is generated, not hand-edited, so the three surfaces that show it
(repository README, GitHub social preview, wiki banner) stay in sync and no
release-fragile number is baked into a bitmap. Everything on the image is an
evergreen design principle or a command that exists in this repository.

Outputs (all derived from one render):

  agentic-dfir-hero.png       1920×540   README header
  agentic-dfir-thumbnail.png  1280×720   social preview (letterboxed)
  docs/wiki-banner.png        1200×300   wiki Home banner (letterboxed)

Run: python3 scripts/regenerate_hero.py
Requires Pillow. Uses DejaVu fonts when available (Linux package
fonts-dejavu, or the font-dejavu cask on macOS); falls back to Pillow's
default font otherwise.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("ERROR: Pillow not installed. pip install Pillow", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
HERO_OUT = ROOT / "agentic-dfir-hero.png"
THUMB_OUT = ROOT / "agentic-dfir-thumbnail.png"
WIKI_OUT = ROOT / "docs" / "wiki-banner.png"

W, H = 1920, 540

BG_TOP = (9, 20, 37)
BG_BOTTOM = (4, 11, 22)
PANEL = (7, 15, 28)
WHITE = (245, 248, 252)
RED = (220, 38, 38)
CYAN = (34, 211, 238)
GREEN = (34, 197, 94)
INK = (215, 224, 238)
MUTED = (140, 155, 178)
RING = (70, 78, 122)
RING_2 = (96, 84, 150)

FONT_DIRS = [
    Path.home() / "Library" / "Fonts",
    Path("/Library/Fonts"),
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/dejavu"),
    Path("/usr/share/fonts/TTF"),
]


def _font(size: int, *, bold: bool = False, mono: bool = False, oblique: bool = False):
    family = "DejaVuSansMono" if mono else "DejaVuSans"
    style = ""
    if bold and oblique:
        style = "-BoldOblique"
    elif bold:
        style = "-Bold"
    elif oblique:
        style = "-Oblique"
    name = f"{family}{style}.ttf"
    for d in FONT_DIRS:
        p = d / name
        if p.exists():
            return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()


def _gradient(img: Image.Image) -> None:
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / (H - 1)
        c = tuple(round(BG_TOP[i] + t * (BG_BOTTOM[i] - BG_TOP[i])) for i in range(3))
        draw.line([(0, y), (W, y)], fill=c + (255,))


def _spaced(draw, xy, text, font, fill, spacing):
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += draw.textlength(ch, font=font) + spacing


def _fingerprint(draw: ImageDraw.ImageDraw, cx: int, cy: int) -> None:
    """Concentric arc segments — the evidence motif. Deterministic gaps."""
    for i, r in enumerate(range(44, 176, 22)):
        color = RING if i % 2 == 0 else RING_2
        width = 6 if i < 3 else 5
        # three arcs per ring with fixed gaps, rotated per ring so the gaps
        # spiral instead of lining up
        start = (i * 37) % 360
        for k in range(3):
            a0 = start + k * 120
            a1 = a0 + 92
            draw.arc((cx - r, cy - r, cx + r, cy + r), a0, a1, fill=color, width=width)
    # centre: the finding
    draw.ellipse((cx - 14, cy - 14, cx + 14, cy + 14), fill=RED)
    draw.ellipse((cx - 5, cy - 5, cx + 5, cy + 5), fill=WHITE)
    # magnifier ring + handle in cyan
    R = 190
    draw.ellipse((cx - R, cy - R, cx + R, cy + R), outline=CYAN, width=4)
    hx = cx + int(R * math.cos(math.radians(40)))
    hy = cy + int(R * math.sin(math.radians(40)))
    draw.line([(hx, hy), (hx + 70, hy + 58)], fill=CYAN, width=14)


def make_hero() -> Image.Image:
    img = Image.new("RGBA", (W, H))
    _gradient(img)
    draw = ImageDraw.Draw(img)

    # frame lines
    draw.rectangle((0, 0, W, 3), fill=RED)
    draw.rectangle((0, H - 4, W, H), fill=RED)

    # top-left terminal chip
    draw.rounded_rectangle((52, 16, 548, 52), radius=6, fill=(16, 28, 48))
    draw.text((64, 22), "$ python3 -m dfir_agent --case case-04", font=_font(20, mono=True), fill=CYAN)

    # top-right status
    for k in range(3):
        draw.ellipse((1746 + k * 18, 30, 1754 + k * 18, 38), fill=GREEN)
    draw.text((1808, 27), "ONLINE", font=_font(13, mono=True), fill=GREEN)
    # small constellation
    pts = [(1740, 62), (1770, 58), (1752, 112), (1732, 90)]
    for a, b in [(0, 1), (1, 2), (2, 3), (3, 0)]:
        draw.line([pts[a], pts[b]], fill=(52, 96, 132), width=1)
    for p in pts:
        draw.ellipse((p[0] - 2, p[1] - 2, p[0] + 2, p[1] + 2), fill=CYAN)

    # left block
    _spaced(draw, (60, 132), "AUTONOMOUS DFIR", _font(22, bold=True), CYAN, 8)
    draw.text((56, 150), "Agentic", font=_font(104, bold=True), fill=WHITE)
    draw.text((56, 252), "DFIR", font=_font(104, bold=True), fill=RED)
    draw.text((60, 368), "Architecture-first, not prompt-first.", font=_font(26, oblique=True), fill=INK)
    draw.rectangle((60, 408, 165, 411), fill=RED)
    draw.text((60, 434), "A senior analyst's reasoning, encoded as architecture.", font=_font(22), fill=INK)
    draw.text((60, 466), "Built for the SIFT Workstation.", font=_font(19), fill=MUTED)
    draw.text((60, 500), "MIT  ·  read-only MCP surface  ·  SHA-256 audit chain", font=_font(15, mono=True), fill=MUTED)

    # centre motif
    _fingerprint(draw, 905, 282)

    # right panel with evergreen guarantees
    panel = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(panel).rectangle((1040, 45, 1720, 470), fill=PANEL + (200,))
    img.alpha_composite(panel)
    draw = ImageDraw.Draw(img)
    big = _font(44, bold=True)
    label = _font(19)
    entries = [
        ("READ-ONLY", "MCP boundary", CYAN),
        ("ARCHITECTURAL", "guardrails, not prompts", CYAN),
        ("VERIFIABLE", "SHA-256 audit chain", GREEN),
        ("ZERO", "destructive ops on the wire", GREEN),
    ]
    entry_h = (470 - 45) // len(entries)
    for i, (word, sub, color) in enumerate(entries):
        y0 = 45 + i * entry_h + 12
        draw.text((1070, y0), word, font=big, fill=color)
        draw.text((1072, y0 + 52), sub, font=label, fill=INK)

    # bottom-right address
    addr = "github.com/Juwon1405/agentic-dfir"
    f = _font(17, mono=True)
    draw.text((W - 60 - draw.textlength(addr, font=f), 500), addr, font=f, fill=MUTED)

    img.save(HERO_OUT, optimize=True)
    print(f"  hero      -> {HERO_OUT.name}  ({HERO_OUT.stat().st_size // 1024} KB, {W}x{H})")
    return img


def _fit_to_aspect(img: Image.Image, target_w: int, target_h: int, bg=BG_BOTTOM) -> Image.Image:
    """Fit (never crop) the render into the target aspect by letterboxing."""
    hw, hh = img.size
    src_ratio = hw / hh
    tgt_ratio = target_w / target_h
    if src_ratio > tgt_ratio:
        new_h = int(hw / tgt_ratio)
        canvas = Image.new("RGB", (hw, new_h), bg)
        canvas.paste(img.convert("RGB"), (0, (new_h - hh) // 2))
    else:
        new_w = int(hh * tgt_ratio)
        canvas = Image.new("RGB", (new_w, hh), bg)
        canvas.paste(img.convert("RGB"), ((new_w - hw) // 2, 0))
    return canvas.resize((target_w, target_h), Image.LANCZOS)


def make_thumbnail(hero: Image.Image) -> None:
    thumb = _fit_to_aspect(hero, 1280, 720)
    thumb.save(THUMB_OUT, "PNG", optimize=True)
    print(f"  thumbnail -> {THUMB_OUT.name}  ({THUMB_OUT.stat().st_size // 1024} KB, 1280x720)")


def make_wiki_banner(hero: Image.Image) -> None:
    banner = _fit_to_aspect(hero, 1200, 300)
    banner.save(WIKI_OUT, "PNG", optimize=True)
    print(f"  wiki      -> docs/{WIKI_OUT.name}  ({WIKI_OUT.stat().st_size // 1024} KB, 1200x300)")


if __name__ == "__main__":
    print("[rendering hero from scratch]")
    hero = make_hero()
    make_thumbnail(hero)
    make_wiki_banner(hero)
