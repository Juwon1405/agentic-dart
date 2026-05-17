#!/usr/bin/env python3
"""
regenerate_hero.py — Generate hero, thumbnail, and wiki banner images.

Design principles (v0.7.1 redesign):
  1. No fake CLI options. Earlier versions showed `$dart-agent --hunt`
     in the terminal banner; that flag does not exist. The redesign
     removes the fake terminal entirely.
  2. No dartboard metaphor. Architecture-first means showing the
     architectural surface, not throwing-at-a-target imagery.
  3. Evergreen numerics. Counts that drift between releases (47, 72,
     79) live in README, not in pixel form.
  4. Three consistent variants from the same design token set:
       - agentic-dart-hero.png       (1600x600 wide hero for main README)
       - agentic-dart-thumbnail.png  (1280x720 16:9 for social / Devpost)
       - docs/wiki-banner.png        (1200x300 wide-thin for Wiki Home)

Run: python3 scripts/regenerate_hero.py
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore
except ImportError:
    print("ERROR: Pillow not installed. pip install Pillow", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
HERO_OUT = ROOT / "agentic-dart-hero.png"
THUMB_OUT = ROOT / "agentic-dart-thumbnail.png"
WIKI_OUT = ROOT / "docs" / "wiki-banner.png"

# ─── Design tokens — single source of truth ─────────────────────────────

BG_TOP = (10, 14, 26)
BG_BOTTOM = (18, 26, 44)
FG_PRIMARY = (235, 240, 248)
FG_DIM = (148, 163, 184)
FG_FAINT = (71, 85, 105)
ACCENT_CYAN = (56, 189, 248)
ACCENT_GREEN = (74, 222, 128)
ACCENT_AMBER = (251, 191, 36)
BOUNDARY = (148, 163, 184)
GRID = (30, 41, 59)


def _font(size: int, bold: bool = False, mono: bool = False):
    if mono:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        ]
    else:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


def _gradient_bg(w, h):
    img = Image.new("RGB", (w, h), BG_TOP)
    px = img.load()
    for y in range(h):
        t = y / max(h - 1, 1)
        r = int(BG_TOP[0] * (1 - t) + BG_BOTTOM[0] * t)
        g = int(BG_TOP[1] * (1 - t) + BG_BOTTOM[1] * t)
        b = int(BG_TOP[2] * (1 - t) + BG_BOTTOM[2] * t)
        for x in range(w):
            px[x, y] = (r, g, b)
    return img


def _grid_overlay(img, spacing=40, alpha=24):
    draw = ImageDraw.Draw(img, "RGBA")
    w, h = img.size
    for x in range(0, w, spacing):
        draw.line([(x, 0), (x, h)], fill=GRID + (alpha,), width=1)
    for y in range(0, h, spacing):
        draw.line([(0, y), (w, y)], fill=GRID + (alpha,), width=1)


def _surface_diagram(img, ox, oy, w, h, label_scale=1.0):
    """4-layer architecture surface diagram.
       Agent (top) → MCP boundary → dart_mcp → Evidence (bottom).
       Audit chain side-tapped on the right."""
    draw = ImageDraw.Draw(img, "RGBA")
    s = label_scale

    layer_h = int(h / 5)
    gap = int(layer_h / 3)

    # Evidence layer (bottom)
    ev_y = oy + h - layer_h
    draw.rounded_rectangle(
        [ox, ev_y, ox + w, ev_y + layer_h],
        radius=8, outline=FG_FAINT, width=2,
        fill=(BG_BOTTOM[0], BG_BOTTOM[1], BG_BOTTOM[2], 180))
    draw.text((ox + 20, ev_y + 12), "EVIDENCE",
              fill=FG_DIM, font=_font(int(16 * s), bold=True))
    draw.text((ox + 20, ev_y + 34), "read-only mount",
              fill=FG_FAINT, font=_font(int(13 * s)))
    draw.text((ox + w - 290, ev_y + layer_h // 2 - 8),
              "MFT · EVTX · Memory · NetFlow",
              fill=FG_FAINT, font=_font(int(12 * s), mono=True))

    # MCP boundary line (dashed)
    mcp_y = ev_y - gap // 2
    for x in range(ox, ox + w, 12):
        draw.line([(x, mcp_y), (x + 6, mcp_y)], fill=BOUNDARY, width=2)
    draw.text((ox + w // 2 - 200, mcp_y - 28),
              "─── MCP BOUNDARY · TYPED · READ-ONLY ───",
              fill=ACCENT_CYAN, font=_font(int(13 * s), bold=True))

    # dart_mcp layer
    mcp_box_y = mcp_y - gap - layer_h
    draw.rounded_rectangle(
        [ox, mcp_box_y, ox + w, mcp_box_y + layer_h],
        radius=8, outline=ACCENT_CYAN, width=2,
        fill=(15, 23, 42, 200))
    draw.text((ox + 20, mcp_box_y + 12), "dart_mcp",
              fill=ACCENT_CYAN, font=_font(int(18 * s), bold=True, mono=True))
    draw.text((ox + 20, mcp_box_y + 38),
              "native forensic functions  +  SIFT Workstation adapters",
              fill=FG_DIM, font=_font(int(13 * s)))
    draw.text((ox + w - 310, mcp_box_y + layer_h // 2 - 8),
              "Volatility · MFTECmd · EvtxECmd · YARA",
              fill=FG_FAINT, font=_font(int(11 * s), mono=True))

    # dart_agent layer (top)
    ag_y = mcp_box_y - gap - layer_h
    draw.rounded_rectangle(
        [ox, ag_y, ox + w, ag_y + layer_h],
        radius=8, outline=ACCENT_GREEN, width=2,
        fill=(15, 23, 42, 200))
    draw.text((ox + 20, ag_y + 12), "dart_agent",
              fill=ACCENT_GREEN, font=_font(int(18 * s), bold=True, mono=True))
    draw.text((ox + 20, ag_y + 38),
              "iteration · hypothesis revision · self-correction",
              fill=FG_DIM, font=_font(int(13 * s)))

    # Side-tapped audit chain — three amber lines pointing out right
    for tap_y in [ag_y + layer_h // 2, mcp_box_y + layer_h // 2,
                  ev_y + layer_h // 2]:
        draw.line([(ox + w, tap_y), (ox + w + 25, tap_y)],
                  fill=ACCENT_AMBER, width=2)


# ─── Hero (1600x600 wide) ───────────────────────────────────────────────

def make_hero():
    W, H = 1600, 600
    img = _gradient_bg(W, H)
    _grid_overlay(img, spacing=40, alpha=18)
    draw = ImageDraw.Draw(img, "RGBA")

    # Left — title
    draw.text((60, 60), "Agentic",
              fill=FG_DIM, font=_font(48))
    draw.text((60, 110), "DART",
              fill=FG_PRIMARY, font=_font(96, bold=True))
    draw.text((60, 220),
              "Autonomous DFIR agent.",
              fill=FG_PRIMARY, font=_font(24))
    draw.text((60, 252),
              "Architecture-first, not prompt-first.",
              fill=ACCENT_CYAN, font=_font(22, bold=True))

    # Three pillars
    pill_y = 340
    pillars = [
        ("READ-ONLY",     "MCP boundary",                    ACCENT_CYAN),
        ("VERIFIABLE",    "SHA-256 audit chain",             ACCENT_GREEN),
        ("AUDITABLE",     "every step replayable",           ACCENT_AMBER),
    ]
    for i, (kw, sub, color) in enumerate(pillars):
        x = 60 + i * 200
        draw.text((x, pill_y), kw, fill=color,
                  font=_font(15, bold=True, mono=True))
        draw.text((x, pill_y + 22), sub, fill=FG_DIM,
                  font=_font(13))

    # Footer
    draw.text((60, H - 50),
              "SANS FIND EVIL! 2026  ·  participating submission",
              fill=FG_FAINT, font=_font(14))
    draw.text((60, H - 28),
              "github.com/Juwon1405/agentic-dart",
              fill=FG_FAINT, font=_font(14, mono=True))

    # Right — surface diagram
    _surface_diagram(img, ox=820, oy=60, w=720, h=480, label_scale=1.0)

    img.save(HERO_OUT, "PNG", optimize=True)
    print(f"  ✓ hero      → {HERO_OUT.name}  ({HERO_OUT.stat().st_size // 1024} KB)")


# ─── Thumbnail (1280x720 16:9) ──────────────────────────────────────────

def make_thumbnail():
    W, H = 1280, 720
    img = _gradient_bg(W, H)
    _grid_overlay(img, spacing=36, alpha=20)
    draw = ImageDraw.Draw(img, "RGBA")

    # Centered title block
    draw.text((W // 2 - 110, 100), "Agentic",
              fill=FG_DIM, font=_font(46))
    draw.text((W // 2 - 165, 150), "DART",
              fill=FG_PRIMARY, font=_font(110, bold=True))
    draw.text((W // 2 - 220, 290),
              "Autonomous DFIR agent",
              fill=FG_PRIMARY, font=_font(28))
    draw.text((W // 2 - 280, 328),
              "Architecture-first, not prompt-first",
              fill=ACCENT_CYAN, font=_font(22, bold=True))

    # Surface diagram band
    _surface_diagram(img, ox=240, oy=400, w=800, h=240, label_scale=0.85)

    # Footer
    draw.text((W // 2 - 320, H - 50),
              "SANS FIND EVIL! 2026  ·  github.com/Juwon1405/agentic-dart",
              fill=FG_FAINT, font=_font(15, mono=True))

    img.save(THUMB_OUT, "PNG", optimize=True)
    print(f"  ✓ thumbnail → {THUMB_OUT.name}  ({THUMB_OUT.stat().st_size // 1024} KB)")


# ─── Wiki banner (1200x300 wide-thin) ───────────────────────────────────

def make_wiki_banner():
    W, H = 1200, 300
    img = _gradient_bg(W, H)
    _grid_overlay(img, spacing=32, alpha=16)
    draw = ImageDraw.Draw(img, "RGBA")

    # Title
    draw.text((40, 60), "Agentic-DART",
              fill=FG_PRIMARY, font=_font(56, bold=True))
    draw.text((40, 130),
              "Autonomous DFIR agent  ·  Architecture-first, not prompt-first",
              fill=ACCENT_CYAN, font=_font(18, bold=True))
    draw.text((40, 165),
              "Wiki  ·  the long-form companion to the README",
              fill=FG_DIM, font=_font(15))

    # Right — three chips
    chip_x = 740
    chip_y = 100
    chips = [
        ("READ-ONLY",    ACCENT_CYAN),
        ("VERIFIABLE",   ACCENT_GREEN),
        ("AUDITABLE",    ACCENT_AMBER),
    ]
    for i, (kw, color) in enumerate(chips):
        y = chip_y + i * 38
        font = _font(13, bold=True, mono=True)
        bbox = draw.textbbox((chip_x, y), kw, font=font)
        pad = 12
        draw.rounded_rectangle(
            [chip_x - pad, y - pad // 2, bbox[2] + pad, bbox[3] + pad // 2],
            radius=4, outline=color, width=1,
            fill=(15, 23, 42, 180))
        draw.text((chip_x, y), kw, fill=color, font=font)

    # Footer
    draw.text((40, H - 32),
              "github.com/Juwon1405/agentic-dart/wiki",
              fill=FG_FAINT, font=_font(13, mono=True))

    img.save(WIKI_OUT, "PNG", optimize=True)
    print(f"  ✓ wiki      → docs/{WIKI_OUT.name}  ({WIKI_OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    print("[regenerating hero / thumbnail / wiki-banner — v0.7.1 unified design]\n")
    make_hero()
    make_thumbnail()
    make_wiki_banner()
    print("\ndone. Three images share unified design tokens:")
    print("  - same color palette (slate base + cyan/green/amber accents)")
    print("  - same surface diagram metaphor (no dartboard)")
    print("  - same typography stack")
    print("  - no fake CLI flags")
    print("  - no version-pinned numbers in pixel form")
