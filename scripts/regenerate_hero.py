#!/usr/bin/env python3
"""
regenerate_hero.py -- draw the Agentic-DFIR hero images from scratch.

The hero is generated, not hand-edited, so the three surfaces that show it stay
in sync and no release-fragile number is baked into a bitmap:

  agentic-dfir-hero.png       1920x540   README header (also the profile README and the wiki Home)
  agentic-dfir-thumbnail.png  1280x720   GitHub social preview (its own 16:9 layout)
  docs/wiki-banner.png        1200x300   wiki banner

Design: a ruled editorial page. Bone paper, a large Charter wordmark, the
tagline in italic oxblood, hairline rules. The lower rule is the chain of
custody -- 64 dashes whose lengths are the 64 hex nibbles of
SHA-256("Agentic-DFIR") -- and the same digest is set in full as a small
monospaced block, the key to the rule.

Two faces only: Charter (wordmark, tagline, tracked-caps kicker) and JetBrains
Mono (digest, footer URL, details line). Deterministic: the same script always
produces byte-identical PNGs. Pillow + standard library only. Renders at 2x and
downsamples with LANCZOS. Fonts fall back to DejaVu, then to Pillow's built-in
face, so the script also runs on Linux (the committed images were rendered on
macOS with Charter and JetBrains Mono).

Run: python3 scripts/regenerate_hero.py
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = {
    "hero.png": ROOT / "agentic-dfir-hero.png",
    "thumb.png": ROOT / "agentic-dfir-thumbnail.png",
    "banner.png": ROOT / "docs" / "wiki-banner.png",
}
S = 2  # supersampling factor

# --- palette -----------------------------------------------------------------
PAPER = (244, 239, 230)        # bone
INK = (28, 27, 24)             # near-black, warm
INK_SOFT = (92, 88, 82)        # secondary text
INK_FAINT = (128, 122, 113)    # the digest block
RULE = (170, 164, 154)         # hairlines
ACCENT = (122, 31, 43)         # oxblood -- the only accent

# --- copy --------------------------------------------------------------------
WORDMARK = "Agentic-DFIR"
TAGLINE = "Architecture-first, not prompt-first."
KICKER = "Autonomous DFIR agent for the SIFT Workstation"
DETAILS = "read-only tool surface · SHA-256 audit chain · MIT"
FOOTER = "github.com/Juwon1405/agentic-dfir"
DIGEST = hashlib.sha256(WORDMARK.encode("utf-8")).hexdigest()   # 64 nibbles

# --- fonts -------------------------------------------------------------------
HOME = Path(os.path.expanduser("~"))
DEJAVU_DIRS = [
    HOME / "Library" / "Fonts",
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/dejavu"),
    Path("/usr/share/fonts/TTF"),
    Path("/usr/share/fonts"),
]

FACES = {
    # role: ([(path, index), ...], dejavu fallback file)
    "display": ([("/System/Library/Fonts/Supplemental/Charter.ttc", 0)], "DejaVuSerif.ttf"),
    "display_it": ([("/System/Library/Fonts/Supplemental/Charter.ttc", 1)], "DejaVuSerif-Italic.ttf"),
    "mono": ([
        (str(HOME / "Library/Fonts/JetBrainsMonoNerdFontMono-Regular.ttf"), 0),
        (str(HOME / "Library/Fonts/JetBrainsMonoNerdFont-Regular.ttf"), 0),
        (str(HOME / "Library/Fonts/JetBrainsMono-Regular.ttf"), 0),
        ("/Library/Fonts/JetBrainsMono-Regular.ttf", 0),
        ("/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf", 0),
    ], "DejaVuSansMono.ttf"),
}

_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def _find_dejavu(name: str) -> str | None:
    for d in DEJAVU_DIRS:
        p = d / name
        if p.exists():
            return str(p)
        if d.exists():
            for hit in d.rglob(name):
                return str(hit)
    return None


def font(role: str, size_px: int) -> ImageFont.FreeTypeFont:
    """Load a face by role at *size_px* (already multiplied by S by the caller)."""
    key = (role, size_px)
    if key in _CACHE:
        return _CACHE[key]
    candidates, dejavu = FACES[role]
    f = None
    for path, index in candidates:
        if Path(path).exists():
            try:
                f = ImageFont.truetype(path, size_px, index=index)
                break
            except OSError:
                pass
    if f is None:
        alt = _find_dejavu(dejavu)
        f = ImageFont.truetype(alt, size_px) if alt else ImageFont.load_default(size_px)
    _CACHE[key] = f
    return f


# --- drawing helpers (all coordinates are in 1x pixels; scaled inside) --------
class Canvas:
    def __init__(self, w: int, h: int):
        self.w, self.h = w, h
        self.im = Image.new("RGB", (w * S, h * S), PAPER)
        self.d = ImageDraw.Draw(self.im)

    def text(self, x: float, y: float, s: str, role: str, size: int,
             fill=INK, anchor: str = "ls", tracking: float = 0.0,
             optical: bool = False) -> float:
        """Draw *s* with its baseline at *y*. Returns the x after the last glyph.

        optical=True shifts the run so the first glyph's ink (not its advance
        box) lands exactly on x -- used for the wordmark, tagline and kicker so
        they align optically with the rules. With anchor "rs" the run is
        right-aligned so the last glyph's ink ends on x.
        """
        f = font(role, size * S)
        X, Y = x * S, y * S
        total = self.width(s, role, size, tracking) * S
        if anchor.startswith("r"):
            X -= total
            if optical:
                right_bearing = f.getlength(s[-1]) - f.getbbox(s[-1], anchor="ls")[2]
                X += right_bearing
        elif optical:
            X -= f.getbbox(s[0], anchor="ls")[0]
        if tracking == 0.0:
            self.d.text((X, Y), s, font=f, fill=fill, anchor="ls")
            return (X + total) / S
        for i, c in enumerate(s):
            self.d.text((X, Y), c, font=f, fill=fill, anchor="ls")
            X += f.getlength(c) + (tracking * S if i < len(s) - 1 else 0)
        return X / S

    def width(self, s: str, role: str, size: int, tracking: float = 0.0) -> float:
        f = font(role, size * S)
        if tracking == 0.0:
            return f.getlength(s) / S
        return (sum(f.getlength(c) for c in s) + tracking * S * (len(s) - 1)) / S

    def cap_height(self, role: str, size: int) -> float:
        return -font(role, size * S).getbbox("H", anchor="ls")[1] / S

    def rule(self, x0: float, x1: float, y: float, fill=RULE, weight: float = 1.0):
        h = max(1, round(weight * S))
        Y = round(y * S)
        self.d.rectangle([round(x0 * S), Y, round(x1 * S) - 1, Y + h - 1], fill=fill)

    def chain(self, x0: float, x1: float, y: float, gap: float = 8.0,
              weight: float = 1.5, mark: int | None = 0):
        """A ruled line broken into 64 dashes. Dash lengths are the nibbles of
        SHA-256(WORDMARK) -- a 0 is a tick, an f is a long stroke -- and one
        dash (index *mark*) is set in the accent colour."""
        nibbles = [int(c, 16) for c in DIGEST]            # 64 values, 0..15
        n = len(nibbles)
        span = (x1 - x0) - gap * (n - 1)
        base = 0.22                                       # min dash weight
        units = [base + v / 15.0 for v in nibbles]
        unit = span / sum(units)
        h = max(1, round(weight * S))
        Y = round(y * S)
        X = x0 * S
        for i, u in enumerate(units):
            L = u * unit * S
            colour = ACCENT if i == mark else RULE
            self.d.rectangle([round(X), Y, round(X + L) - 1, Y + h - 1], fill=colour)
            X += L + gap * S

    def digest(self, x_right: float, y_baseline: float, size: int, rows: int,
               pitch: float, tracking: float = 1.0, mark: int | None = 0):
        """The full 64-nibble digest, right-aligned, *rows* rows, bottom row on
        *y_baseline*. Nibble *mark* is set in the accent colour so the block
        keys to the accent dash of the chain."""
        per = len(DIGEST) // rows
        f = font("mono", size * S)
        adv = f.getlength("0") + tracking * S
        row_w = adv * per - tracking * S
        for r in range(rows):
            Y = (y_baseline - (rows - 1 - r) * pitch) * S
            X = x_right * S - row_w
            for i in range(per):
                idx = r * per + i
                colour = ACCENT if idx == mark else INK_FAINT
                self.d.text((X, Y), DIGEST[idx], font=f, fill=colour, anchor="ls")
                X += adv

    def save(self, name: str):
        out = self.im.resize((self.w, self.h), Image.LANCZOS)
        target = OUTPUTS[name]
        out.save(target, "PNG", optimize=True)
        print(f"wrote {target.relative_to(ROOT)}  {self.w}x{self.h}  ({target.stat().st_size // 1024} KB)")


def kicker(c: Canvas, x: float, y: float, size: int, tracking: float):
    c.text(x, y, KICKER.upper(), "display", size, fill=INK_SOFT,
           tracking=tracking, optical=True)


# --- compositions ------------------------------------------------------------
def hero():
    W, H, M = 1920, 540, 96
    c = Canvas(W, H)
    R = W - M

    # top row: tracked-caps kicker on a hairline
    kicker(c, M, 98, 16, 2.6)
    c.rule(M, R, 112)

    # wordmark + tagline, centred between the two rules
    wm, tg = 200, 44
    base_wm = 290
    c.text(M, base_wm, WORDMARK, "display", wm, fill=INK, optical=True)
    c.text(M + 2, base_wm + 88, TAGLINE, "display_it", tg, fill=ACCENT, optical=True)

    # the digest, 4 x 16, sharing the wordmark's baseline in the right column
    c.digest(R, base_wm, size=23, rows=4, pitch=36, tracking=1.5)

    # chain rule, then footer URL left / details right on one baseline
    c.chain(M, R, 428)
    c.text(M, 456, FOOTER, "mono", 16, fill=INK_SOFT)
    c.text(R, 456, DETAILS, "mono", 16, fill=INK_SOFT, anchor="rs")
    c.save("hero.png")


def thumb():
    W, H, M = 1280, 720, 84
    c = Canvas(W, H)
    R = W - M

    kicker(c, M, 98, 15, 2.4)
    c.rule(M, R, 112)

    # wordmark group; the digest sits as a two-row caption above the chain
    wm, tg = 176, 40
    base_wm = 336
    c.text(M, base_wm, WORDMARK, "display", wm, fill=INK, optical=True)
    c.text(M + 2, base_wm + 80, TAGLINE, "display_it", tg, fill=ACCENT, optical=True)

    c.digest(R, 566, size=15, rows=2, pitch=22, tracking=1.0)
    c.chain(M, R, 592, gap=6.0)
    c.text(M, 622, FOOTER, "mono", 14, fill=INK_SOFT)
    c.text(R, 622, DETAILS, "mono", 14, fill=INK_SOFT, anchor="rs")
    c.save("thumb.png")


def banner():
    W, H, M = 1200, 300, 60
    c = Canvas(W, H)
    R = W - M

    kicker(c, M, 43, 11, 1.8)
    c.rule(M, R, 54)

    wm, tg = 112, 25
    base_wm = 158
    c.text(M, base_wm, WORDMARK, "display", wm, fill=INK, optical=True)
    c.text(M + 1, base_wm + 52, TAGLINE, "display_it", tg, fill=ACCENT, optical=True)

    c.digest(R, base_wm, size=13, rows=4, pitch=21, tracking=1.0)

    c.chain(M, R, 241, gap=4.5, weight=1.25)
    c.text(M, 266, FOOTER, "mono", 12, fill=INK_SOFT)
    c.text(R, 266, DETAILS, "mono", 12, fill=INK_SOFT, anchor="rs")
    c.save("banner.png")


if __name__ == "__main__":
    hero()
    thumb()
    banner()
