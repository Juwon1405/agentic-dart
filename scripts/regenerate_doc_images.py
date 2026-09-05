#!/usr/bin/env python3
"""Regenerate Agentic-DFIR documentation images.

The images are deterministic diagrams and terminal stills. They avoid
release-fragile claims unless the value is part of the current public surface.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SCREENSHOTS = DOCS / "screenshots"

BG = (12, 17, 28)
PANEL = (23, 31, 46)
PANEL_2 = (31, 42, 61)
INK = (229, 237, 246)
MUTED = (148, 163, 184)
BLUE = (96, 165, 250)
CYAN = (45, 212, 191)
GREEN = (74, 222, 128)
YELLOW = (250, 204, 21)
ORANGE = (251, 146, 60)
RED = (248, 113, 113)
PURPLE = (196, 181, 253)
WHITE = (255, 255, 255)


def font(size: int, *, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    family = "DejaVuSansMono" if mono else "DejaVuSans"
    weight = "Bold" if bold else ""
    candidates = [
        f"/usr/share/fonts/truetype/dejavu/{family}-{weight}.ttf" if weight
        else f"/usr/share/fonts/truetype/dejavu/{family}.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf" if mono and bold
        else "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf" if mono
        else "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            pass
    return ImageFont.load_default()


FONT_TITLE = font(42, bold=True)
FONT_H2 = font(25, bold=True)
FONT_BODY = font(20)
FONT_SMALL = font(16)
FONT_MONO = font(20, mono=True)
FONT_MONO_SMALL = font(17, mono=True)


def rounded(draw: ImageDraw.ImageDraw, box, fill, outline, width=2, radius=16):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def centered_text(draw, xy, text, fnt, fill):
    x, y, w, h = xy
    bbox = draw.multiline_textbbox((0, 0), text, font=fnt, spacing=4, align="center")
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.multiline_text((x + (w - tw) / 2, y + (h - th) / 2), text, font=fnt,
                        fill=fill, spacing=4, align="center")


def arrow(draw, start, end, color, width=4):
    draw.line([start, end], fill=color, width=width)
    sx, sy = start
    ex, ey = end
    if abs(ex - sx) >= abs(ey - sy):
        direction = 1 if ex >= sx else -1
        pts = [(ex, ey), (ex - direction * 18, ey - 9), (ex - direction * 18, ey + 9)]
    else:
        direction = 1 if ey >= sy else -1
        pts = [(ex, ey), (ex - 9, ey - direction * 18), (ex + 9, ey - direction * 18)]
    draw.polygon(pts, fill=color)


def architecture():
    img = Image.new("RGB", (1920, 1250), (246, 248, 252))
    draw = ImageDraw.Draw(img)
    title_color = (25, 32, 44)
    body_color = (53, 65, 83)
    boundary = (185, 58, 58)

    draw.text((960, 48), "Agentic-DFIR - Autonomous DFIR Agent on SIFT Workstation",
              anchor="ma", font=FONT_TITLE, fill=title_color)
    draw.text((960, 100), "Architecture-first, not prompt-first",
              anchor="ma", font=font(25), fill=(95, 107, 126))

    boxes = {
        "analyst": (760, 155, 1160, 230, "IR Analyst / User", "", (255, 255, 255), (79, 91, 110)),
        "client": (620, 285, 1300, 380, "Claude API or dry-run mock",
                   "session ergonomics only; no security boundary here",
                   (219, 234, 254), (59, 130, 246)),
        "agent": (535, 445, 1385, 560, "dfir_agent",
                  "playbook v3, hypothesis tracker, max-iteration controller",
                  (219, 234, 254), (59, 130, 246)),
        "progress": (90, 445, 510, 565, "progress.jsonl / report.json",
                     "hypothesis, confidence, gaps, final findings",
                     (254, 243, 199), (217, 119, 6)),
        "playbook": (1410, 445, 1830, 565, "dfir_playbook",
                     "sequencing rules and analyst heuristics",
                     (254, 243, 199), (217, 119, 6)),
        "mcp": (520, 690, 1400, 850, "dfir_mcp - primary enforcement layer",
                "73 schema-validated read-only tools\n48 native + 25 SIFT adapters\nno execute_shell, write_file, mount, or network egress",
                (220, 252, 231), (22, 163, 74)),
        "corr": (520, 890, 1400, 985, "dfir_corr",
                 "DuckDB-backed timeline joins; contradictions stay UNRESOLVED",
                 (243, 232, 255), (126, 34, 206)),
        "evidence": (520, 1030, 1400, 1148, "DFIR_EVIDENCE_ROOT",
                     "read-only evidence: EVTX, MFT, Prefetch, Registry, Browser, Web, Auth, Memory",
                     (237, 233, 254), (124, 58, 237)),
        "derived": (1410, 750, 1830, 870, "DFIR_DERIVED_ROOT",
                    "generated Plaso storage and other derived artifacts; never inside evidence",
                    (224, 242, 254), (2, 132, 199)),
        "audit": (125, 715, 475, 965, "dfir_audit",
                  "SHA-256 chained JSONL\none entry per MCP call\nfinding -> audit_id -> raw tool result",
                  (255, 237, 213), (234, 88, 12)),
    }

    for x1, y1, x2, y2, title, sub, fill, outline in boxes.values():
        rounded(draw, (x1, y1, x2, y2), fill, outline, width=3, radius=18)
        title_font = FONT_H2
        if draw.textlength(title, font=title_font) > (x2 - x1 - 32):
            title_font = font(22, bold=True)
        draw.text(((x1 + x2) / 2, y1 + 22), title, anchor="ma", font=title_font, fill=title_color)
        if sub:
            wrap_width = max(24, int((x2 - x1 - 60) / 10))
            lines = "\n".join(textwrap.wrap(sub, width=wrap_width)) if "\n" not in sub else sub
            centered_text(draw, (x1 + 25, y1 + 55, x2 - x1 - 50, y2 - y1 - 65),
                          lines, FONT_BODY, body_color)

    draw.rounded_rectangle((90, 630, 1830, 1185), radius=22, outline=boundary, width=5)
    draw.text((960, 647), "READ-ONLY BOUNDARY - enforced by MCP surface and OS-level mount",
              anchor="ma", font=font(23, bold=True), fill=boundary)

    arrow(draw, (960, 230), (960, 285), (79, 91, 110))
    arrow(draw, (960, 380), (960, 445), (79, 91, 110))
    arrow(draw, (960, 560), (960, 690), boundary)
    arrow(draw, (960, 850), (960, 890), (126, 34, 206))
    arrow(draw, (960, 985), (960, 1030), (124, 58, 237))
    arrow(draw, (535, 505), (510, 505), (217, 119, 6))
    arrow(draw, (1410, 505), (1385, 505), (217, 119, 6))
    arrow(draw, (520, 760), (510, 840), (234, 88, 12))
    arrow(draw, (1400, 785), (1410, 810), (2, 132, 199))

    draw.text((960, 1212),
              "Loop: hypothesis -> typed tool call -> audit entry -> correlation -> revise or emit cited finding",
              anchor="ma", font=font(20), fill=(95, 107, 126))
    img.save(DOCS / "dfir-architecture.png", optimize=True)


def terminal(path: Path, title: str, lines: list[tuple[str, tuple[int, int, int] | None]]):
    img = Image.new("RGB", (1100, 630), (25, 24, 38))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 0, 1100, 38), fill=(31, 30, 46))
    for i, c in enumerate(((248, 113, 113), (250, 204, 21), (74, 222, 128))):
        draw.ellipse((16 + i * 25, 12, 30 + i * 25, 26), fill=c)
    draw.text((550, 20), title, anchor="mm", font=font(15, mono=True), fill=MUTED)

    y = 64
    for raw, color in lines:
        wrapped = []
        for part in raw.split("\n"):
            wrapped.extend(textwrap.wrap(part, width=96, replace_whitespace=False) or [""])
        for line in wrapped:
            draw.text((32, y), line, font=FONT_MONO_SMALL, fill=color or INK)
            y += 24
        y += 6
    img.save(path, optimize=True)


def screenshots():
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    terminal(
        SCREENSHOTS / "dfir-run-01-init.png",
        "SIFT Workstation - agentic-dfir live dry-run",
        [
            ("analyst@sift:~/agentic-dfir$ python3 -m dfir_agent --mode live --dry-run \\\n"
             "  --case screenshot-dry-run --out /tmp/agentic-dfir-screenshot --max-iterations 4", CYAN),
            ("[live] case=screenshot-dry-run  mode=DRY-RUN  max_iter=4", GREEN),
            ("[live] MCP handshake OK - 73 tools visible", GREEN),
            ("[live] evidence root: case-studies/self-evaluation/case-01/evidence_root (read-only)", MUTED),
            ("[live] derived root : ${TMPDIR:-/tmp}/agentic-dfir-derived", MUTED),
            ("[live] no API call is made in --dry-run; MCP stdio plumbing is real", YELLOW),
        ],
    )
    terminal(
        SCREENSHOTS / "dfir-run-02-investigate.png",
        "typed MCP calls - schema validated",
        [
            ("[mock] iter 1: get_amcache -> ERR", ORANGE),
            ("  error: amcache_csv_missing; no synthetic records returned", MUTED),
            ("[mock] iter 2: analyze_usb_history -> OK", GREEN),
            ("  output: IP-KVM indicators include VID 0557 / PID 2419", GREEN),
            ("[mock] iter 3: correlate_timeline -> OK", GREEN),
            ("  output: cross_source_correlations=1; kvm_precedes_logon=1", GREEN),
            ("[mock] iter 4: parse_shimcache -> OK", GREEN),
            ("  every call is routed through dfir_mcp.call_tool() schema validation", CYAN),
        ],
    )
    terminal(
        SCREENSHOTS / "dfir-run-03-contradiction.png",
        "correlation and revision discipline",
        [
            ("dfir_corr: timeline joins run after tool output enters state", PURPLE),
            ("rule: same target within 600s across usb and security_log", MUTED),
            ("match: usb_insert -> logon on DESKTOP-7K2L", GREEN),
            ("guard: if kvm_precedes_logon is empty, dry-run emits no finding", YELLOW),
            ("regression: tests/test_live_mcp.py blocks uncorroborated mock findings", CYAN),
            ("serializer rule: findings must be evidence-backed and cite tool calls", MUTED),
        ],
    )
    terminal(
        SCREENSHOTS / "dfir-run-04-final.png",
        "final verdict and audit discipline",
        [
            ("REPORT: F-013 - IP-KVM insertion preceded an operator logon", GREEN),
            ("confidence: 0.82", CYAN),
            ("evidence: analyze_usb_history + correlate_timeline + parse_shimcache", INK),
            ("[dfir-agent] deterministic demo: iterations=5 findings=2", GREEN),
            ("[dfir-agent] audit chain: chain verified: 3 entries", GREEN),
            ("[demo] PASS - ToolNotFound: 'execute_shell' is not exposed by dfir-mcp", GREEN),
        ],
    )


def main():
    architecture()
    screenshots()
    print("regenerated docs/dfir-architecture.png and docs/screenshots/*.png")


if __name__ == "__main__":
    main()
