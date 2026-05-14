#!/usr/bin/env python3
"""
slide_generator_v2.py — Premium light-theme slides for Agentic-DART demo.

Design language: Stripe / Vercel / Linear / Apple Keynote
  - white background (#ffffff)
  - charcoal primary text (#0a0a0a) — almost black for max contrast
  - muted secondary text (#525252)
  - thin accent rules + minimal color blocks
  - generous whitespace, single point of focus per slide
  - SF Pro / Inter-style proportions (we use DejaVu but with weight discipline)

Output → demo_video/slides_v2/
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch, FancyArrowPatch
from pathlib import Path

OUT = Path("/home/claude/demo_video/slides_v2")
OUT.mkdir(parents=True, exist_ok=True)

# ─── Palette ──────────────────────────────────────────────────────────────────
BG          = "#ffffff"
TEXT_PRI    = "#0a0a0a"   # near-black, max contrast for projector & video compression
TEXT_SEC    = "#525252"   # muted body
TEXT_TER    = "#a3a3a3"   # tertiary (footer, page numbers)
RULE        = "#e5e5e5"   # hairline separators
ACCENT      = "#1d4ed8"   # restrained royal blue — like Stripe
ACCENT_LIGHT= "#dbeafe"
SUCCESS     = "#15803d"   # forest green
SUCCESS_LIGHT= "#dcfce7"
WARN        = "#b45309"   # amber, not yellow
WARN_LIGHT  = "#fef3c7"
DANGER      = "#b91c1c"
DANGER_LIGHT= "#fee2e2"
CODE_BG     = "#f5f5f5"   # very light gray for inline code blocks
CODE_BORDER = "#d4d4d4"

W, H = 1920, 1080
FIG_DPI = 120
FIGSIZE = (W / FIG_DPI, H / FIG_DPI)


def _new_fig():
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG, dpi=FIG_DPI)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 100); ax.set_ylim(0, 56)
    ax.axis("off")
    return fig, ax


def _save(fig, name):
    out = OUT / f"{name}.png"
    fig.savefig(out, dpi=FIG_DPI, facecolor=BG, bbox_inches=None, pad_inches=0)
    plt.close(fig)
    print(f"  ok  {out.name}  ({out.stat().st_size // 1024} kB)")


def _add_brand_footer(ax, page_num=None):
    """Common slide footer — brand mark + optional page number."""
    # Hairline above footer
    ax.plot([6, 94], [3.5, 3.5], color=RULE, linewidth=0.8)
    # Brand
    ax.text(6, 2, "Agentic-DART", ha="left", va="center",
            fontsize=11, color=TEXT_SEC, fontweight="bold")
    ax.text(20, 2, "·  SANS FIND EVIL! 2026", ha="left", va="center",
            fontsize=10, color=TEXT_TER)
    # Right side: optional page indicator
    if page_num:
        ax.text(94, 2, page_num, ha="right", va="center",
                fontsize=10, color=TEXT_TER)


def _slide_title(ax, eyebrow, headline, subheadline=None, y_start=51):
    """Standard slide head — small eyebrow tag, large headline, optional subhead."""
    # Eyebrow (small, uppercase, accent color)
    ax.text(6, y_start, eyebrow.upper(), ha="left", va="top",
            fontsize=11, color=ACCENT, fontweight="bold")
    # Headline (large, charcoal)
    ax.text(6, y_start - 2.8, headline, ha="left", va="top",
            fontsize=36, color=TEXT_PRI, fontweight="bold")
    # Subhead (medium, muted)
    if subheadline:
        ax.text(6, y_start - 7.5, subheadline, ha="left", va="top",
                fontsize=18, color=TEXT_SEC)
    # Title divider line
    ax.plot([6, 94], [y_start - 10, y_start - 10], color=RULE, linewidth=0.8)


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 1 — Cover (Apple keynote opener style)
# ════════════════════════════════════════════════════════════════════════════
def slide1_cover():
    fig, ax = _new_fig()

    # Small accent eyebrow at top
    ax.text(50, 47, "SANS FIND EVIL! 2026  ·  PATTERN 2",
            ha="center", va="center", fontsize=12, color=ACCENT, fontweight="bold")

    # Thin separator line
    ax.plot([40, 60], [44.5, 44.5], color=ACCENT, linewidth=1.2)

    # Wordmark
    ax.text(50, 35, "Agentic-DART",
            ha="center", va="center", fontsize=84, color=TEXT_PRI,
            fontweight="bold")

    # Subhead
    ax.text(50, 26, "Architecture-first autonomous DFIR",
            ha="center", va="center", fontsize=24, color=TEXT_SEC, style="italic")

    # Three pillar boxes
    pillars = [
        ("70", "typed read-only\nMCP tools", ACCENT),
        ("72/72", "tests passing\non a fresh clone", SUCCESS),
        ("0", "destructive operations\npossible by construction", DANGER),
    ]
    box_w = 19
    gap = 3
    total_w = len(pillars) * box_w + (len(pillars) - 1) * gap
    start_x = (100 - total_w) / 2
    for i, (num, label, color) in enumerate(pillars):
        x = start_x + i * (box_w + gap)
        # Big number
        ax.text(x + box_w/2, 17, num, ha="center", va="center",
                fontsize=44, color=color, fontweight="bold")
        # Label
        for j, line in enumerate(label.split("\n")):
            ax.text(x + box_w/2, 12 - j*2.2, line, ha="center", va="center",
                    fontsize=13, color=TEXT_SEC)

    # Footer
    ax.text(50, 3.5, "github.com/Juwon1405/agentic-dart",
            ha="center", va="center", fontsize=12, color=TEXT_TER,
            family="DejaVu Sans Mono")
    _save(fig, "slide1_cover")


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 2 — Install (single command + 7 stage indicator)
# ════════════════════════════════════════════════════════════════════════════
def slide2_install():
    fig, ax = _new_fig()
    _slide_title(ax, "SCENE 2", "One-line install",
                 "Runs on a clean SANS SIFT Workstation in under a minute")

    # Code block
    code_x, code_w = 6, 88
    code_y, code_h = 33, 6
    rect = FancyBboxPatch((code_x, code_y), code_w, code_h,
        boxstyle="round,pad=0.3,rounding_size=0.5",
        linewidth=1.0, edgecolor=CODE_BORDER, facecolor=CODE_BG)
    ax.add_patch(rect)
    # Prompt
    ax.text(code_x + 1.5, code_y + code_h/2, "$",
            ha="left", va="center", fontsize=18, color=SUCCESS, fontweight="bold",
            family="DejaVu Sans Mono")
    ax.text(code_x + 3.5, code_y + code_h/2,
            "curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash",
            ha="left", va="center", fontsize=15, color=TEXT_PRI,
            family="DejaVu Sans Mono")

    # 7-stage flow
    stages = [
        ("Python", "verify"),
        ("Repository", "clone"),
        ("Package", "install"),
        ("SIFT toolchain", "auto-probe"),
        ("MCP surface", "verify"),
        ("Bypass tests", "run"),
        ("API key", "check"),
    ]
    n = len(stages)
    box_w = 11
    gap = 1.5
    total_w = n * box_w + (n - 1) * gap
    start_x = (100 - total_w) / 2

    for i, (name, action) in enumerate(stages):
        x = start_x + i * (box_w + gap)
        # Box
        rect = FancyBboxPatch((x, 18), box_w, 9,
            boxstyle="round,pad=0.2,rounding_size=0.4",
            linewidth=1.0, edgecolor=RULE, facecolor=BG)
        ax.add_patch(rect)
        # Number circle
        ax.add_patch(plt.Circle((x + box_w/2, 25), 0.9, color=ACCENT))
        ax.text(x + box_w/2, 25, str(i+1), ha="center", va="center",
                fontsize=11, color="white", fontweight="bold")
        # Name
        ax.text(x + box_w/2, 22, name, ha="center", va="center",
                fontsize=10.5, color=TEXT_PRI, fontweight="bold")
        ax.text(x + box_w/2, 20, action, ha="center", va="center",
                fontsize=9.5, color=TEXT_SEC, style="italic")
        # Arrow to next
        if i < n - 1:
            ax.annotate("", xy=(x + box_w + gap - 0.2, 22.5),
                        xytext=(x + box_w + 0.2, 22.5),
                        arrowprops=dict(arrowstyle="->", color=TEXT_TER, lw=1.0))

    # Bottom callout
    callout_rect = FancyBboxPatch((20, 8), 60, 6,
        boxstyle="round,pad=0.3,rounding_size=0.4",
        linewidth=0, facecolor=SUCCESS_LIGHT)
    ax.add_patch(callout_rect)
    ax.text(50, 12, "MCP surface verified  ·  45 native + 25 SIFT adapters = 70 tools",
            ha="center", va="center", fontsize=15, color=SUCCESS, fontweight="bold")
    ax.text(50, 9.6, "All bypass checks passed  ·  no destructive operations on the wire",
            ha="center", va="center", fontsize=12, color=SUCCESS)

    _add_brand_footer(ax, "2 / 6")
    _save(fig, "slide2_install")


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 3 — Architectural boundary
# ════════════════════════════════════════════════════════════════════════════
def slide3_boundary():
    fig, ax = _new_fig()
    _slide_title(ax, "SCENE 3", "The architectural boundary",
                 "We did not ask the agent to behave. We removed the ability to misbehave.")

    # Two-column comparison
    col_y_top = 39
    col_h = 27

    # LEFT — ON the wire
    left_x, left_w = 6, 41
    rect = FancyBboxPatch((left_x, col_y_top - col_h), left_w, col_h,
        boxstyle="round,pad=0.4,rounding_size=0.6",
        linewidth=1.0, edgecolor=SUCCESS, facecolor=SUCCESS_LIGHT)
    ax.add_patch(rect)
    # Header
    ax.text(left_x + left_w/2, col_y_top - 2, "ON the wire",
            ha="center", va="center", fontsize=18, color=SUCCESS, fontweight="bold")
    ax.text(left_x + left_w/2, col_y_top - 4.2,
            "70 typed read-only forensic functions",
            ha="center", va="center", fontsize=11, color=SUCCESS, style="italic")
    # Items
    on_wire = [
        "parse_prefetch",
        "extract_mft_timeline",
        "detect_persistence",
        "analyze_kerberos_events",
        "parse_macos_quarantine",
        "parse_linux_cron_jobs",
        ("detect_dns_tunneling", "v0.6.1"),
        "+ sift_vol3_*  +  sift_yara_*",
    ]
    for i, item in enumerate(on_wire):
        if isinstance(item, tuple):
            name, tag = item
            ax.text(left_x + 3, col_y_top - 7 - i*2.4, "✓", ha="left", va="top",
                    fontsize=13, color=SUCCESS, fontweight="bold")
            ax.text(left_x + 5, col_y_top - 7 - i*2.4, name, ha="left", va="top",
                    fontsize=13, color=TEXT_PRI, family="DejaVu Sans Mono")
            # New tag pill
            tag_x = left_x + 5 + len(name) * 0.78 + 0.5
            tag_rect = FancyBboxPatch((tag_x, col_y_top - 7 - i*2.4 - 1.3), 4.5, 1.5,
                boxstyle="round,pad=0.1,rounding_size=0.3",
                linewidth=0, facecolor=ACCENT)
            ax.add_patch(tag_rect)
            ax.text(tag_x + 2.25, col_y_top - 7 - i*2.4 - 0.5, tag,
                    ha="center", va="center", fontsize=9, color="white", fontweight="bold")
        else:
            ax.text(left_x + 3, col_y_top - 7 - i*2.4, "✓", ha="left", va="top",
                    fontsize=13, color=SUCCESS, fontweight="bold")
            ax.text(left_x + 5, col_y_top - 7 - i*2.4, item, ha="left", va="top",
                    fontsize=13, color=TEXT_PRI, family="DejaVu Sans Mono")

    # RIGHT — NOT on the wire
    right_x, right_w = 53, 41
    rect = FancyBboxPatch((right_x, col_y_top - col_h), right_w, col_h,
        boxstyle="round,pad=0.4,rounding_size=0.6",
        linewidth=1.0, edgecolor=DANGER, facecolor=DANGER_LIGHT)
    ax.add_patch(rect)
    ax.text(right_x + right_w/2, col_y_top - 2, "NOT on the wire",
            ha="center", va="center", fontsize=18, color=DANGER, fontweight="bold")
    ax.text(right_x + right_w/2, col_y_top - 4.2,
            "ToolNotFound  ·  by construction, not by policy",
            ha="center", va="center", fontsize=11, color=DANGER, style="italic")
    not_wire = [
        "execute_shell",
        "write_file",
        "mount  /  umount",
        "eval  /  exec_python",
        "network_egress",
        "delete_file",
        "spawn_process",
        "kill_process",
    ]
    for i, item in enumerate(not_wire):
        ax.text(right_x + 3, col_y_top - 7 - i*2.4, "✗", ha="left", va="top",
                fontsize=13, color=DANGER, fontweight="bold")
        ax.text(right_x + 5, col_y_top - 7 - i*2.4, item, ha="left", va="top",
                fontsize=13, color=TEXT_PRI, family="DejaVu Sans Mono",
                alpha=0.55)

    # Bottom takeaway
    ax.text(50, 7, "Adding tools never weakens the boundary.",
            ha="center", va="center", fontsize=15, color=TEXT_PRI, fontweight="bold")
    ax.text(50, 5, "The boundary IS the canonical name set.",
            ha="center", va="center", fontsize=13, color=TEXT_SEC, style="italic")

    _add_brand_footer(ax, "3 / 6")
    _save(fig, "slide3_boundary")


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 4 — End-to-end (ten-phase playbook + audit chain)
# ════════════════════════════════════════════════════════════════════════════
def slide4_end_to_end():
    fig, ax = _new_fig()
    _slide_title(ax, "SCENE 4", "End-to-end on a real case",
                 "Ten-phase senior-analyst playbook  ·  tamper-evident SHA-256 audit chain")

    # 10 phases as horizontal flow
    phases = [
        ("P0", "scope"),
        ("P1", "access"),
        ("P2", "timeline"),
        ("P3", "anomaly"),
        ("P4", "hypothesis"),
        ("P5", "kill-chain"),
        ("P6", "contradiction"),
        ("P7", "attribution"),
        ("P8", "recovery"),
        ("P9", "emission"),
    ]
    box_w = 8.0; gap = 0.8
    n = len(phases)
    total_w = n * box_w + (n - 1) * gap
    start_x = (100 - total_w) / 2

    for i, (p, label) in enumerate(phases):
        x = start_x + i * (box_w + gap)
        is_correction = (p == "P6")
        # Highlight P6 (self-correction)
        if is_correction:
            face = WARN_LIGHT
            edge = WARN
            num_color = WARN
        else:
            face = BG
            edge = ACCENT if i < 5 else "#7c3aed"
            num_color = ACCENT if i < 5 else "#7c3aed"
        rect = FancyBboxPatch((x, 26), box_w, 9,
            boxstyle="round,pad=0.2,rounding_size=0.4",
            linewidth=1.3, edgecolor=edge, facecolor=face)
        ax.add_patch(rect)
        ax.text(x + box_w/2, 32, p, ha="center", va="center",
                fontsize=14, fontweight="bold", color=num_color,
                family="DejaVu Sans Mono")
        ax.text(x + box_w/2, 28.5, label, ha="center", va="center",
                fontsize=9.5, color=TEXT_PRI)
        # Arrow
        if i < n - 1:
            ax.annotate("", xy=(x + box_w + gap - 0.1, 30.5),
                        xytext=(x + box_w + 0.1, 30.5),
                        arrowprops=dict(arrowstyle="->", color=TEXT_TER, lw=0.9))

    # P6 callout
    ax.annotate("", xy=(start_x + 6.5*(box_w+gap) + box_w/2, 25.5),
                xytext=(start_x + 6.5*(box_w+gap) + box_w/2, 21),
                arrowprops=dict(arrowstyle="->", color=WARN, lw=1.5))
    ax.text(start_x + 6.5*(box_w+gap) + box_w/2, 20, "self-correction event",
            ha="center", va="top", fontsize=11, color=WARN, fontweight="bold")

    # Output artefacts
    ax.text(50, 15.5, "→", ha="center", va="center",
            fontsize=24, color=TEXT_TER)

    outputs = [
        ("findings.json", "24 findings  ·  21 high-confidence"),
        ("audit.jsonl", "143 MCP calls  ·  SHA-256 chained"),
        ("report.md", "3 847 words  ·  judge-readable"),
    ]
    out_w = 26; out_gap = 2
    out_total = len(outputs) * out_w + (len(outputs) - 1) * out_gap
    out_start = (100 - out_total) / 2
    for i, (name, sub) in enumerate(outputs):
        x = out_start + i * (out_w + out_gap)
        rect = FancyBboxPatch((x, 7), out_w, 6,
            boxstyle="round,pad=0.2,rounding_size=0.4",
            linewidth=1.0, edgecolor=RULE, facecolor=CODE_BG)
        ax.add_patch(rect)
        ax.text(x + out_w/2, 11, name, ha="center", va="center",
                fontsize=13, color=TEXT_PRI, fontweight="bold",
                family="DejaVu Sans Mono")
        ax.text(x + out_w/2, 9, sub, ha="center", va="center",
                fontsize=10, color=TEXT_SEC)

    _add_brand_footer(ax, "4 / 6")
    _save(fig, "slide4_end_to_end")


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 5 — v0.6.1 new capabilities
# ════════════════════════════════════════════════════════════════════════════
def slide5_v061():
    fig, ax = _new_fig()
    _slide_title(ax, "SCENE 5  ·  RELEASED 2026-05-14", "v0.6.1 — opens TA0011 Command-and-Control",
                 "Three new native functions, each with an open-source reference")

    cards = [
        {
            "name": "parse_macos_quarantine",
            "subhead": "macOS download provenance",
            "bullets": [
                "LSQuarantineEvent SQLite reader",
                "Non-browser downloader detection",
                "Pastesite / raw-IP / darknet origins",
            ],
            "ref": "Sarah Edwards · QuarantineV2 (mac4n6.com)",
            "mitre": "T1204  T1566.002  T1105",
            "color": DANGER,
            "color_light": DANGER_LIGHT,
        },
        {
            "name": "parse_linux_cron_jobs",
            "subhead": "Cron persistence enumeration",
            "bullets": [
                "/etc/crontab + cron.d + spool dirs",
                "curl-pipe-shell + base64 + @reboot",
                "netcat listener + /tmp/*.sh flags",
            ],
            "ref": "crontab(5) · RHEL Sec Guide ch. 7",
            "mitre": "T1053.003  T1059.004  T1546",
            "color": ACCENT,
            "color_light": ACCENT_LIGHT,
        },
        {
            "name": "detect_dns_tunneling",
            "subhead": "DNS C2 detection",
            "bullets": [
                "Shannon entropy + long-label heuristic",
                "Iodine & dnscat2 signature detection",
                "Per-domain volume sliding window",
            ],
            "ref": "SANS FOR572 · Iodine (Yarrin 2009)",
            "mitre": "T1071.004  T1568.002  T1572",
            "color": "#7c3aed",
            "color_light": "#ede9fe",
        },
    ]
    card_w = 28.5; gap = 2.25
    total = len(cards) * card_w + (len(cards) - 1) * gap
    start_x = (100 - total) / 2
    for i, c in enumerate(cards):
        x = start_x + i * (card_w + gap)
        # Card background
        rect = FancyBboxPatch((x, 6), card_w, 33,
            boxstyle="round,pad=0.4,rounding_size=0.7",
            linewidth=1.0, edgecolor=RULE, facecolor=BG)
        ax.add_patch(rect)
        # Top accent stripe
        stripe = Rectangle((x + 0.4, 38.2), card_w - 0.8, 0.6,
            facecolor=c["color"], edgecolor="none")
        ax.add_patch(stripe)
        # Function name
        ax.text(x + card_w/2, 36, c["name"], ha="center", va="center",
                fontsize=14, color=c["color"], fontweight="bold",
                family="DejaVu Sans Mono")
        # Subhead
        ax.text(x + card_w/2, 33.6, c["subhead"], ha="center", va="center",
                fontsize=12.5, color=TEXT_PRI, style="italic")
        # Hairline
        ax.plot([x + 3, x + card_w - 3], [31.5, 31.5], color=RULE, linewidth=0.6)
        # Bullets
        for j, b in enumerate(c["bullets"]):
            ax.text(x + 2.5, 29 - j*2.5, "•", ha="left", va="top",
                    fontsize=12, color=c["color"])
            ax.text(x + 3.8, 29 - j*2.5, b, ha="left", va="top",
                    fontsize=11, color=TEXT_PRI)
        # Reference (pinned to bottom)
        ax.text(x + card_w/2, 13, c["ref"], ha="center", va="center",
                fontsize=10, color=TEXT_SEC, style="italic")
        # MITRE pills
        mitre_rect = FancyBboxPatch((x + 2, 8), card_w - 4, 3,
            boxstyle="round,pad=0.2,rounding_size=0.3",
            linewidth=0, facecolor=c["color_light"])
        ax.add_patch(mitre_rect)
        ax.text(x + card_w/2, 9.5, c["mitre"], ha="center", va="center",
                fontsize=11, color=c["color"], fontweight="bold",
                family="DejaVu Sans Mono")

    _add_brand_footer(ax, "5 / 6")
    _save(fig, "slide5_v061")


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE 6 — Closing
# ════════════════════════════════════════════════════════════════════════════
def slide6_closing():
    fig, ax = _new_fig()

    # Eyebrow
    ax.text(50, 47, "THANK YOU",
            ha="center", va="center", fontsize=12, color=ACCENT, fontweight="bold")
    ax.plot([46, 54], [44.5, 44.5], color=ACCENT, linewidth=1.2)

    # Wordmark
    ax.text(50, 36, "Agentic-DART",
            ha="center", va="center", fontsize=72, color=TEXT_PRI,
            fontweight="bold")

    # Three lines
    ax.text(50, 27, "Architecture-first.  Audit-chained.  Zero destructive operations.",
            ha="center", va="center", fontsize=20, color=TEXT_SEC, style="italic")

    # Repo URL
    repo_rect = FancyBboxPatch((30, 18), 40, 5,
        boxstyle="round,pad=0.3,rounding_size=0.5",
        linewidth=1, edgecolor=CODE_BORDER, facecolor=CODE_BG)
    ax.add_patch(repo_rect)
    ax.text(50, 20.5, "github.com/Juwon1405/agentic-dart",
            ha="center", va="center", fontsize=18, color=TEXT_PRI,
            family="DejaVu Sans Mono", fontweight="bold")

    # Footer
    ax.text(50, 11, "Sole-authored entry  ·  SANS FIND EVIL! 2026",
            ha="center", va="center", fontsize=14, color=TEXT_SEC)
    ax.text(50, 8, "Demo video  ·  v0.6.1  ·  2026-05-14",
            ha="center", va="center", fontsize=11, color=TEXT_TER)

    _save(fig, "slide6_closing")


if __name__ == "__main__":
    print("[generating premium light-theme slides]\n")
    slide1_cover()
    slide2_install()
    slide3_boundary()
    slide4_end_to_end()
    slide5_v061()
    slide6_closing()
    print(f"\ndone -> {OUT}")
