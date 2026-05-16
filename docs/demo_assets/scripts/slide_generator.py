#!/usr/bin/env python3
"""
slide_generator.py — Produce 1920x1080 slides for the Agentic-DART demo.

Outputs PNG slides into demo_video/slides/.
- 6 title slides (one per scene)
- Each is the cover frame the voiceover lands on for the first ~1-2s

Visual style: quiet-luxury dark theme matching GitHub canvas-default
(#0d1117), the agentic-dart README hero, and the adapter diagrams.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch
from pathlib import Path

OUT = Path("/home/claude/demo_video/slides")
OUT.mkdir(parents=True, exist_ok=True)

# Palette (matches agentic-dart README + adapter diagrams)
BG          = "#0d1117"
BOX_FILL    = "#161b22"
TEXT_PRI    = "#e6edf3"
TEXT_SEC    = "#8b949e"
ACCENT      = "#79a6dc"
GREEN       = "#7fb88f"
CORAL       = "#c97064"
PURPLE      = "#b88dd3"

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


# ─── Scene 1: Cold open ────────────────────────────────────────────────────────
def scene1_cold_open():
    fig, ax = _new_fig()
    # Title
    ax.text(50, 38, "Agentic-DART",
            ha="center", va="center", fontsize=60, fontweight="bold", color=TEXT_PRI,
            family="DejaVu Sans Mono")
    ax.text(50, 30, "Architecture-first autonomous DFIR",
            ha="center", va="center", fontsize=22, color=TEXT_SEC, style="italic")
    # Three pillars
    ax.text(50, 19, "72 typed read-only MCP tools",
            ha="center", va="center", fontsize=20, color=ACCENT, fontweight="bold")
    ax.text(50, 14, "Architectural boundary at the wire — not the prompt",
            ha="center", va="center", fontsize=16, color=TEXT_SEC)
    ax.text(50, 9,  "Zero destructive operations possible by construction",
            ha="center", va="center", fontsize=16, color=GREEN)
    # Footer
    ax.text(50, 3, "SANS FIND EVIL! 2026  ·  Pattern 2 — Custom MCP Server",
            ha="center", va="center", fontsize=11, color=TEXT_SEC)
    _save(fig, "scene1_cold_open")


# ─── Scene 2: Install ─────────────────────────────────────────────────────────
def scene2_install():
    fig, ax = _new_fig()
    ax.text(50, 50, "One-line install on SIFT Workstation",
            ha="center", va="top", fontsize=32, fontweight="bold", color=TEXT_PRI)
    ax.text(50, 44, "Probes the SIFT toolchain · Auto-wires SIFT adapters · Verifies surface",
            ha="center", va="top", fontsize=16, color=TEXT_SEC, style="italic")

    # Code block
    code_x, code_y, code_w, code_h = 12, 25, 76, 14
    rect = FancyBboxPatch((code_x, code_y), code_w, code_h,
        boxstyle="round,pad=0.4,rounding_size=0.6",
        linewidth=1.0, edgecolor=ACCENT, facecolor=BOX_FILL)
    ax.add_patch(rect)
    ax.text(50, 35, "$ curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash",
            ha="center", va="center", fontsize=16, color=ACCENT,
            family="DejaVu Sans Mono")
    ax.text(50, 30.5, "[ok] MCP surface verified  ·  native + SIFT adapters",
            ha="center", va="center", fontsize=14, color=GREEN,
            family="DejaVu Sans Mono")
    ax.text(50, 27, "[ok] All bypass checks passed",
            ha="center", va="center", fontsize=14, color=GREEN,
            family="DejaVu Sans Mono")

    # 7 stages indicator
    stages = ["Python", "Repo", "Install", "SIFT probe", "Surface", "Bypass", "API key"]
    for i, s in enumerate(stages):
        x = 8 + i * 12.5
        circle = plt.Circle((x, 14), 1.2, color=ACCENT, alpha=0.7)
        ax.add_patch(circle)
        ax.text(x, 14, str(i+1), ha="center", va="center", fontsize=11, color=BG, fontweight="bold")
        ax.text(x, 10, s, ha="center", va="center", fontsize=10, color=TEXT_SEC)

    _save(fig, "scene2_install")


# ─── Scene 3: Architectural boundary ───────────────────────────────────────────
def scene3_boundary():
    fig, ax = _new_fig()
    ax.text(50, 51, "The architectural boundary",
            ha="center", va="top", fontsize=32, fontweight="bold", color=TEXT_PRI)
    ax.text(50, 46, "We removed the ability to misbehave",
            ha="center", va="top", fontsize=16, color=TEXT_SEC, style="italic")

    # Left side: what's on the wire
    ax.text(28, 39, "ON the wire", ha="center", va="top", fontsize=18, fontweight="bold", color=GREEN)
    on_wire = [
        "✓  parse_prefetch",
        "✓  extract_mft_timeline",
        "✓  detect_persistence",
        "✓  analyze_kerberos_events",
        "✓  parse_macos_quarantine",
        "✓  parse_linux_cron_jobs",
        "✓  detect_dns_tunneling   ← new",
        "✓  + sift_vol3_*  +  sift_yara_*",
    ]
    for i, line in enumerate(on_wire):
        ax.text(8, 35 - i * 2.6, line, ha="left", va="top", fontsize=14, color=TEXT_PRI,
                family="DejaVu Sans Mono")

    # Vertical divider
    ax.plot([50, 50], [10, 41], color=TEXT_SEC, alpha=0.4, linewidth=1)

    # Right side: what's NOT on the wire
    ax.text(72, 39, "NOT on the wire", ha="center", va="top", fontsize=18, fontweight="bold", color=CORAL)
    not_wire = [
        "✗  execute_shell",
        "✗  write_file",
        "✗  mount  /  umount",
        "✗  eval  /  exec_python",
        "✗  network_egress",
        "✗  delete_file",
        "✗  spawn_process",
        "✗  kill_process",
    ]
    for i, line in enumerate(not_wire):
        ax.text(53, 35 - i * 2.6, line, ha="left", va="top", fontsize=14, color=TEXT_SEC,
                family="DejaVu Sans Mono", alpha=0.7)

    # Bottom note
    ax.text(50, 5, "ToolNotFound is not a refusal — it is a fact about the universe the agent lives in.",
            ha="center", va="center", fontsize=14, color=TEXT_SEC, style="italic")

    _save(fig, "scene3_boundary")


# ─── Scene 4: End-to-end run ───────────────────────────────────────────────────
def scene4_end_to_end():
    fig, ax = _new_fig()
    ax.text(50, 51, "End-to-end on a real case",
            ha="center", va="top", fontsize=32, fontweight="bold", color=TEXT_PRI)
    ax.text(50, 46, "Ten-phase senior-analyst playbook · tamper-evident audit chain",
            ha="center", va="top", fontsize=16, color=TEXT_SEC, style="italic")

    # 10 phases as horizontal flow
    phases = [
        ("P0", "scope"),
        ("P1", "initial access"),
        ("P2", "timeline"),
        ("P3", "anomaly"),
        ("P4", "hypothesis"),
        ("P5", "kill-chain"),
        ("P6", "contradiction"),
        ("P7", "attribution"),
        ("P8", "recovery"),
        ("P9", "emission"),
    ]
    box_w = 8.5
    start_x = 4.5
    for i, (p, label) in enumerate(phases):
        x = start_x + i * (box_w + 0.5)
        # Phase box
        color = ACCENT if i < 5 else PURPLE
        rect = FancyBboxPatch((x, 28), box_w, 8,
            boxstyle="round,pad=0.15,rounding_size=0.4",
            linewidth=1.2, edgecolor=color, facecolor=BOX_FILL)
        ax.add_patch(rect)
        ax.text(x + box_w/2, 33, p, ha="center", va="center", fontsize=13, fontweight="bold", color=color, family="DejaVu Sans Mono")
        ax.text(x + box_w/2, 30, label, ha="center", va="center", fontsize=8.5, color=TEXT_PRI)
        # Arrows (except last)
        if i < len(phases) - 1:
            ax.annotate("", xy=(x + box_w + 0.5, 32), xytext=(x + box_w + 0.1, 32),
                arrowprops=dict(arrowstyle="->", color=TEXT_SEC, lw=1.0))

    # Output artifacts
    ax.text(50, 20, "→  findings.json   ·   audit.jsonl   ·   report.md",
            ha="center", va="center", fontsize=18, color=GREEN, fontweight="bold",
            family="DejaVu Sans Mono")
    ax.text(50, 14, "Every MCP call hashed into a SHA-256 chain. Verifiable after the fact.",
            ha="center", va="center", fontsize=14, color=TEXT_SEC, style="italic")
    ax.text(50, 8, "$ python3 -m dart_audit verify  →  OK · chain intact",
            ha="center", va="center", fontsize=13, color=GREEN, family="DejaVu Sans Mono")

    _save(fig, "scene4_end_to_end")


# ─── Scene 5: v0.6.1 capabilities ──────────────────────────────────────────────
def scene5_v061():
    fig, ax = _new_fig()
    ax.text(50, 51, "v0.6.1 — opens TA0011 Command-and-Control",
            ha="center", va="top", fontsize=30, fontweight="bold", color=TEXT_PRI)
    ax.text(50, 46, "Three new native functions ship with this release",
            ha="center", va="top", fontsize=16, color=TEXT_SEC, style="italic")

    # Three function cards
    cards = [
        ("parse_macos_quarantine", "LSQuarantineEvent SQLite reader",
         "Download provenance · non-browser flag\nPastesite / raw-IP / darknet origin\nT1204, T1566.002, T1105", CORAL),
        ("parse_linux_cron_jobs", "Full cron path enumeration",
         "@reboot triggers · curl-pipe-shell\nbase64 decode · /tmp/*.sh · netcat\nT1053.003, T1059.004, T1546", ACCENT),
        ("detect_dns_tunneling", "DNS C2 detection",
         "Shannon entropy · long-label · volume\nIodine & dnscat2 signatures\nT1071.004, T1568.002, T1572\nTA0011", PURPLE),
    ]
    card_w = 28; card_h = 26
    for i, (fn, sub, body, color) in enumerate(cards):
        x = 3 + i * (card_w + 2.5)
        rect = FancyBboxPatch((x, 8), card_w, card_h,
            boxstyle="round,pad=0.3,rounding_size=0.6",
            linewidth=1.3, edgecolor=color, facecolor=BOX_FILL)
        ax.add_patch(rect)
        ax.text(x + card_w/2, 30, fn, ha="center", va="top", fontsize=13.5, fontweight="bold",
                color=color, family="DejaVu Sans Mono")
        ax.text(x + card_w/2, 27, sub, ha="center", va="top", fontsize=12, color=TEXT_PRI, style="italic")
        for j, line in enumerate(body.split("\n")):
            ax.text(x + card_w/2, 23 - j*2.5, line, ha="center", va="top",
                    fontsize=10.5, color=TEXT_SEC)

    _save(fig, "scene5_v061")


# ─── Scene 6: Closing ──────────────────────────────────────────────────────────
def scene6_closing():
    fig, ax = _new_fig()
    ax.text(50, 38, "Agentic-DART",
            ha="center", va="center", fontsize=58, fontweight="bold", color=TEXT_PRI,
            family="DejaVu Sans Mono")
    ax.text(50, 30, "github.com/Juwon1405/agentic-dart",
            ha="center", va="center", fontsize=20, color=ACCENT, family="DejaVu Sans Mono")
    ax.text(50, 22, "Architecture-first.  Audit-chained.  Zero destructive ops.",
            ha="center", va="center", fontsize=18, color=TEXT_SEC, style="italic")
    ax.text(50, 13, "SANS FIND EVIL! 2026  ·  sole-authored entry",
            ha="center", va="center", fontsize=14, color=TEXT_SEC)
    ax.text(50, 7, "Thank you for watching",
            ha="center", va="center", fontsize=13, color=TEXT_PRI)
    _save(fig, "scene6_closing")


if __name__ == "__main__":
    print("[generating Agentic-DART demo slides — quiet-luxury dark theme]\n")
    scene1_cold_open()
    scene2_install()
    scene3_boundary()
    scene4_end_to_end()
    scene5_v061()
    scene6_closing()
    print(f"\ndone -> {OUT}")
