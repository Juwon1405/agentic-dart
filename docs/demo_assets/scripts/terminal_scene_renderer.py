#!/usr/bin/env python3
"""
terminal_scene_renderer.py — Render virtual SIFT terminal screencast frames.

Produces a sequence of 1920x1080 PNG frames simulating a real terminal session.
Frames per second: 15 (3 minutes total budget). Output → demo_video/terminal/.

Per scene we render the *terminal* portion only; slides cover the rest.
ffmpeg later concatenates: slide → terminal scene → slide → terminal scene ...
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch
from pathlib import Path
import re

OUT = Path("/home/claude/demo_video/terminal")
OUT.mkdir(parents=True, exist_ok=True)

# ─── Terminal visual settings ─────────────────────────────────────────────────
BG          = "#0d1117"
TERM_FILL   = "#0d1117"
TEXT_PRI    = "#e6edf3"
TEXT_DIM    = "#8b949e"
PROMPT_USER = "#7fb88f"
PROMPT_HOST = "#79a6dc"
PROMPT_CWD  = "#b88dd3"
SUCCESS     = "#7fb88f"
WARN        = "#d4a72c"
ERROR       = "#c97064"
HEADER      = "#79a6dc"
MUTED       = "#8b949e"

W, H = 1920, 1080
FIG_DPI = 120
FIGSIZE = (W / FIG_DPI, H / FIG_DPI)

# Window bar
WINDOW_TITLE = "yushin@siftworkstation: ~/agentic-dart"
LINE_HEIGHT = 1.55  # in axes units (figure is 56 tall)
MONO = {"family": "DejaVu Sans Mono", "fontsize": 13}


def _new_terminal_frame():
    """Return a fig, ax with the macOS-style terminal chrome ready."""
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG, dpi=FIG_DPI)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 100); ax.set_ylim(0, 56)
    ax.axis("off")

    # Terminal window background
    term = FancyBboxPatch((2, 2), 96, 52,
        boxstyle="round,pad=0,rounding_size=0.8",
        linewidth=0, facecolor=TERM_FILL,
        edgecolor="#21262d")
    ax.add_patch(term)

    # Title bar
    titlebar = Rectangle((2, 52), 96, 2,
        facecolor="#161b22", edgecolor="none", linewidth=0)
    ax.add_patch(titlebar)
    # 3 dots (close/min/max)
    for i, color in enumerate(["#ff5f57", "#ffbd2e", "#28c941"]):
        ax.add_patch(plt.Circle((5 + i * 1.5, 53), 0.4, color=color))
    # Title
    ax.text(50, 53, WINDOW_TITLE, ha="center", va="center",
            fontsize=10, color=TEXT_DIM, style="italic")

    return fig, ax


def _prompt_text():
    """Return the colored prompt string parts."""
    return [
        ("yushin", PROMPT_USER),
        ("@", TEXT_DIM),
        ("siftworkstation", PROMPT_HOST),
        (":", TEXT_DIM),
        ("~/agentic-dart", PROMPT_CWD),
        ("$ ", TEXT_PRI),
    ]


def _draw_lines(ax, lines, y_top=49):
    """
    Draw a list of (text, color) tuples or list-of-tuples (for mixed coloring).
    Each item is one line. An empty tuple `()` or `[]` is a blank line.
    """
    y = y_top
    for line in lines:
        # Blank line
        if not line:
            y -= LINE_HEIGHT
            continue
        # Single (text, color) tuple → wrap to list
        if isinstance(line, tuple) and len(line) == 2 and isinstance(line[0], str):
            line = [line]
        x = 4
        for txt, color in line:
            ax.text(x, y, txt, ha="left", va="top", color=color, **MONO)
            x += len(txt) * 0.84  # tighter monospace advance to prevent overlap
        y -= LINE_HEIGHT


def _prompt_line(typed=""):
    """Return a fully-composed prompt line as a list of (text,color) tuples."""
    return _prompt_text() + [(typed, TEXT_PRI)]


def render_frame(name, lines):
    """Render a single frame with the provided lines. Save as PNG."""
    fig, ax = _new_terminal_frame()
    _draw_lines(ax, lines)
    out = OUT / f"{name}.png"
    fig.savefig(out, dpi=FIG_DPI, facecolor=BG, bbox_inches=None, pad_inches=0)
    plt.close(fig)


# ════════════════════════════════════════════════════════════════════════════
#  SCENE 2 — Install (the install.sh demo)
# ════════════════════════════════════════════════════════════════════════════
def scene2_frames():
    """
    Scene 2 plays from 0:15 to 0:45 in the final cut (30 seconds of terminal).
    At 15 fps that's 450 frames. To save disk we render 6 keyframes and let
    ffmpeg hold each frame for ~5 seconds.
    """
    print("[scene2] install demo")

    # Frame 1: prompt only (the typing-pause beat before the command appears)
    render_frame("s2_01_empty", [_prompt_line()])

    # Frame 2: command typed
    cmd = "curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash"
    render_frame("s2_02_typed", [_prompt_line(cmd)])

    # Frame 3: stage 1-2 output (Python + repo)
    render_frame("s2_03_stages_1_2", [
        _prompt_line(cmd),
        (),
        [("══ ", HEADER), ("1. Python check", HEADER)],
        [("[ok] ", SUCCESS), ("Python 3.12.3 detected", TEXT_PRI)],
        (),
        [("══ ", HEADER), ("2. Repository clone", HEADER)],
        [("[ok] ", SUCCESS), ("cloned Juwon1405/agentic-dart @ main (c94c1c4)", TEXT_PRI)],
        (),
        [("══ ", HEADER), ("3. Package install (-e ./dart_mcp/)", HEADER)],
        [("[..] ", MUTED), ("pip install -e dart_mcp/ ...", TEXT_DIM)],
    ])

    # Frame 4: stage 3-5 output (install + SIFT probe + surface)
    render_frame("s2_04_stages_3_5", [
        _prompt_line(cmd),
        (),
        [("══ ", HEADER), ("3. Package install", HEADER)],
        [("[ok] ", SUCCESS), ("dart_mcp 0.6.1 installed", TEXT_PRI)],
        (),
        [("══ ", HEADER), ("4. SIFT toolchain probe", HEADER)],
        [("[ok] ", SUCCESS), ("vol3 vol.py    /usr/local/bin/vol.py", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("MFTECmd        /opt/MFTECmd/MFTECmd.dll", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("EvtxECmd       /opt/EvtxECmd/EvtxECmd.dll", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("PECmd          /opt/PECmd/PECmd.dll", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("RECmd          /opt/RECmd/RECmd.dll", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("AmcacheParser  /opt/AmcacheParser/AmcacheParser.dll", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("yara           /usr/bin/yara", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("log2timeline   /usr/bin/log2timeline.py", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("psort          /usr/bin/psort.py", TEXT_PRI)],
    ])

    # Frame 5: stage 5 surface verification — the money shot
    render_frame("s2_05_surface_ok", [
        _prompt_line(cmd),
        (),
        [("══ ", HEADER), ("5. MCP surface verification", HEADER)],
        [("    ", TEXT_PRI), ("native pure-Python forensic functions:  ", TEXT_DIM), ("45", SUCCESS)],
        [("    ", TEXT_PRI), ("SIFT Workstation adapters:              ", TEXT_DIM), ("25", SUCCESS)],
        [("    ", TEXT_PRI), ("total typed read-only MCP tools:        ", TEXT_DIM), ("70", SUCCESS)],
        (),
        [("[", SUCCESS), ("ok", SUCCESS), ("] ", SUCCESS), ("MCP surface verified", TEXT_PRI)],
        (),
        [("══ ", HEADER), ("6. Bypass test surface (negative set)", HEADER)],
        [("[ok] ", SUCCESS), ("execute_shell        not registered", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("write_file           not registered", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("mount / umount / eval / network_egress  not registered", TEXT_PRI)],
        [("[ok] ", SUCCESS), ("All bypass checks passed", TEXT_PRI)],
    ])

    # Frame 6: install complete
    render_frame("s2_06_done", [
        _prompt_line(cmd),
        (),
        [("══ ", HEADER), ("Install complete", HEADER)],
        [("    ", TEXT_PRI), ("agentic-dart v0.6.1 ready", TEXT_PRI)],
        (),
        [("    Try:", TEXT_DIM)],
        [("    $ python3 -m dart_agent --evidence-root <path>", PROMPT_HOST)],
        (),
        _prompt_line(""),
    ])


# ════════════════════════════════════════════════════════════════════════════
#  SCENE 3 — Architectural boundary (bypass tests run)
# ════════════════════════════════════════════════════════════════════════════
def scene3_frames():
    print("[scene3] bypass tests")

    cmd1 = "python3 -m pytest tests/test_mcp_bypass.py -v"

    # Frame 1: command typed
    render_frame("s3_01_typed", [_prompt_line(cmd1)])

    # Frame 2: tests running (mid-flight)
    render_frame("s3_02_running", [
        _prompt_line(cmd1),
        (),
        [("======================== ", MUTED), ("test session starts", TEXT_PRI), (" ========================", MUTED)],
        [("platform linux -- Python 3.12.3, pytest-9.0.3", TEXT_DIM)],
        [("rootdir: /home/yushin/agentic-dart", TEXT_DIM)],
        [("collected 11 items", TEXT_DIM)],
        (),
        [("tests/test_mcp_bypass.py::test_surface_is_exact_positive_and_negative_set ", TEXT_PRI), ("PASSED", SUCCESS), ("  [  9%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_destructive_tools_not_registered ", TEXT_PRI), ("PASSED", SUCCESS), ("                  [ 18%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_path_traversal_blocked_at_mcp_boundary ", TEXT_PRI), ("PASSED", SUCCESS), ("            [ 27%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_evidence_root_escape_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("                  [ 36%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_null_byte_injection_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("                    [ 45%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_sql_injection_in_query_args_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("           [ 54%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_symlink_resolution_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("                   [ 63%]", TEXT_DIM)],
    ])

    # Frame 3: tests complete
    render_frame("s3_03_complete", [
        _prompt_line(cmd1),
        (),
        [("tests/test_mcp_bypass.py::test_unregistered_function_call_raises ", TEXT_PRI), ("PASSED", SUCCESS), ("              [ 72%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_attempted_eval_in_filename_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("            [ 81%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_subprocess_escape_via_pipe_blocked ", TEXT_PRI), ("PASSED", SUCCESS), ("            [ 90%]", TEXT_DIM)],
        [("tests/test_mcp_bypass.py::test_no_shell_metachar_passthrough ", TEXT_PRI), ("PASSED", SUCCESS), ("                [100%]", TEXT_DIM)],
        (),
        [("======================= ", MUTED), ("11 passed in 0.18s", SUCCESS), (" =======================", MUTED)],
        (),
        _prompt_line("python3 -m pytest tests/test_sift_adapters.py -q"),
    ])

    # Frame 4: SIFT adapter tests
    render_frame("s3_04_sift_adapters", [
        _prompt_line("python3 -m pytest tests/test_sift_adapters.py -q"),
        (),
        [(".........................                                              [100%]", SUCCESS)],
        (),
        [("25 passed in 0.31s", SUCCESS)],
        (),
        [("Surface invariants verified:", TEXT_PRI)],
        [("  ", TEXT_PRI), ("•  every adapter wraps subprocess with EVIDENCE_ROOT sandbox", TEXT_DIM)],
        [("  ", TEXT_PRI), ("•  SHA-256 of inputs + outputs threaded into audit chain", TEXT_DIM)],
        [("  ", TEXT_PRI), ("•  timeout guards prevent hung subprocesses", TEXT_DIM)],
        [("  ", TEXT_PRI), ("•  graceful SiftToolNotFoundError when binary absent", TEXT_DIM)],
        (),
        _prompt_line(""),
    ])


# ════════════════════════════════════════════════════════════════════════════
#  SCENE 4 — End-to-end case study + self-correction
# ════════════════════════════════════════════════════════════════════════════
def scene4_frames():
    print("[scene4] end-to-end + self-correction")

    cmd = "python3 -m dart_agent --evidence-root examples/case-studies/case-04-phishing-to-exfil/evidence_root \\\n    --playbook dart_playbook/senior-analyst-v3.yaml --output /tmp/case-04-out"

    # Frame 1: command typed
    render_frame("s4_01_typed", [
        _prompt_line("python3 -m dart_agent \\"),
        [("    --evidence-root examples/case-studies/case-04-phishing-to-exfil/evidence_root \\", TEXT_PRI)],
        [("    --playbook dart_playbook/senior-analyst-v3.yaml \\", TEXT_PRI)],
        [("    --output /tmp/case-04-out", TEXT_PRI)],
    ])

    # Frame 2: P0-P3 streaming
    render_frame("s4_02_p0_p3", [
        [("[boot] ", HEADER), ("Agentic-DART v0.6.1  ·  loaded 70 MCP tools  ·  playbook v3 (10 phases)", TEXT_PRI)],
        [("[boot] ", HEADER), ("audit chain seeded from manifest.json (entry 0, SHA-256: 7af3...c01e)", TEXT_DIM)],
        (),
        [("[P0] ", PROMPT_HOST), ("scope and volatility", TEXT_PRI)],
        [("     ", TEXT_PRI), ("evidence host: WIN-DESKTOP-7AC2  ·  collected 2026-04-29  ·  artefacts: 47 sources", TEXT_DIM)],
        (),
        [("[P1] ", PROMPT_HOST), ("initial access vector triage", TEXT_PRI)],
        [("     ", TEXT_PRI), ("→ analyze_downloads found .docx → Word macro → cmd.exe at 14:23:07", TEXT_DIM)],
        [("     ", TEXT_PRI), ("→ correlate_download_to_execution: chain (URL → file → execution) confirmed", TEXT_DIM)],
        (),
        [("[P2] ", PROMPT_HOST), ("timeline reconstruction", TEXT_PRI)],
        [("     ", TEXT_PRI), ("→ extract_mft_timeline + parse_prefetch: 1,247 events normalised", TEXT_DIM)],
        (),
        [("[P3] ", PROMPT_HOST), ("anomaly surfacing", TEXT_PRI)],
        [("     ", TEXT_PRI), ("→ detect_persistence: Run key 'OneDriveStartup' → unusual binary path", TEXT_DIM)],
        [("     ", TEXT_PRI), ("→ detect_dns_tunneling: 73 queries flagged, parent domain ", TEXT_DIM), ("evil.example.com", WARN)],
    ])

    # Frame 3: P4-P6 — including self-correction (P6)
    render_frame("s4_03_p4_p6_correction", [
        [("[P4] ", PROMPT_HOST), ("hypothesis formation", TEXT_PRI)],
        [("     H1: phishing macro -> persistence -> DNS C2 -> exfiltration", TEXT_DIM)],
        [("     H2: insider threat staging (low confidence)", TEXT_DIM)],
        (),
        [("[P5] ", PROMPT_HOST), ("kill-chain assembly", TEXT_PRI)],
        [("     MITRE: T1566.001 -> T1059.005 -> T1547.001 -> T1071.004 -> T1041", TEXT_DIM)],
        (),
        [("[P6] ", WARN), ("contradiction handling", WARN)],
        [("     << self-correction trigger >>", WARN)],
        [("     Earlier H1 claimed OneDriveStartup as malicious persistence.", TEXT_DIM)],
        [("     parse_registry_hive shows path =", TEXT_DIM)],
        [("       C:\\Users\\jdoe\\AppData\\Local\\OneDrive\\Update\\OneDriveStartup.exe", TEXT_DIM)],
        [("     -> this is the LEGITIMATE Microsoft OneDrive auto-updater path.", WARN)],
        [("     -> retracting H1 'OneDriveStartup persistence' claim.", SUCCESS)],
        [("     -> true persistence is HKCU\\...\\Run\\WinUpdate (random, unsigned).", TEXT_PRI)],
        [("     -> kill-chain updated. confidence bumped 0.62 -> 0.91.", TEXT_DIM)],
    ])

    # Frame 4: P7-P9 + outputs
    render_frame("s4_04_p7_p9_done", [
        [("[P7] ", PROMPT_HOST), ("attribution and Diamond Model", TEXT_PRI)],
        [("     ", TEXT_PRI), ("infrastructure cluster matches public reporting on FIN-7 phishing kit (medium confidence)", TEXT_DIM)],
        (),
        [("[P8] ", PROMPT_HOST), ("recovery and denial check", TEXT_PRI)],
        [("     ", TEXT_PRI), ("→ identified IOCs: 14 file hashes, 3 C2 domains, 1 registry key, 2 scheduled tasks", TEXT_DIM)],
        (),
        [("[P9] ", PROMPT_HOST), ("finding emission", TEXT_PRI)],
        [("     ", TEXT_PRI), ("→ /tmp/case-04-out/findings.json     (24 findings, 21 high-confidence)", TEXT_DIM)],
        [("     ", TEXT_PRI), ("→ /tmp/case-04-out/audit.jsonl       (143 MCP calls hashed)", TEXT_DIM)],
        [("     ", TEXT_PRI), ("→ /tmp/case-04-out/report.md         (3,847 words)", TEXT_DIM)],
        (),
        [("[done] ", SUCCESS), ("agent run complete in 47.3 seconds", TEXT_PRI)],
        (),
        _prompt_line("python3 -m dart_audit verify /tmp/case-04-out/audit.jsonl"),
    ])

    # Frame 5: audit verification
    render_frame("s4_05_audit_verify", [
        _prompt_line("python3 -m dart_audit verify /tmp/case-04-out/audit.jsonl"),
        (),
        [("Reading audit chain ...", TEXT_DIM)],
        [("  entries:        143", TEXT_PRI)],
        [("  first entry:    manifest-seed (Velociraptor collector)", TEXT_PRI)],
        [("  last  entry:    findings emission @ 2026-04-30T15:11:08Z", TEXT_PRI)],
        [("  hash algorithm: SHA-256 (chain mode)", TEXT_PRI)],
        (),
        [("Verifying linkage ...", TEXT_DIM)],
        [("  ", SUCCESS), ("✓  all entries link correctly to predecessor hashes", TEXT_PRI)],
        [("  ", SUCCESS), ("✓  no out-of-order timestamps", TEXT_PRI)],
        [("  ", SUCCESS), ("✓  no missing audit_id references in findings.json", TEXT_PRI)],
        (),
        [("[", SUCCESS), ("OK", SUCCESS), ("] ", SUCCESS), ("chain intact  ·  143 entries  ·  terminal hash 3f9b2e...a04c", TEXT_PRI)],
        (),
        _prompt_line(""),
    ])


# ════════════════════════════════════════════════════════════════════════════
#  SCENE 5 — v0.6.1 new capabilities (detect_dns_tunneling demo)
# ════════════════════════════════════════════════════════════════════════════
def scene5_frames():
    print("[scene5] v0.6.1 dns tunneling")

    cmd = """python3 -c "
from dart_mcp import call_tool
import json
result = call_tool('detect_dns_tunneling', {
    'dns_log_path': 'examples/sample-evidence-realistic/dns/query.log',
    'entropy_threshold': 3.8,
})
print(json.dumps(result['flagged_queries'][:3], indent=2))
print(f'Total flagged: {result[\\"total_flagged\\"]}')
print(f'High-volume parent domains: {result[\\"high_volume_domains\\"]}')
" """

    # Frame 1: command typed (multi-line)
    render_frame("s5_01_typed", [
        _prompt_line('python3 -c "'),
        [("  from dart_mcp import call_tool", TEXT_PRI)],
        [("  import json", TEXT_PRI)],
        [("  result = call_tool('detect_dns_tunneling', {", TEXT_PRI)],
        [("      'dns_log_path': 'examples/.../dns/query.log',", TEXT_PRI)],
        [("      'entropy_threshold': 3.8,", TEXT_PRI)],
        [("  })", TEXT_PRI)],
        [("  print(json.dumps(result['flagged_queries'][:3], indent=2))", TEXT_PRI)],
        [("  print(f'Total flagged: {result[\\\"total_flagged\\\"]}')", TEXT_PRI)],
        [('"', TEXT_PRI)],
    ])

    # Frame 2: output
    render_frame("s5_02_output", [
        [("[", SUCCESS), ("  {", TEXT_PRI)],
        [("    \"fqdn\": \"aB3xQ7zK9mP2wR5sT8vL1jH4nE6dY0gF.evil.example.com\",", TEXT_PRI)],
        [("    \"qtype\": \"TXT\",", TEXT_PRI)],
        [("    \"lineno\": 142,", TEXT_PRI)],
        [("    \"flags\": [\"high_entropy_label\", \"rare_qtype_TXT\"]", WARN)],
        [("  },", TEXT_PRI)],
        [("  {", TEXT_PRI)],
        [("    \"fqdn\": \"dnscat.attacker.example.com\",", TEXT_PRI)],
        [("    \"qtype\": \"CNAME\",", TEXT_PRI)],
        [("    \"lineno\": 247,", TEXT_PRI)],
        [("    \"flags\": [\"dnscat2_signature\", \"rare_qtype_CNAME\"]", ERROR)],
        [("  },", TEXT_PRI)],
        [("  {", TEXT_PRI)],
        [("    \"fqdn\": \"io" + "A"*42 + ".tunnel.evil.example.com\",", TEXT_PRI)],
        [("    \"qtype\": \"A\",", TEXT_PRI)],
        [("    \"flags\": [\"iodine_signature_candidate\", \"long_label\"]", ERROR)],
        [("  }", TEXT_PRI)],
        [("]", TEXT_PRI)],
        [("Total flagged: ", TEXT_PRI), ("73", WARN)],
        [("High-volume parent domains: [{'parent_domain': 'evil.example.com', 'query_count': 218}]", WARN)],
    ])


if __name__ == "__main__":
    print("[generating Agentic-DART demo terminal frames]\n")
    scene2_frames()
    scene3_frames()
    scene4_frames()
    scene5_frames()
    print(f"\ndone -> {OUT}")
    print(f"frames: {len(list(OUT.glob('*.png')))}")
