"""Documentation consistency checks.

The long-form documentation lives in ``docs/`` with a short landing page in
``README.md`` and one README per package. These tests keep that set honest
against the tree it describes:

1. every relative link and ``#anchor`` resolves (GitHub slug rules);
2. every documented command exists (``python3 -m dfir_*`` / ``scripts.*``
   modules, ``scripts/*.py``, ``scripts/eval/*.py``, ``examples/*.sh``,
   ``analyze.py``);
3. every tool-surface count (total / native / SIFT) equals what
   ``dfir_mcp.list_tools()`` registers right now;
4. the newest released version in ``CHANGELOG.md`` equals the version in every
   ``*/pyproject.toml``;
5. every "N ground-truth findings" phrase equals the number of findings in the
   bundled ``truth.json`` files.

Standard library only, no network. Runs from the repository root either with
the CI ``PYTHONPATH`` or bare (``python3 -m pytest tests/test_docs_consistency.py``)
because the four ``src`` directories are added to ``sys.path`` below.
"""
from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC_DIRS = [
    REPO / "dfir_audit" / "src",
    REPO / "dfir_mcp" / "src",
    REPO / "dfir_agent" / "src",
    REPO / "dfir_corr" / "src",
]
for _d in SRC_DIRS:
    if _d.is_dir() and str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

# Modules that documentation legitimately invokes with ``python3 -m`` but that
# ship in the companion repository (agentic-dfir-collector-adapter), not here.
COMPANION_MODULES = {"dfir_collector_adapter"}


# --------------------------------------------------------------------------- #
# file inventory
# --------------------------------------------------------------------------- #

def doc_files() -> list[Path]:
    """The documentation surface these checks cover."""
    found: set[Path] = set()
    for pattern in (
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/**/*.md",
        "dfir_*/README.md",
        "dfir_playbook/README.md",
        "dfir_sigma/README.md",
        "examples/README.md",
        "scripts/README.md",
        "tests/README.md",
        ".github/**/*.md",
    ):
        found.update(p for p in REPO.glob(pattern) if p.is_file())
    return sorted(found)


DOC_FILES = doc_files()
DOC_IDS = [str(p.relative_to(REPO)) for p in DOC_FILES]


def rel(path: Path) -> str:
    return str(path.relative_to(REPO))


# --------------------------------------------------------------------------- #
# markdown helpers
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_INLINE_CODE_RE = re.compile(r"`+[^`]*`+")
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_HTML_ANCHOR_RE = re.compile(r"""<a\s+(?:name|id)=["']([^"']+)["']""", re.I)
# Markdown inline link / image: [text](target "title") — target may be <wrapped>.
_MD_LINK_RE = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
# HTML links and images used for badges, the hero image and screenshots.
_HTML_LINK_RE = re.compile(r"""<(?:a|img)\s[^>]*?(?:href|src)=["']([^"']+)["']""", re.I)


@lru_cache(maxsize=None)
def numbered_lines(path: Path) -> tuple[tuple[int, str, bool], ...]:
    """(line_no, text, in_fenced_code) for every line of *path*."""
    out = []
    fence_marker: str | None = None
    for no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        m = _FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                out.append((no, line, True))
                continue
            if marker[0] == fence_marker:
                fence_marker = None
                out.append((no, line, True))
                continue
        out.append((no, line, fence_marker is not None))
    return tuple(out)


def prose_lines(path: Path) -> list[tuple[int, str]]:
    """Lines outside fenced code, with inline code spans removed."""
    return [
        (no, _INLINE_CODE_RE.sub(" ", text))
        for no, text, fenced in numbered_lines(path)
        if not fenced
    ]


def heading_text_to_slug(text: str) -> str:
    """GitHub's heading slug: render inline markdown to plain text, lowercase,
    drop everything except letters, digits, underscores, spaces and hyphens,
    then turn spaces into hyphens."""
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)  # image -> alt
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # link -> text
    text = re.sub(r"<[^>]+>", "", text)  # inline html
    text = text.replace("`", "").replace("*", "").replace("~", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s", "-", text)
    return text


@lru_cache(maxsize=None)
def anchors_in(path: Path) -> frozenset[str]:
    """Every anchor GitHub renders for *path*: heading slugs (duplicates get
    ``-1``, ``-2`` …) plus explicit ``<a name=...>`` / ``<a id=...>`` tags."""
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    for _no, text, fenced in numbered_lines(path):
        if fenced:
            continue
        m = _HEADING_RE.match(text)
        if m:
            slug = heading_text_to_slug(m.group(2))
            if slug in seen:
                seen[slug] += 1
                slug = f"{slug}-{seen[slug]}"
            else:
                seen[slug] = 0
            anchors.add(slug)
        for a in _HTML_ANCHOR_RE.finditer(text):
            anchors.add(a.group(1))
    return frozenset(anchors)


def links_in(path: Path) -> list[tuple[int, str]]:
    """(line_no, target) for every markdown and HTML link outside fenced code."""
    out = []
    for no, text in prose_lines(path):
        for m in _MD_LINK_RE.finditer(text):
            out.append((no, m.group(1)))
        for m in _HTML_LINK_RE.finditer(text):
            out.append((no, m.group(1)))
    return out


# --------------------------------------------------------------------------- #
# 1. relative links and anchors resolve
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("doc", DOC_FILES, ids=DOC_IDS)
def test_relative_links_and_anchors_resolve(doc: Path):
    failures = []
    for no, target in links_in(doc):
        lowered = target.lower()
        if lowered.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _, fragment = target.partition("#")
        path_part = unquote(path_part)
        if path_part:
            resolved = (doc.parent / path_part).resolve()
            if not resolved.exists():
                failures.append(f"{rel(doc)}:{no} → {target}  (missing file)")
                continue
        else:
            resolved = doc
        if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
            if fragment not in anchors_in(resolved):
                failures.append(f"{rel(doc)}:{no} → {target}  (no such anchor)")
    assert not failures, "unresolved links:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# 2. referenced commands exist
# --------------------------------------------------------------------------- #

_MODULE_RE = re.compile(r"\bpython3?\s+-m\s+((?:dfir_|scripts\.)[\w.]*)")
_PATH_RE = re.compile(
    r"(?<![\w/.-])(?:\./)?("
    r"scripts/eval/[\w-]+\.py"
    r"|scripts/[\w-]+\.py"
    r"|examples/[\w-]+\.sh"
    r"|analyze\.py"
    r")\b"
)


def module_exists(module: str) -> bool:
    parts = module.split(".")
    for base in [REPO, *SRC_DIRS]:
        candidate = base.joinpath(*parts)
        if candidate.with_suffix(".py").is_file():
            return True
        if candidate.is_dir() and (
            (candidate / "__init__.py").is_file() or (candidate / "__main__.py").is_file()
        ):
            return True
    return False


@pytest.mark.parametrize("doc", DOC_FILES, ids=DOC_IDS)
def test_referenced_commands_exist(doc: Path):
    failures = []
    for no, text, _fenced in numbered_lines(doc):
        for m in _MODULE_RE.finditer(text):
            module = m.group(1).rstrip(".")
            if module.split(".")[0] in COMPANION_MODULES:
                continue
            if not module_exists(module):
                failures.append(f"{rel(doc)}:{no} → python3 -m {module}  (module not in tree)")
        for m in _PATH_RE.finditer(text):
            if not (REPO / m.group(1)).is_file():
                failures.append(f"{rel(doc)}:{no} → {m.group(1)}  (file not in tree)")
    assert not failures, "documented commands that do not exist:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# 3. tool-surface numbers
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=None)
def tool_surface() -> dict[str, int]:
    from dfir_mcp import list_tools

    tools = list_tools()
    sift = [t for t in tools if t["name"].startswith("sift_")]
    return {"total": len(tools), "native": len(tools) - len(sift), "sift": len(sift)}


# A number may be closed by bold/italic markers ("= 73** typed read-only tools").
_NUM = r"\b(\d+)[*_]{0,2}\s+"

# (pattern, key) — key is the surface figure the captured number must equal;
# "functions" decides between native and total from the phrase itself.
_COUNT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # "48 native functions", "48 native + 25 SIFT", "48 native pure-Python …"
    (re.compile(_NUM + r"native\b", re.I), "native"),
    # "25 SIFT Workstation tool adapters", "25 SIFT adapters", "(… + 25 SIFT)",
    # "25 SIFT Workstation" at line end — but not "5 SIFT adapter layer guarantees".
    (
        re.compile(
            _NUM + r"SIFT\b(?:\s+Workstation)?(?:\s+tool)?"
            r"(?:\s+adapters?\b(?!\s+layer)|(?=\s*(?:[).,;:—–-]|=|$)))",
            re.I,
        ),
        "sift",
    ),
    # "73 tools", "73 typed read-only MCP tools", "72 typed MCP tools"
    (re.compile(_NUM + r"(?:typed[,\s]+)?(?:read-only\s+)?(?:MCP\s+)?tools\b", re.I), "total"),
    # "73 read-only functions", "73 registered functions",
    # "73 read-only native functions" (native), "73 functions, 48 native …"
    (
        re.compile(
            _NUM + r"(?:typed[,\s]+)?(?:read-only\s+|registered\s+)"
            r"(?P<native>native\s+)?(?:forensic\s+)?functions\b",
            re.I,
        ),
        "functions",
    ),
    (re.compile(_NUM + r"functions\b(?=,?\s+\d+\s+native\b)", re.I), "total"),
    # "73 total — 48 native + 25 SIFT adapters"
    (re.compile(_NUM + r"total\b(?=\s*[—–-]*\s*\d+\s+native\b)", re.I), "total"),
]

# Release-history table rows ("| 2026-04-30 | **v0.4** | … 35 native functions |")
# describe a past surface, not the current one.
_HISTORY_ROW_RE = re.compile(r"^\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|[^|]*\bv\d+\.\d+")


def _is_history_row(text: str) -> bool:
    return bool(_HISTORY_ROW_RE.match(text))


@pytest.mark.parametrize("doc", DOC_FILES, ids=DOC_IDS)
def test_tool_surface_numbers(doc: Path):
    surface = tool_surface()
    failures = []
    for no, text in prose_lines(doc):
        if _is_history_row(text):
            continue
        for pattern, key in _COUNT_PATTERNS:
            for m in pattern.finditer(text):
                if key == "functions":
                    key_here = "native" if m.group("native") else "total"
                else:
                    key_here = key
                expected = surface[key_here]
                if int(m.group(1)) != expected:
                    failures.append(
                        f"{rel(doc)}:{no} → \"{m.group(0).strip()}\" "
                        f"(computed {key_here} = {expected})"
                    )
    assert not failures, (
        f"tool-surface counts disagree with dfir_mcp.list_tools() {surface}:\n  "
        + "\n  ".join(failures)
    )


def test_tool_surface_is_nonempty():
    surface = tool_surface()
    assert surface["native"] > 0 and surface["sift"] > 0


# --------------------------------------------------------------------------- #
# 4. versions agree
# --------------------------------------------------------------------------- #

_CHANGELOG_HEADING_RE = re.compile(r"^## \[([^\]]+)\]")
_PYPROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)


def changelog_released_version() -> str:
    for line in (REPO / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        m = _CHANGELOG_HEADING_RE.match(line)
        if m and m.group(1).lower() != "unreleased":
            return m.group(1).strip()
    raise AssertionError("CHANGELOG.md has no released '## [x.y.z]' heading")


def test_changelog_version_matches_every_pyproject():
    released = changelog_released_version()
    pyprojects = sorted(REPO.glob("*/pyproject.toml"))
    assert pyprojects, "no */pyproject.toml found"
    mismatches = []
    for p in pyprojects:
        m = _PYPROJECT_VERSION_RE.search(p.read_text(encoding="utf-8"))
        version = m.group(1) if m else "<missing>"
        if version != released:
            mismatches.append(f"{rel(p)} version = {version}")
    assert not mismatches, (
        f"CHANGELOG.md newest release is [{released}] but:\n  " + "\n  ".join(mismatches)
    )


# --------------------------------------------------------------------------- #
# 5. ground-truth count
# --------------------------------------------------------------------------- #

_GROUND_TRUTH_RE = re.compile(_NUM + r"ground[- ]truth\s+findings\b", re.I)


def bundled_ground_truth_count() -> int:
    truth_files = sorted(REPO.glob("examples/case-studies/*/*/truth.json"))
    assert truth_files, "no examples/case-studies/*/*/truth.json found"
    total = 0
    for tf in truth_files:
        data = json.loads(tf.read_text(encoding="utf-8"))
        total += len(data.get("ground_truth_findings", []))
    return total


def test_ground_truth_finding_count_matches_docs():
    expected = bundled_ground_truth_count()
    failures = []
    for doc in DOC_FILES:
        for no, text in prose_lines(doc):
            if _is_history_row(text):
                continue
            for m in _GROUND_TRUTH_RE.finditer(text):
                if int(m.group(1)) != expected:
                    failures.append(f"{rel(doc)}:{no} → \"{m.group(0).strip()}\"")
    assert not failures, (
        f"bundled truth.json files hold {expected} ground-truth findings, but:\n  "
        + "\n  ".join(failures)
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
