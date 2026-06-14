"""End-to-end tests for the tiered case-study layout and analyze.py.

These assert the *structure and contracts* of the overhauled platform; they do
not call the Anthropic API (live runs need a key and are out of scope for CI).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import analyze  # noqa: E402

CASE_ROOT = REPO / "examples" / "case-studies"
TIERS = ("self-evaluation", "external-evaluation")


# --------------------------------------------------------------------------- #
# new layout exists and every case is complete
# --------------------------------------------------------------------------- #

def test_tier_directories_exist():
    for tier in TIERS:
        assert (CASE_ROOT / tier).is_dir(), f"missing tier {tier}"


def test_every_case_has_readme_and_truth():
    cases = analyze.discover_cases()
    assert len(cases) >= 11
    for c in cases:
        assert (c.path / "README.md").is_file(), f"{c.ref} missing README.md"
        assert c.truth_path.is_file(), f"{c.ref} missing truth.json"
        json.loads(c.truth_path.read_text())  # valid JSON


def test_index_only_folder_names():
    for c in analyze.discover_cases():
        # folder names are case-NN only (no descriptive suffix)
        assert c.case_id[:5] == "case-" and c.case_id[5:].isdigit(), c.case_id


def test_external_numbering_resets():
    ext = sorted(c.case_id for c in analyze.discover_cases()
                 if c.tier == "external-evaluation")
    assert ext == ["case-01", "case-02", "case-03"]
    # no carryover of the old case-08/09/10 names anywhere
    for name in ("case-08", "case-09", "case-10"):
        assert not (CASE_ROOT / "external-evaluation" / name).exists()


def test_ground_truth_json_renamed_to_truth_json():
    assert not list(CASE_ROOT.glob("**/ground-truth.json"))


def test_case01_has_bundled_evidence():
    c = analyze.get_case("self-evaluation/case-01")
    assert c.has_evidence
    assert (c.evidence_root / "linux").is_dir() or any(c.evidence_root.iterdir())


# --------------------------------------------------------------------------- #
# dynamic discovery (both tiers, no special-casing)
# --------------------------------------------------------------------------- #

def test_discovery_covers_both_tiers():
    tiers = {c.tier for c in analyze.discover_cases()}
    assert tiers == set(TIERS)


def test_get_case_unknown_fails():
    with pytest.raises(SystemExit):
        analyze.get_case("self-evaluation/case-99")


# --------------------------------------------------------------------------- #
# analyze.py CLI contracts
# --------------------------------------------------------------------------- #

def _run(args, *, key=False):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    if key:
        env["ANTHROPIC_API_KEY"] = "sk-test-not-real"
    return subprocess.run([sys.executable, "analyze.py", *args],
                          cwd=REPO, capture_output=True, text=True, env=env)


def test_help_exits_zero():
    r = _run(["--help"])
    assert r.returncode == 0
    assert "live mode only" in r.stdout.lower()


def test_list_needs_no_key():
    r = _run(["--list"])
    assert r.returncode == 0
    assert "self-evaluation/case-01" in r.stdout
    assert "external-evaluation/case-03" in r.stdout


def test_fail_fast_without_key_exact_message():
    r = _run([])
    assert r.returncode == 1
    assert r.stderr.rstrip("\n") == (
        "Error: ANTHROPIC_API_KEY is not set. Export it first:\n"
        "  export ANTHROPIC_API_KEY='sk-...'"
    )


def test_fail_fast_happens_before_work():
    # even with a valid case selected, no key -> fail fast, no out/ dir created
    r = _run(["--case", "self-evaluation/case-01"])
    assert r.returncode == 1
    assert "ANTHROPIC_API_KEY is not set" in r.stderr


def test_external_without_download_gives_remediation():
    # key present but external evidence absent -> clear remediation, no API call
    r = _run(["--case", "external-evaluation/case-01"], key=True)
    assert r.returncode == 3
    assert "download" in r.stderr.lower()
    assert "scripts.eval.download cfreds" in r.stderr


# --------------------------------------------------------------------------- #
# the --variant / sample-evidence-realistic runtime concept is gone
# --------------------------------------------------------------------------- #

def test_no_sample_evidence_realistic_dir():
    assert not (REPO / "examples" / "sample-evidence-realistic").exists()


def test_variant_flag_removed_from_public_runners():
    # The --variant / sample-evidence-realistic runtime concept is gone. Check
    # the current public entry points (the bench trio) don't reintroduce it.
    for rel in ("scripts/eval/demo.py", "scripts/eval/self.py",
                "scripts/eval/external.py"):
        text = (REPO / rel).read_text()
        assert "--variant" not in text, f"{rel} still references --variant"


def test_sample_evidence_realistic_unreferenced_in_source():
    hits = []
    for path in REPO.rglob("*.py"):
        if "__pycache__" in str(path) or path.name == "test_eval_layout.py":
            continue
        if "sample-evidence-realistic" in path.read_text(errors="ignore"):
            hits.append(str(path.relative_to(REPO)))
    assert not hits, f"stale sample-evidence-realistic refs: {hits}"
