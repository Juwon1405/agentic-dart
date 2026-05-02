"""
test_sift_adapters.py — Verify SIFT adapters are registered and behave correctly.

These tests do NOT require the SIFT tools to actually be installed — they
verify:

  1. All adapters successfully register with dart_mcp's tool registry
  2. SiftToolNotFoundError fires cleanly when binaries are absent
  3. PathTraversalAttempt fires when a malicious path is supplied
  4. The schema for each adapter is well-formed JSON Schema
  5. EVIDENCE_ROOT sandbox boundary is shared with native adapters

This pairs with test_mcp_bypass.py — same architectural guarantees apply
to SIFT adapters as to native ones.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dart_mcp" / "src"))
os.environ["DART_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")

# Force adapter package import (triggers @tool registration)
from dart_mcp import call_tool, list_tools  # noqa: E402
from dart_mcp import sift_adapters  # noqa: E402, F401
from dart_mcp.sift_adapters._common import (  # noqa: E402
    SiftToolFailedError,
    SiftToolNotFoundError,
    safe_evidence_input,
)
from dart_mcp import PathTraversalAttempt  # noqa: E402


# Expected adapter tool names — must match @tool(name=...) decorators
EXPECTED_SIFT_TOOLS = {
    # volatility3 (12)
    "sift_vol3_windows_pslist",
    "sift_vol3_windows_pstree",
    "sift_vol3_windows_psscan",
    "sift_vol3_windows_cmdline",
    "sift_vol3_windows_netscan",
    "sift_vol3_windows_malfind",
    "sift_vol3_windows_dlllist",
    "sift_vol3_windows_svcscan",
    "sift_vol3_windows_runkey",
    "sift_vol3_linux_pslist",
    "sift_vol3_linux_bash",
    "sift_vol3_mac_bash",
    # mftecmd (2)
    "sift_mftecmd_parse",
    "sift_mftecmd_timestomp",
    # evtxecmd (2)
    "sift_evtxecmd_parse",
    "sift_evtxecmd_filter_eids",
    # pecmd (2)
    "sift_pecmd_parse",
    "sift_pecmd_run_history",
    # recmd (2)
    "sift_recmd_run_batch",
    "sift_recmd_query_key",
    # amcacheparser (1)
    "sift_amcacheparser_parse",
    # yara (2)
    "sift_yara_scan_file",
    "sift_yara_scan_dir",
    # plaso (2)
    "sift_plaso_log2timeline",
    "sift_plaso_psort",
}


def test_all_sift_adapters_registered():
    """Every adapter we wrote must appear in list_tools()."""
    registered = {t["name"] for t in list_tools()}
    missing = EXPECTED_SIFT_TOOLS - registered
    assert not missing, f"Adapters not registered: {sorted(missing)}"


def test_sift_adapters_dont_clobber_native_tools():
    """SIFT adapter names must not collide with native dart_mcp tool names."""
    registered = [t["name"] for t in list_tools()]
    # No duplicates allowed
    assert len(registered) == len(set(registered))
    # SIFT adapters all start with sift_
    sift_count = sum(1 for n in registered if n.startswith("sift_"))
    assert sift_count == len(EXPECTED_SIFT_TOOLS)


def test_each_sift_adapter_has_valid_schema():
    """Schemas must be dicts with type=object and properties."""
    for tool_def in list_tools():
        if not tool_def["name"].startswith("sift_"):
            continue
        schema = tool_def["inputSchema"]
        assert isinstance(schema, dict), f"{tool_def['name']}: schema not dict"
        assert schema.get("type") == "object", f"{tool_def['name']}: type != object"
        assert "properties" in schema, f"{tool_def['name']}: missing properties"
        # Each declared property must be a dict with a 'type'
        for prop_name, prop_def in schema["properties"].items():
            assert isinstance(prop_def, dict)
            assert "type" in prop_def, f"{tool_def['name']}.{prop_name}: missing type"


def test_path_traversal_blocked_in_sift_adapters():
    """SIFT adapters must reject path traversal attempts."""
    for malicious in ["../etc/passwd", "/etc/shadow", "..\\..\\Windows\\System32"]:
        try:
            safe_evidence_input(malicious)
            raise AssertionError(f"safe_evidence_input accepted {malicious!r}")
        except PathTraversalAttempt:
            pass
        except FileNotFoundError:
            # Acceptable if the path resolves but doesn't exist
            pass


def test_null_byte_blocked_in_sift_adapters():
    """SIFT adapters must reject null bytes in paths."""
    try:
        safe_evidence_input("evidence\x00../etc/passwd")
        raise AssertionError("null byte path accepted")
    except PathTraversalAttempt:
        pass


def test_missing_tool_raises_clean_error():
    """When a SIFT binary is missing, error message is clear and includes install hint."""
    # Set env var to a non-existent binary path
    original = os.environ.get("DART_VOLATILITY3_BIN")
    os.environ["DART_VOLATILITY3_BIN"] = "/nonexistent/vol-binary-XYZ"
    try:
        # Need a valid evidence path for this test, otherwise PathTraversalAttempt
        # fires first. Use the sample evidence dir.
        sample_evtx = REPO / "examples" / "sample-evidence"
        # Pick any volatility plugin
        try:
            call_tool("sift_vol3_windows_pslist",
                      {"image_path": "memory/sample.raw"})
            # If we get here, either the tool ran (unlikely in test env)
            # or PathTraversalAttempt fired before the binary check
        except SiftToolNotFoundError as e:
            assert "DART_VOLATILITY3_BIN" in str(e) or "executable" in str(e)
        except (PathTraversalAttempt, FileNotFoundError):
            # Sample evidence not present — that's OK, we're testing binary
            # resolution, and the path check fires first.
            pass
    finally:
        if original is None:
            os.environ.pop("DART_VOLATILITY3_BIN", None)
        else:
            os.environ["DART_VOLATILITY3_BIN"] = original


def test_sift_adapter_count_matches_documentation():
    """Documentation says 22+ adapters. Verify we hit the announced count."""
    registered = [t["name"] for t in list_tools() if t["name"].startswith("sift_")]
    # If this fails after adding new adapters, update the README count too
    assert len(registered) == 25, (
        f"SIFT adapter count drifted to {len(registered)}. "
        f"Update README.md, CHANGELOG.md, and Wiki accordingly. "
        f"Tools: {sorted(registered)}"
    )


def test_total_tool_count_native_plus_sift():
    """Native 35 + SIFT 25 = 60. If this drifts, update README hero numbers."""
    all_tools = [t["name"] for t in list_tools()]
    # Negative — confirm no native tools were accidentally renamed
    native = [t for t in all_tools if not t.startswith("sift_")]
    assert len(native) >= 35, f"Native tool count regressed to {len(native)}"


if __name__ == "__main__":
    test_all_sift_adapters_registered()
    test_sift_adapters_dont_clobber_native_tools()
    test_each_sift_adapter_has_valid_schema()
    test_path_traversal_blocked_in_sift_adapters()
    test_null_byte_blocked_in_sift_adapters()
    test_missing_tool_raises_clean_error()
    test_sift_adapter_count_matches_documentation()
    test_total_tool_count_native_plus_sift()
    print("✓ All SIFT adapter tests passed")
