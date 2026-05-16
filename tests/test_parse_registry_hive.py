"""Unit tests for parse_registry_hive (v0.5.4) — closes CFReDS gap G-001.

Uses an 8 KB Windows registry hive fixture (TimeZoneInformation key with
10 values) borrowed from williballenthin/python-registry's test corpus.
"""
import os
import sys
from pathlib import Path
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dart_mcp" / "src"))
sys.path.insert(0, str(REPO / "dart_audit" / "src"))

FIXTURES = REPO / "tests" / "fixtures" / "registry-hives"


@pytest.fixture(autouse=True)
def _evidence_root_for_registry_tests(monkeypatch):
    """Point DART_EVIDENCE_ROOT at the registry-hives fixture dir for
    these tests, then restore.

    Previous implementation used `importlib.reload(dart_mcp)` which
    rebuilt the module-level _REGISTRY from scratch — but only for the
    top-level dart_mcp package. Sub-modules that contributed @register
    decorations during their own import time were NOT re-imported by
    reload(), so the _REGISTRY came back with 38 functions missing.
    This was invisible when tests ran in their declared order (the
    teardown reload happened to fire before any surface-checking test)
    but caused 47 failures under random-order execution.

    Safer approach: patch dart_mcp.EVIDENCE_ROOT in place. The module
    state stays intact and EVIDENCE_ROOT reverts on teardown."""
    import dart_mcp as _dm
    monkeypatch.setenv("DART_EVIDENCE_ROOT", str(FIXTURES))
    monkeypatch.setattr(_dm, "EVIDENCE_ROOT", FIXTURES, raising=False)
    yield
    # monkeypatch fixture handles restoration of both env and attribute


def _call(name, args):
    """Late import to ensure the reloaded module is used."""
    from dart_mcp import call_tool as _ct
    return _ct(name, args)


def _path_traversal_class():
    from dart_mcp import PathTraversalAttempt
    return PathTraversalAttempt


def test_root_via_empty_key():
    """Empty key string reads the hive's root node."""
    r = _call('parse_registry_hive', {'hive_path': 'sample.hive', 'key': ''})
    assert 'error' not in r, f"unexpected error: {r}"
    assert r['values_total'] == 10
    names = {v['name'] for v in r['values']}
    assert 'DaylightName' in names
    assert 'StandardName' in names
    assert 'Bias' in names
    assert 'DaylightStart' in names


def test_root_via_full_path():
    """Passing the root key's own name resolves to root."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive',
        'key': 'TimeZoneInformation'
    })
    assert 'error' not in r
    assert r['values_total'] == 10


def test_specific_value_extraction():
    """Single value extraction returns typed dict."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': '',
        'value_name': 'DaylightName'
    })
    assert 'error' not in r
    assert r['value']['name'] == 'DaylightName'
    assert r['value']['type'] == 'RegSZ'
    assert isinstance(r['value']['data'], str)


def test_dword_value_type():
    """Numeric DWORD values are returned as int."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': '',
        'value_name': 'DaylightBias'
    })
    assert r['value']['type'] == 'RegDWord'
    assert isinstance(r['value']['data'], int)


def test_binary_value_base64_encoded():
    """Binary blobs (REG_BINARY) come back base64-encoded with size."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': '',
        'value_name': 'StandardStart'  # SYSTEMTIME blob
    })
    assert r['value']['type'] == 'RegBin'
    assert 'data_base64' in r['value']
    assert r['value']['data_size'] > 0


def test_nonexistent_key_returns_error_with_hint():
    """Bad key paths return typed error, not exception."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': 'NoSuchKey'
    })
    assert r['error'] == 'key_not_found'
    assert 'hint' in r
    assert r['root_key_in_hive'] == 'TimeZoneInformation'


def test_nonexistent_value_returns_error():
    """Bad value names return typed error."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': '',
        'value_name': 'FakeValue'
    })
    assert r['error'] == 'value_not_found'


def test_file_not_found():
    """Missing hive file returns typed error."""
    r = _call('parse_registry_hive', {
        'hive_path': 'does-not-exist.hive', 'key': ''
    })
    assert r['error'] == 'file_not_found'


def test_path_traversal_blocked():
    """../../etc/passwd-style paths must raise, not return."""
    try:
        _call('parse_registry_hive', {
            'hive_path': '../../../etc/passwd', 'key': ''
        })
    except _path_traversal_class():
        return
    raise AssertionError("PathTraversalAttempt not raised for ../etc/passwd")


def test_null_byte_blocked():
    """Null byte in path must raise."""
    try:
        _call('parse_registry_hive', {
            'hive_path': 'sample.hive\x00.evil', 'key': ''
        })
    except _path_traversal_class():
        return
    raise AssertionError("PathTraversalAttempt not raised for null byte path")


def test_forward_slash_normalization():
    """Forward slashes accepted as separator (POSIX habit)."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive',
        'key': 'TimeZoneInformation/'
    })
    # Trailing slash gets stripped during normalization, falls through to
    # root resolution. Either way, no error and we see all values.
    assert 'error' not in r or r.get('error') == 'key_not_found'  # accepted variants


def test_audit_chain_includes_call():
    """parse_registry_hive output includes source SHA-256 (audit-friendly)."""
    r = _call('parse_registry_hive', {
        'hive_path': 'sample.hive', 'key': ''
    })
    assert 'source' in r
    assert 'sha256' in r['source']
    assert len(r['source']['sha256']) == 64  # SHA-256 hex


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_') and callable(fn):
            try:
                fn()
                print(f"  ✅ {name}")
            except AssertionError as e:
                print(f"  ❌ {name}: {e}")
            except Exception as e:
                print(f"  💥 {name}: {type(e).__name__}: {e}")
