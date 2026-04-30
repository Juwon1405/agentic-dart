"""
Concurrency and edge-case input tests added in v0.4.1.

Two classes of issue surfaced during the post-v0.4 QA pass:

  1. AuditLogger.log() had a race condition. Concurrent callers
     could read the same _prev_hash, compute different entry_hashes,
     and append both — chain validation then fails because the
     second entry's prev_hash doesn't match its file-position
     predecessor's entry_hash. Fixed by per-instance threading.Lock
     around the prev_hash read / hash compute / file append /
     prev_hash update critical section.

  2. _safe_resolve() would raise unwrapped OSError on
     File-name-too-long and similar OS-level path errors instead of
     the architectural PathTraversalAttempt exception. Fixed by
     catching OSError inside resolve() and re-raising as
     PathTraversalAttempt.

Both have explicit test coverage now so regression is visible.
"""
from __future__ import annotations
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dart_audit" / "src"))
sys.path.insert(0, str(REPO_ROOT / "dart_mcp" / "src"))
os.environ.setdefault("DART_EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "sample-evidence"))

from dart_audit import AuditLogger
from dart_mcp import _safe_resolve, PathTraversalAttempt


def test_concurrent_writes_preserve_chain():
    """50 threads × 20 calls each must produce a valid chain."""
    tmp = Path(tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name)
    log = AuditLogger(str(tmp))

    def worker(tid):
        for i in range(20):
            log.log(f"call_t{tid}_i{i}", {"x": i}, {"ok": True}, i, 0, 0)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()

    n = sum(1 for _ in tmp.open())
    assert n == 1000, f"expected 1000 entries, got {n}"

    r = subprocess.run([sys.executable, "-m", "dart_audit", "verify", str(tmp)],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"chain verify failed under concurrency: {r.stdout}{r.stderr}"

    tmp.unlink()
    print("test_concurrent_writes_preserve_chain ... OK")


def test_safe_resolve_rejects_too_long_paths():
    """Paths over 1024 chars should be rejected with PathTraversalAttempt, not OSError."""
    long_path = "x" * 2000
    try:
        _safe_resolve(long_path)
        assert False, "should have raised PathTraversalAttempt"
    except PathTraversalAttempt:
        pass  # expected
    print("test_safe_resolve_rejects_too_long_paths ... OK")


def test_safe_resolve_rejects_non_string_inputs():
    """None / list / int / empty must all raise PathTraversalAttempt."""
    for bad in (None, [], 42, "", "   x"[:0]):
        try:
            _safe_resolve(bad)
            assert False, f"should have raised on {bad!r}"
        except PathTraversalAttempt:
            pass
    print("test_safe_resolve_rejects_non_string_inputs ... OK")


if __name__ == "__main__":
    test_concurrent_writes_preserve_chain()
    test_safe_resolve_rejects_too_long_paths()
    test_safe_resolve_rejects_non_string_inputs()
    print("\nAll OK")
