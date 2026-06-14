"""Offline unit tests for scripts/eval/download.py.

No network is touched: the HTTP boundary (`_download`) is monkeypatched to
write dummy bytes, so we can exercise the pure-Python split-concat, the
browser-header construction, --dry-run, and --check-urls deterministically.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from eval import download as dl  # noqa: E402


# --------------------------------------------------------------------------- #
# pure-Python split concatenation
# --------------------------------------------------------------------------- #

def test_concat_parts_byte_exact(tmp_path):
    parts = []
    payloads = [b"AAAA" * 10, b"BBBB" * 7, b"CCCC" * 3]
    for i, payload in enumerate(payloads, 1):
        p = tmp_path / f"SPLIT.{i:03d}"
        p.write_bytes(payload)
        parts.append(p)
    joined = tmp_path / "joined.dd"
    dl.concat_parts(parts, joined, chunk=8)  # tiny chunk to exercise streaming
    assert joined.read_bytes() == b"".join(payloads)
    # the temp .partial file must not linger
    assert not joined.with_suffix(".dd.partial").exists()


def test_concat_parts_missing_raises(tmp_path):
    p1 = tmp_path / "a.001"
    p1.write_bytes(b"x")
    with pytest.raises(FileNotFoundError):
        dl.concat_parts([p1, tmp_path / "a.002"], tmp_path / "out.dd")


# --------------------------------------------------------------------------- #
# browser-like headers on every request (incl. resumed range request)
# --------------------------------------------------------------------------- #

def test_request_carries_browser_user_agent():
    req = dl._build_request("https://example.test/x.001")
    ua = req.get_header("User-agent")
    assert ua and "Mozilla/5.0" in ua and "Chrome/125" in ua
    assert req.get_header("Connection") == "keep-alive"


def test_resume_request_keeps_headers_and_adds_range():
    req = dl._build_request("https://example.test/x.001",
                            extra_headers={"Range": "bytes=100-"})
    assert "Mozilla/5.0" in req.get_header("User-agent")
    assert req.get_header("Range") == "bytes=100-"


# --------------------------------------------------------------------------- #
# end-to-end download with a fake dataset + mocked HTTP -> concat + md5 verify
# --------------------------------------------------------------------------- #

@pytest.fixture
def fake_split_dataset(monkeypatch):
    import hashlib
    payloads = {"DUMMY.001": b"hello-", "DUMMY.002": b"world!"}
    joined_bytes = b"".join(payloads.values())
    joined_md5 = hashlib.md5(joined_bytes).hexdigest()

    spec = {
        "title": "Dummy Split Dataset",
        "short": "dummy",
        "size_gb": 0.0,
        "homepage": "https://example.test/",
        "download_base": "https://example.test/files",
        "parts": [("DUMMY.001", "md5", None), ("DUMMY.002", "md5", None)],
        "reassemble_cmd": "cat DUMMY.001 DUMMY.002 > DUMMY.dd",
        "joined_name": "DUMMY.dd",
        "joined_md5": joined_md5,
    }
    monkeypatch.setitem(dl.DATASETS, "dummy", spec)

    def fake_download(url, dst, *, resume=True):
        name = url.rsplit("/", 1)[-1]
        Path(dst).write_bytes(payloads[name])

    monkeypatch.setattr(dl, "_download", fake_download)
    return joined_bytes


def test_download_joins_dummy_splits(tmp_path, fake_split_dataset):
    final = dl.download("dummy", tmp_path)
    assert final.name == "DUMMY.dd"
    assert final.read_bytes() == fake_split_dataset  # concatenated + md5-verified


def test_dry_run_fetches_nothing(tmp_path, fake_split_dataset, capsys):
    dest = dl.download("dummy", tmp_path, dry_run=True)
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    # no parts and no joined image written
    assert not (dest / "DUMMY.001").exists()
    assert not (dest / "DUMMY.dd").exists()


# --------------------------------------------------------------------------- #
# --check-urls
# --------------------------------------------------------------------------- #

def test_check_urls_uses_probe(monkeypatch, fake_split_dataset):
    seen = []

    def fake_check(url, *, timeout=30):
        seen.append(url)
        return True, "HTTP 200 size=6"

    monkeypatch.setattr(dl, "check_url", fake_check)
    rc = dl._check_urls(["dummy"])
    assert rc == 0
    assert seen == [
        "https://example.test/files/DUMMY.001",
        "https://example.test/files/DUMMY.002",
    ]
