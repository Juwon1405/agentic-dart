#!/usr/bin/env python3
"""
download.py — fetch a registered DFIR dataset to a local directory.

Usage:
    python3 -m scripts.eval.download cfreds /path/to/datasets/
    python3 -m scripts.eval.download hadi1  /path/to/datasets/
    python3 -m scripts.eval.download m57    /path/to/datasets/

    # inspect without downloading anything
    python3 -m scripts.eval.download cfreds /tmp --dry-run
    python3 -m scripts.eval.download all    /tmp --check-urls

The script verifies checksums where available, joins split parts (CFReDS) using
a pure-Python streaming concatenation (no shell), and prints the final image
path on success. Downloaded images are large and third-party; they are never
committed to the repository.

This is run on the user's analysis host (where there's disk space), NOT inside
the Agentic-DART container. Container disk is too small for the full multi-GB
combined dataset corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Make this importable as a module (scripts.eval.download) or runnable directly
try:
    from .datasets import DATASETS
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from datasets import DATASETS

# Shared browser-like headers for EVERY request, including resumed range
# requests. Some hosts (notably NIST CFReDS via its CDN) return HTTP 403 to
# default bot/library User-Agents, so a realistic UA is required for the
# download to succeed at all.
DEFAULT_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

CONCAT_CHUNK = 8 * 1024 * 1024  # 8 MB streaming concat chunk

# Accept both the registry key (cfreds_hacking_case) and the friendly short
# alias (cfreds) on the command line.
_ALIAS = {d["short"]: key for key, d in DATASETS.items()}


def _resolve_key(name: str) -> str:
    if name in DATASETS:
        return name
    if name in _ALIAS:
        return _ALIAS[name]
    raise ValueError(f"unknown dataset '{name}'. "
                     f"known: {sorted(set(DATASETS) | set(_ALIAS))}")


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _checksum(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_request(url: str, *, extra_headers: dict | None = None) -> urllib.request.Request:
    """Build a Request carrying the shared browser-like headers (plus any
    per-request additions such as a Range header for resume)."""
    headers = dict(DEFAULT_HTTP_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    return urllib.request.Request(url, headers=headers)


def check_url(url: str, *, timeout: int = 30) -> tuple[bool, str]:
    """HEAD-like reachability probe using the shared headers. Returns
    (ok, detail). Falls back to a 1-byte ranged GET when HEAD is rejected."""
    try:
        req = _build_request(url)
        req.method = "HEAD"
        with urllib.request.urlopen(req, timeout=timeout) as r:
            size = r.headers.get("Content-Length", "?")
            return True, f"HTTP {r.status} size={size}"
    except urllib.error.HTTPError as e:
        if e.code in (403, 405, 501):  # HEAD not allowed -> try a tiny ranged GET
            try:
                req = _build_request(url, extra_headers={"Range": "bytes=0-0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return True, f"HTTP {r.status} (ranged GET)"
            except Exception as e2:  # noqa: BLE001
                return False, f"{type(e2).__name__}: {e2}"
        return False, f"HTTP {e.code} {e.reason}"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def _download(url: str, dst: Path, *, resume: bool = True) -> None:
    """Streaming HTTP download with optional resume. Uses the shared headers
    on both the initial and the resumed (Range) request."""
    extra: dict[str, str] = {}
    mode = "wb"
    existing = 0
    if resume and dst.exists():
        existing = dst.stat().st_size
        if existing > 0:
            extra["Range"] = f"bytes={existing}-"
            mode = "ab"

    req = _build_request(url, extra_headers=extra)
    print(f"  GET  {url}")
    if existing:
        print(f"       resuming from {_human(existing)}")
    with urllib.request.urlopen(req, timeout=60) as r, dst.open(mode) as f:
        total = int(r.headers.get("Content-Length", 0)) + existing
        got = existing
        chunk = 1 * 1024 * 1024  # 1 MB
        last_print = 0
        while True:
            buf = r.read(chunk)
            if not buf:
                break
            f.write(buf)
            got += len(buf)
            if got - last_print > 50 * 1024 * 1024:  # every 50 MB
                pct = (100 * got / total) if total else 0
                print(f"       {_human(got)} / {_human(total)} ({pct:.1f}%)")
                last_print = got
    final_size = dst.stat().st_size
    print(f"       done: {_human(final_size)}")


def concat_parts(part_paths: list[Path], joined: Path, *, chunk: int = CONCAT_CHUNK) -> Path:
    """Pure-Python streaming concatenation of split image parts (replaces the
    shell ``cat part.001 part.002 ... > joined``). Streams in ``chunk``-sized
    blocks via shutil.copyfileobj so arbitrarily large images never load into
    memory, and works identically on Linux, macOS, and Windows."""
    missing = [str(p) for p in part_paths if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"missing split parts: {missing}")
    tmp = joined.with_suffix(joined.suffix + ".partial")
    with tmp.open("wb") as out:
        for p in part_paths:
            with p.open("rb") as src:
                shutil.copyfileobj(src, out, length=chunk)
    tmp.replace(joined)
    return joined


def download(short: str, dest_dir: str | Path, *, verify: bool = True,
             dry_run: bool = False) -> Path:
    """Download a dataset by short name. Return the path to the joined image.

    With ``dry_run=True`` no bytes are fetched: the plan (URLs, target paths,
    reassembly, checksums) is printed and the destination directory is returned.
    """
    short = _resolve_key(short)
    spec = DATASETS[short]
    dest = Path(dest_dir) / short
    print(f"\n=== {spec['title']} ===")
    print(f"target: {dest}")
    print(f"expected size: {spec['size_gb']:.1f} GB")

    part_urls = [
        (spec["download_base"].rstrip("/") + "/" + name, name, algo, expected)
        for (name, algo, expected) in spec["parts"]
    ]

    if dry_run:
        print("  [dry-run] would fetch:")
        for url, name, algo, expected in part_urls:
            exp = f" {algo}={expected}" if expected else ""
            print(f"    {url} -> {dest / name}{exp}")
        if spec.get("reassemble_cmd"):
            parts = [p[1] for p in part_urls]
            print(f"  [dry-run] would concat (pure-Python) {parts} -> {spec['joined_name']}")
        if spec.get("joined_md5"):
            print(f"  [dry-run] would verify joined md5={spec['joined_md5']}")
        return dest

    dest.mkdir(parents=True, exist_ok=True)

    # Disk space check (need at least 2x size to allow joining)
    free_gb = shutil.disk_usage(dest).free / (1024**3)
    needed_gb = spec["size_gb"] * 2.2
    if free_gb < needed_gb:
        print(
            f"WARNING: only {free_gb:.1f} GB free, need ~{needed_gb:.1f} GB "
            f"(parts + joined image + headroom)."
        )

    # Fetch each part
    for url, part_name, algo, expected in part_urls:
        dst_part = dest / part_name
        if dst_part.exists() and expected:
            actual = _checksum(dst_part, algo)
            if actual.lower() == expected.lower():
                print(f"  [ok] {part_name} already present, checksum verified")
                continue
            print(f"  [!]  {part_name} checksum mismatch, re-downloading")
            dst_part.unlink()
        try:
            _download(url, dst_part)
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL {part_name}: {e}")
            print(f"  -> fetch manually from {spec['homepage']} and place under {dest}")
            raise

        if verify and expected:
            actual = _checksum(dst_part, algo)
            ok = actual.lower() == expected.lower()
            print(f"  [{'ok' if ok else 'XX'}] {part_name} {algo}={actual}")
            if not ok:
                raise SystemExit(
                    f"checksum mismatch on {part_name}: expected {expected}"
                )

    # Reassemble split parts with a pure-Python streaming concat (no shell).
    joined = dest / spec["joined_name"]
    part_paths = [dest / name for (_u, name, _a, _e) in part_urls]
    if spec.get("reassemble_cmd") and len(part_paths) > 1 and not joined.exists():
        print(f"\n  joining {len(part_paths)} parts -> {joined.name}")
        concat_parts(part_paths, joined)
        print(f"  [ok] joined size: {_human(joined.stat().st_size)}")

    # Verify joined image
    if joined.exists() and spec.get("joined_md5"):
        print("\n  verifying joined image MD5...")
        h = _checksum(joined, "md5")
        ok = h.lower() == spec["joined_md5"].lower()
        print(f"  [{'ok' if ok else 'XX'}] {spec['joined_name']} md5={h}")
        if not ok:
            print(f"    expected: {spec['joined_md5']}")
            raise SystemExit("joined image checksum mismatch")

    final = joined if joined.exists() else dest
    print(f"\nready: {final}")
    return final


def _check_urls(targets: list[str]) -> int:
    rc = 0
    for t in targets:
        t = _resolve_key(t)
        spec = DATASETS[t]
        print(f"\n=== {spec['title']} ===")
        for name, _algo, _exp in spec["parts"]:
            url = spec["download_base"].rstrip("/") + "/" + name
            ok, detail = check_url(url)
            print(f"  [{'ok' if ok else 'XX'}] {url}  ({detail})")
            if not ok:
                rc = 1
    return rc


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dataset",
                   choices=list(DATASETS.keys()) + list(_ALIAS.keys()) + ["all"],
                   metavar="DATASET",
                   help="dataset key or short alias "
                        f"({', '.join(sorted(_ALIAS))}, or 'all')")
    p.add_argument("dest", nargs="?", default=".", help="destination root directory")
    p.add_argument("--no-verify", action="store_true",
                   help="skip checksum verification (faster, less safe)")
    p.add_argument("--dry-run", action="store_true",
                   help="print the download plan without fetching any bytes")
    p.add_argument("--check-urls", action="store_true",
                   help="probe each part URL (with the configured browser "
                        "headers) and report reachability, then exit")
    args = p.parse_args()

    targets = list(DATASETS.keys()) if args.dataset == "all" else [args.dataset]

    if args.check_urls:
        sys.exit(_check_urls(targets))

    for t in targets:
        try:
            download(t, args.dest, verify=not args.no_verify, dry_run=args.dry_run)
        except Exception as e:  # noqa: BLE001
            print(f"\nfailed to fetch {t}: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
