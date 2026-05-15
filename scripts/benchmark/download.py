#!/usr/bin/env python3
"""
download.py — fetch a registered DFIR dataset to a local directory.

Usage:
    python3 -m benchmark.download cfreds   /path/to/datasets/
    python3 -m benchmark.download hadi1    /path/to/datasets/
    python3 -m benchmark.download m57      /path/to/datasets/

The script verifies checksums where available, joins split parts (CFReDS),
and prints the final image path on success.

This is run on the user's analysis host (where there's disk space), NOT
inside the Agentic-DART container. Container disk is too small for the
full ~16 GB combined dataset corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# Make this importable as a module (benchmark.download) or runnable directly
try:
    from .datasets import DATASETS
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from datasets import DATASETS


def _human(n: int) -> str:
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


def _download(url: str, dst: Path, *, resume: bool = True) -> None:
    """Streaming HTTP download with optional resume."""
    headers = {}
    mode = "wb"
    existing = 0
    if resume and dst.exists():
        existing = dst.stat().st_size
        if existing > 0:
            headers["Range"] = f"bytes={existing}-"
            mode = "ab"

    req = urllib.request.Request(url, headers=headers)
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


def download(short: str, dest_dir: str | Path, *, verify: bool = True) -> Path:
    """Download a dataset by short name. Return the path to the joined image."""
    if short not in DATASETS:
        raise ValueError(
            f"unknown dataset '{short}'. known: {list(DATASETS.keys())}"
        )
    spec = DATASETS[short]
    dest = Path(dest_dir) / short
    dest.mkdir(parents=True, exist_ok=True)
    print(f"\n=== {spec['title']} ===")
    print(f"target: {dest}")
    print(f"expected size: {spec['size_gb']:.1f} GB")

    # Disk space check (need at least 2x size to allow joining)
    free_gb = shutil.disk_usage(dest).free / (1024**3)
    needed_gb = spec["size_gb"] * 2.2
    if free_gb < needed_gb:
        print(
            f"WARNING: only {free_gb:.1f} GB free, need ~{needed_gb:.1f} GB "
            f"(parts + joined image + headroom)."
        )

    # Fetch each part
    for part_name, algo, expected in spec["parts"]:
        url = spec["download_base"].rstrip("/") + "/" + part_name
        dst_part = dest / part_name
        if dst_part.exists() and expected:
            actual = _checksum(dst_part, algo)
            if actual.lower() == expected.lower():
                print(f"  ✓ {part_name} already present, checksum verified")
                continue
            else:
                print(f"  ! {part_name} checksum mismatch, re-downloading")
                dst_part.unlink()
        try:
            _download(url, dst_part)
        except Exception as e:
            print(f"  FAIL {part_name}: {e}")
            print(
                f"  → fetch manually from {spec['homepage']} and place under {dest}"
            )
            raise

        if verify and expected:
            actual = _checksum(dst_part, algo)
            ok = actual.lower() == expected.lower()
            print(f"  {'✓' if ok else '✗'} {part_name} {algo}={actual}")
            if not ok:
                raise SystemExit(
                    f"checksum mismatch on {part_name}: expected {expected}"
                )

    # Reassemble if split
    joined = dest / spec["joined_name"]
    if spec["reassemble_cmd"] and not joined.exists():
        print(f"\n  joining parts → {joined.name}")
        subprocess.run(
            spec["reassemble_cmd"], shell=True, cwd=dest, check=True
        )
        print(f"  ✓ joined size: {_human(joined.stat().st_size)}")

    # Verify joined image
    if joined.exists() and spec.get("joined_md5"):
        print(f"\n  verifying joined image MD5...")
        h = _checksum(joined, "md5")
        ok = h.lower() == spec["joined_md5"].lower()
        print(f"  {'✓' if ok else '✗'} {spec['joined_name']} md5={h}")
        if not ok:
            print(f"    expected: {spec['joined_md5']}")
            raise SystemExit("joined image checksum mismatch")

    final = joined if joined.exists() else dest
    print(f"\nready: {final}")
    return final


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", choices=list(DATASETS.keys()) + ["all"])
    p.add_argument("dest", help="destination root directory")
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="skip checksum verification (faster, less safe)",
    )
    args = p.parse_args()

    targets = list(DATASETS.keys()) if args.dataset == "all" else [args.dataset]
    for t in targets:
        try:
            download(t, args.dest, verify=not args.no_verify)
        except Exception as e:
            print(f"\nfailed to fetch {t}: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
