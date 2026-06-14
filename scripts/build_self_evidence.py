#!/usr/bin/env python3
"""
build_self_evidence.py — give each self-evaluation case its OWN evidence_root.

Until now every self case except case-01 pointed (via an evidence_root symlink)
at one shared sample-evidence tree that actually contained the artifacts for
ALL eight scenarios at once. That made the cases impossible to score honestly:
an agent let loose on case-02 also saw case-07's ransomware, case-08's
supply-chain compromise, etc., and reasonably reported whichever was loudest —
not the one case-02's truth.json scores.

This script builds a SELF-CONTAINED evidence_root under each case directory
that contains only:
  - the artifacts that case's truth.json + README actually reference, and
  - the benign/noise rows that already live inside those same files (the
    sample CSV/JSON/log files are pre-mixed: normal smss.exe + malicious
    powershell -enc, normal GETs + sqlmap, etc.), so each case still presents
    a realistic 'find the needle' tree without importing any OTHER case's
    attack.

It is idempotent: it wipes and rebuilds each case's evidence_root from the
canonical source tree. After this runs, the shared sample-evidence tree and
the cross-case symlinks are no longer needed.

Source of truth for files is the existing case-01 evidence_root (the most
complete copy). Each case's file list below was derived from that case's
truth.json evidence_path + README 'How to invoke' block + the auto-scan paths
the relevant dart_mcp tools walk (e.g. detect_persistence reads
SYSTEM.services.csv + *.runkeys.csv + Tasks/).
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SELF = REPO / "examples" / "case-studies" / "self-evaluation"
# Canonical source: case-01's evidence_root has every file any case needs.
SRC = SELF / "case-01" / "evidence_root"

# Per-case file manifest. Paths are relative to an evidence_root.
# Each list = that scenario's artifacts + the auto-scan companions tools need.
# Benign noise rides along inside these same pre-mixed files.
MANIFEST: dict[str, list[str]] = {
    # IP-KVM remote-hands insider: USB insertion ordering + scheduled task
    "case-01": [
        "disk/Windows/INF/setupapi.dev.log",
        "disk/Windows/AppCompat/Programs/Amcache.hve",
        "disk/Windows/System32/Tasks/RemoteHandsSync",
        "disk/Windows/System32/config/SYSTEM",
        "disk/Windows/System32/config/SYSTEM.shimcache.csv",
        "disk/Windows/System32/config/NTUSER.DAT.runkeys.csv",
        "disk/Windows/System32/config/SYSTEM.services.csv",
        "event-logs/unified_events.jsonl",
        "sigma-rules/ip_kvm_usb_insertion.yml",
    ],
    # LOTL via signed Windows binaries: process tree + events + persistence
    "case-02": [
        "disk/processes.csv",
        "disk/events.json",
        "disk/Windows/System32/Tasks/RemoteHandsSync",
        "disk/Windows/System32/config/NTUSER.DAT.runkeys.csv",
        "disk/Windows/System32/config/SYSTEM.services.csv",
        "sigma-rules/suspicious_scheduled_task.yml",
    ],
    # macOS insider: unsigned remote-admin app + staged exfil
    "case-03": [
        "mac/Users/analyst/Library/Application Support/Knowledge/knowledgeC.db",
        "mac/Users/analyst/Library/Application Support/Knowledge/knowledgeC.csv",
        "mac/fsevents.csv",
        "mac/private/var/db/diagnostics/unifiedlog.ndjson",
        "mac/var/log/auth.log",
        "macos/com.evil.persistence.plist",
    ],
    # Classic data-theft chain: browser download -> execution -> exfil
    "case-04": [
        "disk/Users/analyst/AppData/Local/Google/Chrome/User Data/Default/History",
        "disk/Users/analyst/AppData/Local/Google/Chrome/User Data/Default/History.csv",
        "disk/Users/analyst/AppData/Local/Google/Chrome/User Data/Default/History.downloads.csv",
        "disk/Users/analyst/Downloads/quarterly-report.pdf.exe",
        "disk/Users/analyst/Downloads/quarterly-report.pdf.exe.Zone.Identifier",
        "disk/Users/analyst/Downloads/helper.zip",
        "disk/Users/analyst/Downloads/helper.zip.Zone.Identifier",
        "disk/Users/analyst/NTUSER.DAT",
        "disk/Users/analyst/NTUSER.DAT.shellbags.csv",
        "disk/Windows/AppCompat/Programs/Amcache.hve",
    ],
    # WHO investigation: stolen cred + AD attack chain (Win + Linux)
    "case-05": [
        "disk/processes.csv",
        "disk/security-events.json",
        "linux/auth.log",
    ],
    # Initial access: web shell + RDP brute force
    "case-06": [
        "disk/rdp-brute-events.json",
        "disk/security-events.json",
        "web/logs/access.log",
        "web/var/www/html/index.php",
        "web/var/www/html/includes/config.php",
        "web/var/www/html/includes/db.php",
        "web/var/www/html/uploads/about.php",
        "web/var/www/html/uploads/cmd.php",
        "web/var/www/html/uploads/shell.php",
        "web/var/www/html/uploads/x.php",
        "web/var/www/html/uploads/page-1.php",
        "web/var/www/html/uploads/page-2.php",
        "web/var/www/html/uploads/page-3.php",
        "web/var/www/html/uploads/page-4.php",
        "web/var/www/html/uploads/page-5.php",
    ],
    # Post-foothold ransomware deployment
    "case-07": [
        "disk/creds-processes.csv",
        "disk/discovery-processes.csv",
        "disk/ransomware-processes.csv",
        "disk/log-clearing-events.json",
    ],
    # Domain-admin takeover: supply-chain + ESC8 + DCSync + Golden Ticket
    "case-08": [
        "disk/supplychain-processes.csv",
        "disk/supplychain-network.json",
        "disk/supplychain-security-events.json",
    ],
}


def build(case: str, files: list[str], *, dry_run: bool) -> tuple[int, list[str]]:
    dst_root = SELF / case / "evidence_root"
    missing = []
    # Resolve each source file
    resolved = []
    for rel in files:
        src = SRC / rel
        if not src.exists():
            missing.append(rel)
            continue
        resolved.append(rel)

    if dry_run:
        return len(resolved), missing

    # Wipe any existing evidence_root (symlink OR real dir) and rebuild
    if dst_root.is_symlink() or dst_root.exists():
        if dst_root.is_symlink():
            dst_root.unlink()
        else:
            shutil.rmtree(dst_root)
    dst_root.mkdir(parents=True)

    for rel in resolved:
        src = SRC / rel
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    return len(resolved), missing


def main() -> int:
    global SRC
    dry = "--dry-run" in sys.argv
    print(f"{'DRY-RUN: ' if dry else ''}building per-case evidence_root from {SRC}\n")

    # Snapshot the canonical source FIRST. case-01 is both the source and a
    # build target, so building case-01 would otherwise wipe the source out
    # from under the remaining cases. Copy the whole source tree to a temp dir
    # and resolve every file from there.
    snapshot_dir = None
    if not dry:
        import tempfile
        snapshot_dir = Path(tempfile.mkdtemp(prefix="dart-evsrc."))
        shutil.copytree(SRC, snapshot_dir / "src")
        SRC = snapshot_dir / "src"

    total_missing = []
    try:
        for case, files in MANIFEST.items():
            n, missing = build(case, files, dry_run=dry)
            status = "OK" if not missing else f"{len(missing)} MISSING"
            print(f"  {case}: {n} files [{status}]")
            for m in missing:
                print(f"      missing from source: {m}")
                total_missing.append((case, m))
    finally:
        if snapshot_dir is not None:
            shutil.rmtree(snapshot_dir, ignore_errors=True)

    print()
    if total_missing:
        print(f"WARNING: {len(total_missing)} files missing from the source tree.")
        return 1
    print("All cases built." if not dry else "Dry-run complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
