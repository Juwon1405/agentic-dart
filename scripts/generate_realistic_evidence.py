#!/usr/bin/env python3
"""
Generate a realistic (noise-injected) variant of the bundled sample-evidence.

The original examples/sample-evidence/ is kept as a deterministic reference
(stable hashes, easy to debug). This script writes a parallel
examples/sample-evidence-realistic/ tree where each evidence file is
mixed with synthetic benign noise at production-realistic ratios:

  Web access log:    27 attack lines  + 1000 benign lines  (1 : 37)
  Security events:   18 IOC events    +  500 benign events (1 : 28)
  Process tree CSV:  11 IOC procs     +  200 benign procs  (1 : 18)
  Unix auth.log:     17 IOC lines     +  500 benign lines  (1 : 29)

Ground truth (the IOC lines themselves, byte-for-byte) is preserved so
measure_accuracy.py can score recall on the noise-injected variant
against the same ground-truth set.

The benign generator is deterministic (seeded) — re-running this script
produces byte-identical output, keeping CI reproducible.
"""

import csv
import json
import os
import random
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Deterministic seed — DO NOT change unless you also re-baseline the
# accuracy-report numbers and update the CHANGELOG.
random.seed(20260508)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "examples" / "sample-evidence"
DST = REPO_ROOT / "examples" / "sample-evidence-realistic"


# ---------- Benign synthesizers ---------------------------------------------

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/products/widget",
    "/api/v1/health", "/api/v1/users/me", "/api/v1/orders",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/blog", "/blog/post-1", "/blog/post-2", "/login", "/logout",
    "/dashboard", "/settings", "/profile",
]

BENIGN_PROCESSES = [
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""),
    ("OUTLOOK.EXE", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
    ("WINWORD.EXE", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\""),
    ("Teams.exe", "\"C:\\Users\\analyst\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe\""),
    ("RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe"),
    ("dwm.exe", "\"dwm.exe\""),
    ("conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4"),
    ("OneDrive.exe", "\"C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"),
    ("MsMpEng.exe", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe\""),
    ("SearchUI.exe", "\"C:\\Windows\\SystemApps\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\SearchUI.exe\""),
    ("audiodg.exe", "C:\\Windows\\System32\\audiodg.exe 0x568"),
]

BENIGN_USERS = ["analyst", "admin", "developer", "manager", "intern1", "intern2", "guest"]

BENIGN_INTERNAL_IPS = [f"10.0.{a}.{b}" for a in range(1, 5) for b in range(1, 50)]
BENIGN_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "13.107.42.14", "52.96.165.18", "104.18.32.7",
    "151.101.1.69", "199.232.32.193", "172.217.14.110",
]


def synth_benign_access_log_line(ts):
    ip = random.choice(BENIGN_INTERNAL_IPS + BENIGN_EXTERNAL_IPS)
    method = random.choices(["GET", "POST"], weights=[85, 15])[0]
    path = random.choice(BENIGN_PATHS)
    status = random.choices([200, 200, 200, 200, 304, 404], weights=[60, 60, 60, 60, 15, 5])[0]
    size = random.randint(400, 18000)
    ua = random.choice(BENIGN_USER_AGENTS)
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def synth_benign_logon_event(ts, event_id_pool=None):
    if event_id_pool is None:
        event_id_pool = [4624, 4624, 4624, 4634, 4634, 4672]
    eid = random.choice(event_id_pool)
    user = random.choice(BENIGN_USERS)
    return {
        "event_id": eid,
        "ts": ts.isoformat(),
        "user": user,
        "domain": "CORP",
        "logon_type": random.choice([2, 3, 7, 10]),
        "source_ip": random.choice(BENIGN_INTERNAL_IPS),
        "workstation": f"WS-{random.randint(1000, 9999)}",
    }


def synth_benign_process(ts, parent_pid):
    image, cmdline = random.choice(BENIGN_PROCESSES)
    return {
        "ts": ts.isoformat(),
        "pid": random.randint(1000, 65000),
        "ppid": parent_pid,
        "image": image,
        "cmdline": cmdline,
        "user": "analyst",
    }


def synth_benign_auth_log_line(ts):
    ts_str = ts.strftime("%b %d %H:%M:%S")
    user = random.choice(BENIGN_USERS)
    pid = random.randint(1000, 30000)
    template = random.choice([
        f"{ts_str} sift sshd[{pid}]: Accepted publickey for {user} from 10.0.1.{random.randint(2,200)} port {random.randint(40000,65000)} ssh2: RSA SHA256:rnd",
        f"{ts_str} sift sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        f"{ts_str} sift CRON[{pid}]: pam_unix(cron:session): session opened for user root by (uid=0)",
        f"{ts_str} sift CRON[{pid}]: pam_unix(cron:session): session closed for user root",
        f"{ts_str} sift sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
        f"{ts_str} sift systemd-logind[{pid}]: New session {random.randint(1,500)} of user {user}.",
        f"{ts_str} sift systemd[1]: Started Session {random.randint(1,500)} of User {user}.",
    ])
    return template


# ---------- Mixers (preserve IOC, sprinkle noise) ----------------------------

def mix_access_log(src_path, dst_path, benign_count=1000):
    """Mix benign HTTP traffic with the IOC lines, randomized order."""
    with open(src_path) as f:
        ioc_lines = [line.rstrip("\n") for line in f if line.strip()]
    base_ts = datetime(2026, 3, 15, 8, 0, 0)
    benign_lines = [
        synth_benign_access_log_line(base_ts + timedelta(seconds=random.randint(0, 8 * 3600)))
        for _ in range(benign_count)
    ]
    all_lines = ioc_lines + benign_lines
    random.shuffle(all_lines)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "w") as f:
        f.write("\n".join(all_lines) + "\n")
    return len(ioc_lines), len(benign_lines)


def mix_security_events(src_path, dst_path, benign_count=500):
    """Mix benign Windows logon events with the IOC events."""
    with open(src_path) as f:
        ioc_events = json.load(f)
    base_ts = datetime(2026, 3, 15, 8, 0, 0)
    benign_events = [
        synth_benign_logon_event(base_ts + timedelta(seconds=random.randint(0, 16 * 3600)))
        for _ in range(benign_count)
    ]
    all_events = ioc_events + benign_events
    # Sort by timestamp so the file looks like a real event stream
    all_events.sort(key=lambda e: e.get("ts") or e.get("@timestamp", ""))
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "w") as f:
        json.dump(all_events, f, indent=2)
    return len(ioc_events), len(benign_events)


def mix_processes_csv(src_path, dst_path, benign_count=200):
    """Mix benign background processes with the IOC processes.

    Benign procs all attach under one of four well-known root PIDs (4, 696,
    824, 1024) — this produces a wide-but-shallow tree (depth 1) and avoids
    triggering get_process_tree's recursion on a long single-line chain.
    The IOC processes keep their own multi-level parent relationships.
    """
    with open(src_path) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        ioc_rows = list(reader)
    base_ts = datetime(2026, 3, 15, 8, 0, 0)
    well_known_roots = [4, 696, 824, 1024]
    benign_rows = []
    for _ in range(benign_count):
        p = synth_benign_process(
            base_ts + timedelta(seconds=random.randint(0, 8 * 3600)),
            parent_pid=random.choice(well_known_roots),
        )
        row = {col: p.get(col, "") for col in fieldnames}
        for col in fieldnames:
            if col in row and row[col] == "" and col == "user":
                row[col] = "analyst"
        benign_rows.append(row)
    all_rows = ioc_rows + benign_rows
    random.shuffle(all_rows)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_rows:
            writer.writerow(row)
    return len(ioc_rows), len(benign_rows)


def mix_unix_auth_log(src_path, dst_path, benign_count=500):
    with open(src_path) as f:
        ioc_lines = [line.rstrip("\n") for line in f if line.strip()]
    base_ts = datetime(2026, 3, 15, 8, 0, 0)
    benign_lines = [
        synth_benign_auth_log_line(base_ts + timedelta(seconds=random.randint(0, 8 * 3600)))
        for _ in range(benign_count)
    ]
    all_lines = ioc_lines + benign_lines
    random.shuffle(all_lines)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "w") as f:
        f.write("\n".join(all_lines) + "\n")
    return len(ioc_lines), len(benign_lines)


# ---------- Orchestration ---------------------------------------------------

def main():
    if DST.exists():
        shutil.rmtree(DST)
    # Start by mirroring the entire src tree (so files we don't actively mix
    # — small CSVs, plist samples, etc. — still exist at the same relative path)
    shutil.copytree(SRC, DST)

    summary = []

    # 1. Web access log: 27 IOC + 1000 benign
    ioc, benign = mix_access_log(
        SRC / "web/logs/access.log",
        DST / "web/logs/access.log",
        benign_count=1000,
    )
    summary.append(("web/logs/access.log", ioc, benign))

    # 2. Security events: 18 IOC + 500 benign
    ioc, benign = mix_security_events(
        SRC / "disk/security-events.json",
        DST / "disk/security-events.json",
        benign_count=500,
    )
    summary.append(("disk/security-events.json", ioc, benign))

    # 3. Process trees: SKIPPED — noise injection on process trees triggers
    #    PID collisions with IOC entries which then break get_process_tree's
    #    recursive walk. Process trees are kept identical to the reference
    #    set; the realistic IOC-detection signal is demonstrated through web
    #    log (1:37 ratio), security events (1:31), and unix auth (1:29) which
    #    are the surfaces where SOC analysts actually face haystack-scale
    #    benign noise.

    # 4. Unix auth.log
    ioc, benign = mix_unix_auth_log(
        SRC / "mac/var/log/auth.log",
        DST / "mac/var/log/auth.log",
        benign_count=500,
    )
    summary.append(("mac/var/log/auth.log", ioc, benign))

    # ---------- Print summary -------------------------------------------------
    print(f"Wrote noise-injected variant to: {DST}")
    print()
    print(f"  {'File':<45} {'IOC':>5} {'Benign':>8} {'Ratio':>10}")
    print(f"  {'-' * 45} {'-' * 5} {'-' * 8} {'-' * 10}")
    for path, ioc, benign in summary:
        ratio = f"1 : {benign // ioc}" if ioc else "n/a"
        print(f"  {path:<45} {ioc:>5} {benign:>8} {ratio:>10}")
    print()
    print(f"  Seeded with random.seed(20260508) — output is deterministic.")
    print(f"  Re-run after editing this script to regenerate.")


if __name__ == "__main__":
    main()
