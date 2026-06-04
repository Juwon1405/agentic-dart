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

import random
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
    # The realistic tree is hand-curated with production-volume evidence on
    # most surfaces (security-events ~11k lines, supply-chain, RDP brute, USB
    # setupapi, memory triage, etc.). Only two logs ship IOC-only: the web
    # access log and the unix auth log. This script enriches ONLY those two
    # in-place with deterministic benign noise (seed 20260508) so that
    # needle-in-haystack detection is exercised at realistic signal-to-noise.
    #
    # IMPORTANT: every other evidence file is left byte-for-byte untouched.
    # We deliberately do NOT rmtree / copytree the reference set over the
    # realistic tree — that would destroy hand-curated evidence that exists
    # only in the realistic variant (e.g. supply-chain events with no
    # reference counterpart). Enrichment is purely additive.
    if not DST.exists():
        raise SystemExit(
            f"realistic tree not found at {DST}; it is version-controlled, "
            f"hand-curated evidence and is not generated from scratch."
        )

    summary = []

    # Web access log: reference IOC requests + benign traffic (~1:37)
    ioc, benign = mix_access_log(
        SRC / "web/logs/access.log",
        DST / "web/logs/access.log",
        benign_count=1000,
    )
    summary.append(("web/logs/access.log", ioc, benign))

    # Unix auth.log: reference IOC auth events + benign logins (~1:29)
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
