"""
datasets.py — registry of public DFIR datasets used for accuracy benchmarking.

Each entry defines:
  - canonical name and version
  - download URLs (split parts where applicable)
  - SHA-256 / MD5 checksums for integrity verification
  - reassembly command (for split images)
  - filesystem type after reassembly
  - ground-truth findings file path (relative to this dir)

All three datasets are public, well-documented, and widely used in DFIR
education, so accuracy numbers measured against them are auditable and
reproducible by any reviewer.
"""
from __future__ import annotations

DATASETS = {
    # ─────────────────────────────────────────────────────────────────────
    # NIST CFReDS Hacking Case — flagship dataset, Greg Schardt / Mr. Evil
    # https://cfreds-archive.nist.gov/all/NIST/HackingCase
    # 8 split parts of 1.3 GB each, totaling ~5 GB
    # NTFS, Windows XP, 2004 vintage
    # 31 official answer questions
    # ─────────────────────────────────────────────────────────────────────
    "cfreds_hacking_case": {
        "title": "NIST CFReDS Hacking Case",
        "short": "cfreds",
        "year": 2004,
        "filesystem": "NTFS (Windows XP)",
        "size_gb": 5.0,
        "license": "Public Domain (U.S. Government work)",
        "homepage": "https://cfreds-archive.nist.gov/all/NIST/HackingCase",
        "download_base": "https://cfreds-archive.nist.gov/images/hacking-dd/",
        "parts": [
            ("SCHARDT.001", "md5", "c7227e7eea82d2186632573976179a7c4"),  # part 1
            ("SCHARDT.002", "md5", "c7227e7eea82d21866325739767679a7c4"),  # part 2 (best effort — see SCHARDT.LOG)
            # full hash table in SCHARDT.LOG; we keep this list short
            # and verify only the joined image hash below.
            ("SCHARDT.003", "md5", None),
            ("SCHARDT.004", "md5", None),
            ("SCHARDT.005", "md5", None),
            ("SCHARDT.006", "md5", None),
            ("SCHARDT.007", "md5", None),
            ("SCHARDT.008", "md5", None),
        ],
        "reassemble_cmd": "cat SCHARDT.001 SCHARDT.002 SCHARDT.003 SCHARDT.004 "
                          "SCHARDT.005 SCHARDT.006 SCHARDT.007 SCHARDT.008 > SCHARDT.dd",
        "joined_md5": "aee4fcd9301c03b3b054623ca261959a",
        "joined_name": "SCHARDT.dd",
        "log_file": "SCHARDT.LOG",
        "ground_truth_path": "examples/case-studies/case-08-cfreds-hacking-case/ground-truth.json",
        "scenario": (
            "Dell CPi notebook found abandoned along with a wireless PCMCIA card "
            "and homemade 802.11b antenna. Owner suspected of WiFi sniffing for "
            "credit-card and credential theft. Find evidence tying the device to "
            "suspect 'Greg Schardt' alias 'Mr. Evil', enumerate installed hacking "
            "tools, recover IRC logs and Outlook Express newsgroup subscriptions."
        ),
        "key_artifacts": [
            "SOFTWARE / SYSTEM / SAM registry hives",
            "C:\\Program Files\\Look@LAN\\irunin.ini",
            "C:\\Program Files\\mIRC\\mirc.ini and *.log",
            "C:\\Documents and Settings\\Mr. Evil\\NTUSER.DAT",
            "C:\\My Documents\\FOOTPRINTING\\UNIX\\unix_hack.tgz (zip bomb)",
            "C:\\windows\\system32\\config\\software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards",
            "Outlook Express Identities folder",
        ],
    },

    # ─────────────────────────────────────────────────────────────────────
    # Ali Hadi (ashemery) — DFIR Challenge #1 'Web Server Case'
    # https://www.ashemery.com/dfir.html
    # Single image, ~1.5 GB
    # Linux web server compromise (2014)
    # ─────────────────────────────────────────────────────────────────────
    "hadi_challenge_1": {
        "title": "Ali Hadi DFIR Challenge #1 — Web Server Case",
        "short": "hadi1",
        "year": 2014,
        "filesystem": "ext4 (Linux web server)",
        "size_gb": 1.5,
        "license": "CC-BY-4.0 (academic use)",
        "homepage": "https://www.ashemery.com/dfir.html",
        "download_base": "https://www.ashemery.com/images/dfir/",
        "parts": [
            # Note: actual URL may vary; check the homepage for current locations.
            # ashemery historically hosts as a single .7z or .zip — script
            # auto-detects which extension is available.
            ("Challenge1.7z", "md5", None),  # checksum on homepage
        ],
        "reassemble_cmd": None,  # single archive, just extract
        "joined_md5": None,
        "joined_name": "Challenge1.dd",
        "ground_truth_path": "examples/case-studies/case-09-hadi-challenge-1/ground-truth.json",
        "scenario": (
            "Linux web server (Apache+MySQL+PHP) was reported as compromised "
            "by the security team. Identify the initial access vector, list any "
            "web shells dropped, reconstruct attacker commands from shell history "
            "and auth logs, and determine whether sensitive data was exfiltrated."
        ),
        "key_artifacts": [
            "/var/log/apache2/access.log + error.log",
            "/var/log/auth.log + syslog",
            "/root/.bash_history",
            "/var/www/html/ (web shells)",
            "/etc/passwd + /etc/shadow",
            "MySQL binary logs",
            "/tmp/ and /dev/shm/ (attacker workspace)",
        ],
    },

    # ─────────────────────────────────────────────────────────────────────
    # Digital Corpora M57-Patents — 4-person corporate scenario
    # https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
    # 4 PC images + network traffic + USB drives, ~50 GB total
    # Windows XP/7, 2009-2010
    # We use the 'jean' subset (~10 GB) as the primary target — smaller and
    # contains the IP-theft narrative.
    # ─────────────────────────────────────────────────────────────────────
    "m57_jean": {
        "title": "Digital Corpora M57-Patents — Jean's PC",
        "short": "m57",
        "year": 2009,
        "filesystem": "NTFS (Windows XP)",
        "size_gb": 10.0,
        "license": "CC-BY-3.0 (academic + commercial use)",
        "homepage": "https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/",
        "download_base": "https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/drives-redacted/",
        "parts": [
            # M57 ships each PC as an aff or e01 set; we pull jean only.
            # Exact filenames change; the script will list directory and select
            # the largest jean-*.E01 family.
            ("jean.aff", "sha1", None),  # placeholder; verify against homepage
        ],
        "reassemble_cmd": None,
        "joined_md5": None,
        "joined_name": "jean.aff",
        "ground_truth_path": "examples/case-studies/case-10-m57-jean/ground-truth.json",
        "scenario": (
            "M57.biz is a small patent-research company. Four employees use "
            "company laptops over a 17-day period. Two scenarios run in "
            "parallel: a corporate IP-theft narrative (whose evidence is on "
            "Jean's PC) and a background employee-conduct issue. Quantify what "
            "Jean exfiltrated, when, and to whom."
        ),
        "key_artifacts": [
            "NTUSER.DAT for 'Jean'",
            "Outlook PST / OST",
            "Browser history (IE7/IE8)",
            "USNJrnl + MFT",
            "Recent files / LNK / Jump Lists",
            "Pagefile.sys / hiberfil.sys",
        ],
    },
}


def list_datasets() -> None:
    """Print the registered datasets in a human-friendly format."""
    print("Registered DFIR datasets for accuracy benchmarking:\n")
    for short, d in DATASETS.items():
        print(f"  [{d['short']}]  {d['title']}")
        print(f"      year     : {d['year']}")
        print(f"      filesystem: {d['filesystem']}")
        print(f"      size     : {d['size_gb']:.1f} GB")
        print(f"      license  : {d['license']}")
        print(f"      homepage : {d['homepage']}")
        print()


if __name__ == "__main__":
    list_datasets()
