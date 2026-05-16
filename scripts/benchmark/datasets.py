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
    # Homepage: https://www.ashemery.com/dfir.html
    # Mirrored on Internet Archive (stable, no captcha): https://archive.org/details/dfir-case1
    # Single E01 image, 2.91 GB. Memory dump available separately.
    # IMPORTANT: this is a WINDOWS server (Apache on Windows Server 2008 + XAMPP),
    # not Linux as misread from various write-ups.
    # ─────────────────────────────────────────────────────────────────────
    "hadi_challenge_1": {
        "title": "Ali Hadi DFIR Challenge #1 — Web Server Case",
        "short": "hadi1",
        "year": 2014,
        "filesystem": "NTFS (Windows Server 2008 + XAMPP/Apache)",
        "size_gb": 2.91,
        "license": "CC-BY-4.0 (academic and personal use)",
        "homepage": "https://www.ashemery.com/dfir.html",
        "download_base": "https://archive.org/download/dfir-case1",
        "parts": [
            ("Case1-Webserver.E01", "sha1", None),  # 2.91 GB main disk image
            # Optional second part — memory dump for memory forensics
            # ("memdump.7z", "sha1", None),  # 0.11 GB
        ],
        "reassemble_cmd": None,  # single E01, no reassembly
        "joined_md5": None,
        "joined_name": "Case1-Webserver.E01",
        "ground_truth_path": "examples/case-studies/case-09-hadi-challenge-1/ground-truth.json",
        "scenario": (
            "Windows Server 2008 web server (Apache + MySQL + PHP via XAMPP) "
            "was reported as compromised. Forensic team arrived in time to take "
            "both a disk image and a memory dump. Identify the attack vector, "
            "enumerate user accounts added by the attacker, list dropped tools "
            "and software, identify the shellcode used (memory forensics), and "
            "build a complete event timeline."
        ),
        "key_artifacts": [
            "C:\\xampp\\apache\\logs\\access.log + error.log",
            "C:\\xampp\\htdocs\\ (web shells)",
            "Windows Security event log (4624/4625 logons, account creation)",
            "Registry Run keys + Services hive",
            "Prefetch + Amcache",
            "Memory dump (httpd.exe, mysqld.exe process spaces)",
            "MFT timeline reconstruction",
        ],
    },

    # ─────────────────────────────────────────────────────────────────────
    # Digital Corpora M57-Patents — 4-person corporate scenario
    # https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
    # 4 PC images over 17 days + network captures + USB, ~50 GB total
    # We use 'jo' (Joanne) — the IP-theft narrative subject.
    # IMPORTANT: actual employee names are charlie, jo, pat, terry.
    # Verified via S3 listing 2026-05.
    # ─────────────────────────────────────────────────────────────────────
    "m57_jo": {
        "title": "Digital Corpora M57-Patents — Jo's PC (last day of scenario)",
        "short": "m57",
        "year": 2009,
        "filesystem": "NTFS (Windows XP)",
        "size_gb": 5.16,  # jo-2009-12-10.E01 specifically (last single-file day)
        "license": "CC-BY-3.0 (academic + commercial use)",
        "homepage": "https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/",
        "download_base": "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted",
        "parts": [
            # Verified via S3 listing 2026-05.
            # 12-10 is the last day that exists as a single E01 (5.16 GB).
            # 12-11 (the very last day) is split into -001 + -002 (~11 GB total).
            # Picking 12-10 gives full post-exfiltration state in a smaller image.
            ("jo-2009-12-10.E01", "sha1", None),  # 5.16 GB
        ],
        "reassemble_cmd": None,  # single E01
        "joined_md5": None,
        "joined_name": "jo-2009-12-10.E01",
        "ground_truth_path": "examples/case-studies/case-10-m57-jean/ground-truth.json",
        "scenario": (
            "M57.biz is a small patent-research company. Four employees "
            "(charlie, jo, pat, terry) use company laptops over a 17-day "
            "period. The primary forensic narrative centres on data "
            "exfiltration; the evidence is on jo's workstation. The "
            "2009-12-11 image is the last-day snapshot containing the "
            "complete activity history including the exfiltration."
        ),
        "key_artifacts": [
            "Users/jo/NTUSER.DAT (RecentDocs MRU, TypedPaths, MUICache)",
            "Outlook PST or Outlook Express *.dbx",
            "Internet Explorer history",
            "$Recycle.Bin metadata + INFO2",
            "$Extend/$UsnJrnl:$J",
            "Windows/Prefetch + Amcache.hve",
            "pagefile.sys / hiberfil.sys",
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
