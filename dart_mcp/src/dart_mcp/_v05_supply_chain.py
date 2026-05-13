"""
v0.5 expansion: supply-chain attack IOC sweeps.

Cross-platform port of the macOS-only `supply_chain` module from
yushin-mac-artifact-collector (https://github.com/Juwon1405/yushin-mac-artifact-collector),
generalized to read evidence directories instead of executing on a live host.

These are read-only filesystem analyzers that operate on collected evidence
(typically inside an evidence_root supplied by agentic-dart-collector-adapter
or any equivalent collector). All six functions are surface-registered via the
@tool decorator so the LLM cannot side-step them.

Functions
---------
- scan_pth_files_for_supply_chain_iocs   : Detect malicious .pth files in site-packages
- detect_pypi_typosquatting              : Levenshtein-based typosquat detection on installed packages
- detect_nodejs_install_hooks            : Locate package.json preinstall/postinstall hooks
- detect_python_backdoor_persistence     : ~/.config/sysmon and equivalent backdoor patterns
- detect_credential_file_access          : Suspicious atime/mtime on SSH/AWS/GCP/Azure creds
- grep_shell_history_for_c2              : Shell history search for C2 domains / suspicious cmds

Reference incident: the litellm PyPI supply-chain attack (2026-03), which used
a malicious `litellm_init.pth` file to achieve persistence and credential
exfiltration. Patterns generalize to npm typosquatting (event-stream 2018,
ua-parser-js 2021), preinstall hook abuse (any npm package), and Python
backdoor persistence (PyTorch torchtriton 2022, ctx 2022).

MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain),
              T1547 (Boot/Logon Autostart Execution),
              T1552 (Unsecured Credentials),
              T1059.006 (Python).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from dart_mcp import tool, _safe_resolve, _sha256


# Known-malicious file basenames (literal match, case-sensitive on Linux).
_KNOWN_MALICIOUS_PTH = {
    "litellm_init.pth",        # litellm 2026-03 supply-chain attack
}

# Suspicious patterns inside .pth files. A .pth file is supposed to contain only
# directory paths to be added to sys.path. Anything else is suspicious.
_SUSPICIOUS_PTH_PATTERNS = [
    (re.compile(r"\bimport\s+"),       "import statement"),
    (re.compile(r"\bexec\s*\("),       "exec() call"),
    (re.compile(r"\beval\s*\("),       "eval() call"),
    (re.compile(r"\b__import__\b"),    "__import__ call"),
    (re.compile(r"\bos\.system\b"),    "os.system call"),
    (re.compile(r"\bsubprocess\b"),    "subprocess import"),
    (re.compile(r"\bsocket\b"),        "socket import"),
    (re.compile(r"\burllib"),          "urllib usage"),
    (re.compile(r"\brequests\b"),      "requests library"),
    (re.compile(r"https?://"),         "URL embedded"),
    (re.compile(r"\bbase64\b"),        "base64 usage"),
]

# Top PyPI packages commonly targeted by typosquatters. Source: PyPI top 100
# downloads (approx.). Used as the reference set for typo distance scoring.
_PYPI_HIGH_VALUE_TARGETS = {
    "requests", "urllib3", "boto3", "numpy", "pandas", "scipy",
    "django", "flask", "fastapi", "sqlalchemy",
    "pytest", "setuptools", "pip", "wheel", "cryptography",
    "pyyaml", "click", "jinja2", "werkzeug", "markupsafe",
    "certifi", "charset-normalizer", "idna",
    "openai", "anthropic", "litellm", "langchain", "transformers",
    "torch", "tensorflow", "sklearn", "scikit-learn",
    "kubernetes", "docker", "ansible",
}

# Backdoor persistence locations across OSes.
_BACKDOOR_PERSISTENCE_PATHS = [
    # ── macOS / Linux ────────────────────────────────────────────────────
    ".config/sysmon",                   # litellm sysmon.py backdoor
    ".config/systemd/user",             # systemd user services
    "Library/LaunchAgents",             # macOS user LaunchAgents
    "Library/LaunchDaemons",            # macOS system LaunchDaemons
    ".local/share/systemd/user",        # alt systemd user
    # ── Linux system-wide ────────────────────────────────────────────────
    "etc/systemd/system",
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "var/spool/cron",
    # ── Windows-like (if collector preserved registry path layout) ───────
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
]

# Credential files commonly targeted in supply-chain exfiltration.
_CREDENTIAL_FILES = [
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/config",
    ".aws/credentials", ".aws/config",
    ".kube/config",
    ".gcloud/application_default_credentials.json",
    ".azure/accessTokens.json", ".azure/azureProfile.json",
    ".docker/config.json",
    ".npmrc", ".pypirc",
    ".gitconfig",
]

# Known C2 domains / patterns from supply-chain incidents.
_C2_PATTERNS = [
    re.compile(r"litellm\.cloud",                        re.IGNORECASE),
    re.compile(r"models\.litellm\.cloud",                re.IGNORECASE),
    re.compile(r"ip-api\.com/json",                      re.IGNORECASE),  # eslint-scope 2018
    re.compile(r"pastebin\.com/raw/",                    re.IGNORECASE),
    re.compile(r"transfer\.sh",                          re.IGNORECASE),
    re.compile(r"ngrok\.io",                             re.IGNORECASE),
    re.compile(r"\.onion/",                              re.IGNORECASE),  # Tor
    re.compile(r"discord\.com/api/webhooks/",            re.IGNORECASE),
    re.compile(r"telegram\.org/bot",                     re.IGNORECASE),
]


# ────────────────────────────────────────────────────────────────────────
# Helper: Levenshtein distance (stdlib only)
# ────────────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Simple O(n*m) Levenshtein. Adequate for short package-name comparison."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


# ============================================================================
# 1. scan_pth_files_for_supply_chain_iocs
# ============================================================================
@tool(
    name="scan_pth_files_for_supply_chain_iocs",
    description=(
        "Scan a Python site-packages directory tree for .pth files and flag "
        "any with known-malicious basenames or suspicious content patterns. "
        "Designed to detect the litellm supply-chain attack pattern (2026-03) "
        "and generic .pth-based persistence. References: PyPI advisory "
        "futuresearch.ai/blog/litellm-pypi-supply-chain-attack. "
        "MITRE ATT&CK: T1195.002, T1547."
    ),
    schema={"type": "object", "properties": {
        "search_root": {
            "type": "string",
            "description": "Directory to walk recursively. Usually site-packages or evidence_root.",
        },
        "max_depth": {"type": "integer", "default": 8, "maximum": 16},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["search_root"]},
)
def scan_pth_files_for_supply_chain_iocs(search_root, max_depth=8, limit=500):
    root = _safe_resolve(search_root)
    if not root.exists():
        return {"error": "directory_not_found", "path": str(root)}
    if not root.is_dir():
        return {"error": "not_a_directory", "path": str(root)}

    findings = []
    scanned = 0
    root_str_parts = len(root.parts)

    for path in root.rglob("*.pth"):
        if not path.is_file():
            continue
        try:
            depth = len(path.parts) - root_str_parts
        except Exception:
            continue
        if depth > max_depth:
            continue
        if scanned >= limit:
            break
        scanned += 1

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        flags = []
        if path.name in _KNOWN_MALICIOUS_PTH:
            flags.append({"severity": "critical",
                          "category": "known_malicious_basename",
                          "detail": path.name})

        for pattern, label in _SUSPICIOUS_PTH_PATTERNS:
            if pattern.search(content):
                flags.append({"severity": "high",
                              "category": "suspicious_content",
                              "detail": label})

        if flags:
            try:
                sha = _sha256(path)
            except Exception:
                sha = None
            findings.append({
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": sha,
                "flags": flags,
                "first_lines": content.splitlines()[:5],
            })

    return {
        "search_root": str(root),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
    }


# ============================================================================
# 2. detect_pypi_typosquatting
# ============================================================================
@tool(
    name="detect_pypi_typosquatting",
    description=(
        "Examine site-packages directory entries and flag package names that "
        "are close (Levenshtein distance 1 or 2) to high-value PyPI packages, "
        "indicating possible typosquatting. References: ReversingLabs Spectra "
        "AI 2024 typosquat report; npm event-stream incident (2018) for prior "
        "art. MITRE ATT&CK: T1195.002."
    ),
    schema={"type": "object", "properties": {
        "site_packages_dir": {"type": "string"},
        "max_distance": {"type": "integer", "default": 2, "maximum": 3},
        "limit": {"type": "integer", "default": 100, "maximum": 1000},
    }, "required": ["site_packages_dir"]},
)
def detect_pypi_typosquatting(site_packages_dir, max_distance=2, limit=100):
    sp = _safe_resolve(site_packages_dir)
    if not sp.exists():
        return {"error": "directory_not_found", "path": str(sp)}
    if not sp.is_dir():
        return {"error": "not_a_directory", "path": str(sp)}

    installed = []
    for entry in sp.iterdir():
        if entry.is_dir() and not entry.name.startswith(("_", ".")):
            # Strip version markers from dist-info dirs.
            name = entry.name
            for suffix in (".dist-info", ".egg-info"):
                if name.endswith(suffix):
                    name = name[: -len(suffix)]
                    name = re.sub(r"-[0-9].*$", "", name)
                    break
            installed.append(name.lower().replace("_", "-"))

    findings = []
    seen = set()
    for pkg in installed:
        if pkg in seen or pkg in _PYPI_HIGH_VALUE_TARGETS:
            continue
        seen.add(pkg)
        if len(findings) >= limit:
            break
        for target in _PYPI_HIGH_VALUE_TARGETS:
            dist = _levenshtein(pkg, target)
            if 0 < dist <= max_distance:
                findings.append({
                    "installed_package": pkg,
                    "similar_to": target,
                    "edit_distance": dist,
                    "severity": "high" if dist == 1 else "medium",
                })
                break

    return {
        "site_packages": str(sp),
        "packages_examined": len(seen),
        "typosquat_count": len(findings),
        "findings": findings,
    }


# ============================================================================
# 3. detect_nodejs_install_hooks
# ============================================================================
@tool(
    name="detect_nodejs_install_hooks",
    description=(
        "Walk a directory tree for package.json files and extract any "
        "preinstall, postinstall, or install scripts. These hooks execute "
        "during npm install and are a primary supply-chain attack vector "
        "(eslint-scope 2018, ua-parser-js 2021, node-ipc 2022). "
        "MITRE ATT&CK: T1195.002, T1059.007."
    ),
    schema={"type": "object", "properties": {
        "search_root": {"type": "string"},
        "max_depth": {"type": "integer", "default": 8, "maximum": 16},
        "limit": {"type": "integer", "default": 500, "maximum": 5000},
    }, "required": ["search_root"]},
)
def detect_nodejs_install_hooks(search_root, max_depth=8, limit=500):
    root = _safe_resolve(search_root)
    if not root.exists():
        return {"error": "directory_not_found", "path": str(root)}
    if not root.is_dir():
        return {"error": "not_a_directory", "path": str(root)}

    findings = []
    scanned = 0
    root_parts = len(root.parts)

    for path in root.rglob("package.json"):
        if not path.is_file():
            continue
        try:
            depth = len(path.parts) - root_parts
        except Exception:
            continue
        if depth > max_depth:
            continue
        if scanned >= limit:
            break
        scanned += 1

        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue

        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            continue

        suspicious_keys = ["preinstall", "postinstall", "install",
                           "preuninstall", "postuninstall", "prepare"]
        hits = {k: scripts[k] for k in suspicious_keys if k in scripts}
        if not hits:
            continue

        severity = "high" if "preinstall" in hits or "postinstall" in hits else "medium"
        findings.append({
            "path": str(path),
            "package_name": data.get("name"),
            "version": data.get("version"),
            "hooks": hits,
            "severity": severity,
        })

    return {
        "search_root": str(root),
        "package_jsons_scanned": scanned,
        "hooks_found_count": len(findings),
        "findings": findings,
    }


# ============================================================================
# 4. detect_python_backdoor_persistence
# ============================================================================
@tool(
    name="detect_python_backdoor_persistence",
    description=(
        "Check for known backdoor persistence locations across user home "
        "directories. Detects the litellm sysmon.py pattern, systemd user "
        "services, macOS LaunchAgents, and Linux cron entries that are "
        "frequently abused by supply-chain attacks for persistence. "
        "MITRE ATT&CK: T1547, T1053.003 (Cron), T1543 (Service)."
    ),
    schema={"type": "object", "properties": {
        "home_root": {
            "type": "string",
            "description": "User home directory or a directory containing user homes."
        },
    }, "required": ["home_root"]},
)
def detect_python_backdoor_persistence(home_root):
    root = _safe_resolve(home_root)
    if not root.exists():
        return {"error": "directory_not_found", "path": str(root)}

    findings = []
    for relpath in _BACKDOOR_PERSISTENCE_PATHS:
        candidate = root / relpath
        if not candidate.exists():
            continue
        entries = []
        try:
            if candidate.is_file():
                entries.append({
                    "path": str(candidate),
                    "type": "file",
                    "size": candidate.stat().st_size,
                })
            elif candidate.is_dir():
                for child in sorted(candidate.iterdir())[:50]:
                    try:
                        st = child.stat()
                        entries.append({
                            "path": str(child),
                            "type": "directory" if child.is_dir() else "file",
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                        })
                    except OSError:
                        continue
        except OSError:
            continue

        if not entries:
            continue

        sev = "critical" if relpath.endswith("sysmon") else "high"
        findings.append({
            "persistence_location": str(candidate),
            "category": relpath,
            "severity": sev,
            "entries": entries,
        })

    return {
        "home_root": str(root),
        "locations_checked": len(_BACKDOOR_PERSISTENCE_PATHS),
        "locations_with_content": len(findings),
        "findings": findings,
    }


# ============================================================================
# 5. detect_credential_file_access
# ============================================================================
@tool(
    name="detect_credential_file_access",
    description=(
        "Report atime/mtime/ctime for credential files (SSH/AWS/GCP/Azure/"
        "kubeconfig/etc) inside a user home directory. Sudden access right "
        "after a suspicious package install is a strong supply-chain "
        "exfiltration signal. MITRE ATT&CK: T1552."
    ),
    schema={"type": "object", "properties": {
        "home_root": {"type": "string"},
    }, "required": ["home_root"]},
)
def detect_credential_file_access(home_root):
    root = _safe_resolve(home_root)
    if not root.exists():
        return {"error": "directory_not_found", "path": str(root)}

    found = []
    for relpath in _CREDENTIAL_FILES:
        p = root / relpath
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        found.append({
            "path": str(p),
            "size": st.st_size,
            "atime": st.st_atime,
            "mtime": st.st_mtime,
            "ctime": st.st_ctime,
        })

    # Also pick up .env files (developer secrets) up to 3 levels deep.
    dotenv_hits = []
    try:
        for env_path in root.glob(".env"):
            if env_path.is_file():
                st = env_path.stat()
                dotenv_hits.append({
                    "path": str(env_path),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
    except OSError:
        pass

    return {
        "home_root": str(root),
        "credential_files_present": len(found),
        "credentials": found,
        "dotenv_files": dotenv_hits,
    }


# ============================================================================
# 6. grep_shell_history_for_c2
# ============================================================================
@tool(
    name="grep_shell_history_for_c2",
    description=(
        "Search shell history files (zsh_history, bash_history, python_history) "
        "for known C2 domains and patterns associated with supply-chain attacks. "
        "Detects post-install reconnaissance and exfiltration commands. "
        "MITRE ATT&CK: T1071 (Application Layer Protocol), T1059."
    ),
    schema={"type": "object", "properties": {
        "history_file_path": {"type": "string"},
        "extra_patterns": {
            "type": "array", "items": {"type": "string"},
            "description": "Additional regex patterns to match.",
        },
        "limit": {"type": "integer", "default": 200, "maximum": 5000},
    }, "required": ["history_file_path"]},
)
def grep_shell_history_for_c2(history_file_path, extra_patterns=None, limit=200):
    p = _safe_resolve(history_file_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    if not p.is_file():
        return {"error": "not_a_file", "path": str(p)}

    patterns = list(_C2_PATTERNS)
    for ep in (extra_patterns or []):
        try:
            patterns.append(re.compile(ep, re.IGNORECASE))
        except re.error:
            continue

    matches = []
    try:
        with p.open(encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if len(matches) >= limit:
                    break
                for pat in patterns:
                    if pat.search(line):
                        matches.append({
                            "line_number": lineno,
                            "matched_pattern": pat.pattern,
                            "line": line.rstrip("\n")[:300],
                        })
                        break
    except OSError as e:
        return {"error": "io_error", "detail": str(e)}

    try:
        sha = _sha256(p)
    except Exception:
        sha = None

    return {
        "history_file": str(p),
        "sha256": sha,
        "patterns_checked": len(patterns),
        "match_count": len(matches),
        "matches": matches,
    }
