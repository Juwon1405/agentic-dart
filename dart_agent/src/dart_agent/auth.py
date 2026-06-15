"""Flexible authentication layer for live-mode Anthropic clients.

Flow:
1. Prefer `ANTHROPIC_API_KEY` when set.
2. Optionally load local Claude credentials when present on the analyst host.
3. Hand the resulting credential to the Anthropic SDK.

No tokens ever live in code or the repo — every value is read at runtime
from the local store.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# Candidate locations where local Claude credentials may be present. Tried in
# order; macOS may also use the Keychain, handled separately below.
_CREDENTIALS_CANDIDATES = [
    "~/.claude/.credentials.json",          # Linux default
    "~/.config/claude/credentials.json",    # XDG-style
    "~/Library/Application Support/claude/.credentials.json",  # macOS (when Keychain is not used)
]


def _find_credentials_file() -> Optional[Path]:
    """Return the first credentials file path that exists, or None."""
    # Explicit environment-variable override
    env_path = os.environ.get("CLAUDE_CREDENTIALS_FILE")
    if env_path:
        p = Path(env_path).expanduser()
        if p.is_file():
            return p

    for candidate in _CREDENTIALS_CANDIDATES:
        p = Path(candidate).expanduser()
        if p.is_file():
            return p
    return None


def _parse_credentials(raw: dict) -> dict | None:
    """Normalize the several credential schema variants into one shape.

    Returns: {"access_token": str, "refresh_token": str|None,
              "expires_at": int (unix seconds)}
    """
    # Shape A: {"claudeAiOauth": {"accessToken": ..., "expiresAt": ..., "refreshToken": ...}}
    if isinstance(raw.get("claudeAiOauth"), dict):
        d = raw["claudeAiOauth"]
        exp = d.get("expiresAt") or 0
        # Correct expiresAt if it is in milliseconds
        if exp > 10_000_000_000:
            exp = exp // 1000
        return {
            "access_token": d.get("accessToken") or "",
            "refresh_token": d.get("refreshToken"),
            "expires_at": int(exp),
        }

    # Shape B: flat keys
    if raw.get("access_token") or raw.get("accessToken"):
        access = raw.get("access_token") or raw.get("accessToken")
        refresh = raw.get("refresh_token") or raw.get("refreshToken")
        exp = raw.get("expires_at") or raw.get("expiresAt") or 0
        if exp > 10_000_000_000:
            exp = exp // 1000
        return {
            "access_token": access or "",
            "refresh_token": refresh,
            "expires_at": int(exp),
        }

    return None


def _load_from_keychain() -> dict | None:
    """Pull local Claude credentials from the macOS Keychain (fallback).

    Used when tokens are stored in the Keychain instead of in credentials.json.
    Reads the secret via
    `security find-generic-password -s "Claude Code-credentials" -w` and
    parses the JSON it returns. Returns None on non-macOS hosts or when
    the entry is absent.
    """
    import sys
    if sys.platform != "darwin":
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        log.debug("Keychain lookup unavailable: %s", e)
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        raw = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        log.warning("Failed to parse JSON returned by the Keychain lookup")
        return None
    parsed = _parse_credentials(raw)
    if parsed and parsed.get("access_token"):
        parsed["_path"] = "macOS Keychain (Claude Code-credentials)"
        log.debug("Loaded Claude Code credentials from the macOS Keychain")
        return parsed
    return None


def load_credentials() -> dict | None:
    """Load local Claude credentials. Reads both file and Keychain and picks
    the FRESHER (larger expires_at) of the two.

    Why both: on a headless host (SSH session, no GUI login), the macOS
    login Keychain is locked and `security` refuses with "User interaction
    is not allowed", so a Keychain-first strategy fails to read the token
    even when the file copy is fine. File-first + freshness-compare keeps
    both interactive and headless setups working without configuration.
    """
    candidates = []
    # 1) File first (most reliable on headless hosts)
    path = _find_credentials_file()
    if path:
        try:
            with path.open("r", encoding="utf-8") as f:
                raw = json.load(f)
            parsed = _parse_credentials(raw)
            if parsed and parsed.get("access_token"):
                parsed["_path"] = str(path)
                candidates.append(parsed)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Failed to read credentials.json at %s: %s", path, e)
    # 2) Keychain (returns None when locked — silently ignored)
    kc = _load_from_keychain()
    if kc and kc.get("access_token"):
        kc["_path"] = "keychain"
        candidates.append(kc)
    if not candidates:
        return None
    # Pick the token with the latest expiry (= most recently refreshed)
    return max(candidates, key=lambda c: c.get("expires_at", 0))


def is_expiring_soon(creds: dict, threshold_sec: int = 3600) -> bool:
    """True if the token expires within threshold_sec. Unknown expiry returns False."""
    exp = int(creds.get("expires_at") or 0)
    if exp <= 0:
        return False
    return (exp - time.time()) < threshold_sec


def trigger_refresh(timeout: float = 30.0) -> bool:
    """Invoke the `claude` CLI as a side-effect to encourage a token refresh.

    Returns whether the CLI invocation itself succeeded; the caller must
    re-read credentials.json to know whether the access_token was actually
    refreshed.

    Known limitation: `claude --version` / `--help` print version info
    without refreshing the token. The direct refresh helper below can refresh
    local credentials when a refresh token is already present. This function
    is kept as a legacy fallback only.
    """
    cmd_candidates = [
        ["claude", "--version"],   # cheapest invocation
        ["claude", "--help"],
    ]
    for cmd in cmd_candidates:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                log.info("claude CLI call succeeded (%s)", " ".join(cmd))
                return True
            log.debug("claude %s failed (rc=%d): %s", cmd, r.returncode, r.stderr[:200])
        except FileNotFoundError:
            log.info("claude CLI not found. Ensure it is installed on PATH.")
            return False
        except subprocess.TimeoutExpired:
            log.warning("claude CLI did not respond within %ss", timeout)
            return False
        except Exception as e:
            log.warning("claude CLI invocation error: %s", e)
    return False


# Public client_id used by local Claude credentials (constant, not a secret).
_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"


def refresh_oauth_token(timeout: float = 30.0) -> dict | None:
    """Issue a new access_token directly using the refresh_token, and
    persist it back to whichever store held the previous one.

    The CLI-side `claude --version` invocation does NOT refresh the token,
    so we POST the refresh_token grant to the token endpoint ourselves.
    On success the new credentials are written back to the file (and to
    the Keychain when present), so subsequent reads see fresh values.

    Returns: refreshed creds dict
             {access_token, refresh_token, expires_at} | None on failure.
    """
    creds = load_credentials()
    if not creds or not creds.get("refresh_token"):
        log.warning("refresh_oauth_token: no refresh_token available — cannot refresh directly")
        return None
    try:
        import requests
        r = requests.post(
            _OAUTH_TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "refresh_token": creds["refresh_token"],
                "client_id": _OAUTH_CLIENT_ID,
            },
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if r.status_code != 200:
            log.warning("Local credential refresh HTTP %s: %s", r.status_code, r.text[:200])
            return None
        data = r.json()
        new_access = data.get("access_token")
        if not new_access:
            log.warning("Local credential refresh response did not include access_token")
            return None
        new_refresh = data.get("refresh_token") or creds["refresh_token"]
        expires_in = int(data.get("expires_in") or 0)
        new_exp = int(time.time()) + expires_in if expires_in else creds.get("expires_at", 0)
        new_creds = {"access_token": new_access, "refresh_token": new_refresh,
                     "expires_at": new_exp}
        # Persist the refreshed credentials so subsequent reads pick them up
        _save_credentials(new_creds)
        log.info("Local Claude token refreshed directly (expires in %.0fs)", new_exp - time.time())
        return new_creds
    except Exception as e:
        log.warning("Local credential refresh exception: %s: %s", type(e).__name__, str(e)[:120])
        return None


def _save_credentials(creds: dict) -> bool:
    """Write refreshed credentials back to their original store. File first,
    Keychain second (when present).

    Saved in the claudeAiOauth schema (milliseconds expiresAt) so that the
    Claude CLI continues to read the values without changes.
    """
    payload = {"claudeAiOauth": {
        "accessToken": creds["access_token"],
        "refreshToken": creds.get("refresh_token"),
        "expiresAt": int(creds["expires_at"]) * 1000,  # ms
        "subscriptionType": "max",
    }}
    ok = False
    # 1) If the credentials file exists, write through to it
    path = _find_credentials_file()
    if path:
        try:
            path.write_text(json.dumps(payload))
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            log.info("Refreshed token written to %s", path)
            ok = True
        except Exception as e:
            log.warning("Failed to persist refreshed token to file: %s", e)
    # 2) Also refresh the macOS Keychain entry so it stays in sync
    import sys
    if sys.platform == "darwin":
        try:
            subprocess.run(
                ["security", "add-generic-password", "-U", "-s",
                 "Claude Code-credentials", "-a", os.environ.get("USER", "claude"),
                 "-w", json.dumps(payload)],
                capture_output=True, text=True, timeout=10,
            )
            log.info("Refreshed token written to the Keychain")
            ok = True
        except Exception as e:
            log.debug("Keychain write failed (ignored): %s", e)
    return ok


def refresh_oauth_if_needed(threshold_sec: int = 7200) -> dict:
    """Proactively refresh the local token so it is ready as a fallback.

    When the access_token has less than threshold_sec (default 2h) left
    until expiry, refresh it via refresh_token directly. Intended for a
    periodic call (daemon, cron) so that local credentials stay fresh.

    Returns: {state, detail, expires_in_sec}. state is one of
             'none' | 'fresh' | 'refreshed' | 'stale'.
    """
    creds = load_credentials()
    if not creds or not creds.get("access_token"):
        return {"state": "none", "detail": "no local credentials available", "expires_in_sec": 0}
    exp = int(creds.get("expires_at") or 0)
    remain = (exp - time.time()) if exp else 0
    if exp and remain >= threshold_sec:
        return {"state": "fresh", "detail": "refresh not needed", "expires_in_sec": int(remain)}
    refreshed = refresh_oauth_token()
    if refreshed and refreshed.get("access_token"):
        nr = refreshed["expires_at"] - time.time()
        return {"state": "refreshed", "detail": "refreshed via refresh_token grant", "expires_in_sec": int(nr)}
    return {"state": "stale", "detail": "refresh failed — refresh_token may be expired",
            "expires_in_sec": int(remain)}


def get_access_token(refresh_threshold_sec: int = 3600) -> str | None:
    """Return a currently-valid access_token, refreshing it first if it is
    close to expiry.

    Returns:
        access_token string on success, or None on failure (no credentials,
        no CLI, refresh failed).
    """
    creds = load_credentials()
    if creds is None:
        return None

    if not is_expiring_soon(creds, threshold_sec=refresh_threshold_sec):
        return creds["access_token"]

    log.info(
        "access_token close to expiry (expires_at=%d, %ds remaining); attempting refresh.",
        creds["expires_at"], int(creds["expires_at"] - time.time()),
    )
    # Primary: direct refresh via refresh_token grant.
    refreshed = refresh_oauth_token()
    if refreshed and refreshed.get("access_token"):
        return refreshed["access_token"]
    # Fallback: invoke the CLI and re-read (the CLI may have refreshed in the background)
    log.info("Direct token refresh failed; trying CLI fallback")
    if not trigger_refresh():
        log.warning("CLI invocation also failed; returning the about-to-expire token")
        return creds["access_token"]
    creds2 = load_credentials()
    if creds2 is None:
        return creds["access_token"]
    if creds2["access_token"] != creds["access_token"]:
        log.info("Token refreshed (new expires_at=%d)", creds2["expires_at"])
    return creds2["access_token"]


# ──────────────────────────────────────────────────────────────────────────
# Flexible Anthropic client builder.
#   1) ANTHROPIC_API_KEY when set.
#   2) Local Claude credentials when available on the analyst host.
# ──────────────────────────────────────────────────────────────────────────
def resolve_auth_mode(model: str | None = None) -> str | None:
    """Return which credential source build_anthropic_client would pick for
    this model — ``"oauth"``, ``"api"``, or ``None`` — WITHOUT building a
    client or refreshing anything.

    This lets a caller label the model line ("haiku · oauth") before a run, so
    you can see at a glance whether it's the cheap subscription or the metered
    API — and, if it ever comes back ``None``, that no credential is available
    (e.g. the local login expired).

    Preference: haiku prefers local OAuth (subscription); everything else
    prefers the API key (metered). Each falls back to the other.
    """
    have_api = bool(os.environ.get("ANTHROPIC_API_KEY"))
    creds = load_credentials()
    have_oauth = bool(creds and creds.get("access_token"))
    short = model.split("-")[1] if model and "-" in model else (model or "?")
    prefer_oauth = (short == "haiku")
    if prefer_oauth:
        if have_oauth:
            return "oauth"
        if have_api:
            return "api"
    else:
        if have_api:
            return "api"
        if have_oauth:
            return "oauth"
    return None


def build_anthropic_client(model: str | None = None,
                           timeout: float = 600.0, max_retries: int = 4):
    """Build an Anthropic client, choosing the credential source by model
    (see ``resolve_auth_mode``). Returns ``(client, auth_mode)`` where
    auth_mode is ``"oauth"``, ``"api"``, or ``None`` (no source — caller falls
    back to mock).

    haiku rides local OAuth (subscription) when present; sonnet/opus prefer the
    API key (metered). If the preferred source is missing, the other is used
    silently. When OAuth is chosen and the token is close to expiry, it is
    refreshed first via the existing refresh_token grant — this is a
    per-client-build check at run time, NOT a background daemon (the tool is a
    short-lived CLI, so it only refreshes if a long multi-case run would
    otherwise cross the expiry).

    `max_retries` enables the SDK's exponential backoff on transient failures
    (HTTP 429, 529, 5xx, connection drops). Deterministic mode never touches
    the network, so this only affects ``--mode live``.
    """
    try:
        import anthropic
    except ImportError:
        return None, None

    mode = resolve_auth_mode(model)
    short = model.split("-")[1] if model and "-" in model else (model or "?")

    if mode == "oauth":
        creds = load_credentials()
        try:
            if is_expiring_soon(creds, threshold_sec=3600):
                refreshed = refresh_oauth_token()
                if refreshed and refreshed.get("access_token"):
                    creds = refreshed
        except Exception as e:  # noqa: BLE001
            log.debug("[dart-auth] oauth refresh attempt failed (ignored): %s", e)
        log.info("[dart-auth] %s → local Claude credentials (oauth, source: %s)",
                 short, creds.get("_path", "?"))
        return (anthropic.Anthropic(auth_token=creds["access_token"],
                                    timeout=timeout, max_retries=max_retries), "oauth")

    if mode == "api":
        log.info("[dart-auth] %s → ANTHROPIC_API_KEY (api)", short)
        return (anthropic.Anthropic(timeout=timeout, max_retries=max_retries), "api")

    log.warning("[dart-auth] no credential source available; client cannot be built")
    return None, None


def has_any_credentials() -> bool:
    """Return True if either an API key or local credentials are present
    (used by callers to decide whether live mode is viable)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    creds = load_credentials()
    return bool(creds and creds.get("access_token"))
