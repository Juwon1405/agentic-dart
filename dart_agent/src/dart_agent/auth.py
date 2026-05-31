"""Claude Code CLI가 관리하는 OAuth credentials을 빌려쓰는 헬퍼.

목적: Anthropic API 키를 별도 발급받지 않고도 Claude Pro/Max 구독으로
Vision 분석을 호출. 사용자는 집 PC에 Claude Code CLI를 1회 설치·로그인만
하면 됨. 이후 refresh는 CLI가 알아서.

동작:
1. `~/.claude/.credentials.json` (또는 동등한 위치) 읽기
2. access_token이 곧 만료 임박이면 `claude` CLI를 dummy 호출해 강제 갱신
3. 봇은 access_token만 추출해 anthropic SDK에 넘김

토큰은 절대 코드/저장소에 들어가지 않는다. 모두 파일에서 동적으로 읽음.
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


# Claude Code CLI가 credentials을 저장할 수 있는 위치 후보들.
# 첫 매칭을 사용. macOS는 Keychain에 저장하기도 해서 거기는 별도 처리.
_CREDENTIALS_CANDIDATES = [
    "~/.claude/.credentials.json",          # Linux 기본
    "~/.config/claude/credentials.json",    # XDG 스타일
    "~/Library/Application Support/claude/.credentials.json",  # macOS (Keychain 미사용 시)
]


def _find_credentials_file() -> Optional[Path]:
    """존재하는 첫 credentials 파일 경로 반환."""
    # 환경변수 명시 override
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
    """다양한 스키마 변형을 표준 형태로 정규화.

    반환: {"access_token": str, "refresh_token": str|None, "expires_at": int(unix sec)}
    """
    # 형태 A: {"claudeAiOauth": {"accessToken": ..., "expiresAt": ..., "refreshToken": ...}}
    if isinstance(raw.get("claudeAiOauth"), dict):
        d = raw["claudeAiOauth"]
        exp = d.get("expiresAt") or 0
        # expiresAt이 ms 단위인 경우 보정
        if exp > 10_000_000_000:
            exp = exp // 1000
        return {
            "access_token": d.get("accessToken") or "",
            "refresh_token": d.get("refreshToken"),
            "expires_at": int(exp),
        }

    # 형태 B: 평면 키
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
    """macOS Keychain에서 Claude Code 토큰 추출 (파일이 없을 때 폴백).

    Claude Code CLI가 macOS에서 credentials.json 대신 Keychain에 저장하는
    경우를 대비. `security find-generic-password -s "Claude Code-credentials" -w`로
    JSON 문자열을 뽑아 파싱한다. macOS가 아니거나 항목이 없으면 None.
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
        log.debug("Keychain 조회 불가: %s", e)
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        raw = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        log.warning("Keychain 토큰 JSON 파싱 실패")
        return None
    parsed = _parse_credentials(raw)
    if parsed and parsed.get("access_token"):
        parsed["_path"] = "macOS Keychain (Claude Code-credentials)"
        log.debug("macOS Keychain에서 Claude Code 토큰 로드 성공")
        return parsed
    return None


def load_credentials() -> dict | None:
    """Claude Code 자격증명 로드. 파일 + 키체인 둘 다 읽어 '더 최신' 토큰 선택.

    2026.05.30 유신님 401 근본원인: 헤드리스(SSH) 맥미니는 로그인 키체인이 잠겨
    `security`가 'User interaction is not allowed'로 거부 → 키체인 우선 로직이
    토큰을 못 읽어 401. 파일(~/.claude/.credentials.json)엔 최신 토큰 정상 저장됨.
    → 파일 우선 + 양쪽 비교해 expires_at 큰(최신) 쪽 채택. 헤드리스는 파일이 답.
    """
    candidates = []
    # 1) 파일 우선 (헤드리스에서 가장 안정적)
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
            log.warning("credentials.json 읽기 실패 %s: %s", path, e)
    # 2) 키체인 (잠겨 있으면 None — 조용히 무시)
    kc = _load_from_keychain()
    if kc and kc.get("access_token"):
        kc["_path"] = "keychain"
        candidates.append(kc)
    if not candidates:
        return None
    # 만료시각이 가장 늦은(=가장 최근 갱신된) 토큰 선택
    return max(candidates, key=lambda c: c.get("expires_at", 0))


def is_expiring_soon(creds: dict, threshold_sec: int = 3600) -> bool:
    """만료까지 threshold_sec 미만이면 True. expires_at이 0이면 알 수 없음 → False."""
    exp = int(creds.get("expires_at") or 0)
    if exp <= 0:
        return False
    return (exp - time.time()) < threshold_sec


def trigger_refresh(timeout: float = 30.0) -> bool:
    """`claude` CLI를 dummy 명령으로 호출해 토큰 갱신을 유도.

    반환: 호출 성공(False면 CLI 미설치/오류 등). 갱신이 실제로 됐는지는
    호출자가 credentials.json을 다시 읽어 확인해야 한다.

    ⚠ 한계 (2026.05.30 유신님 401 사고): `claude --version`/`--help` 는 토큰을
    갱신하지 않는다(버전 출력만). 진짜 갱신은 refresh_oauth_token() 이 직접 수행.
    이 함수는 폴백으로만 남긴다.
    """
    cmd_candidates = [
        ["claude", "--version"],   # 가장 가벼움
        ["claude", "--help"],
    ]
    for cmd in cmd_candidates:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                log.info("claude CLI 호출 성공 (%s)", " ".join(cmd))
                return True
            log.debug("claude %s 실패 (rc=%d): %s", cmd, r.returncode, r.stderr[:200])
        except FileNotFoundError:
            log.info("claude CLI를 찾을 수 없습니다. PATH에 설치되어 있는지 확인.")
            return False
        except subprocess.TimeoutExpired:
            log.warning("claude CLI 응답 없음 (timeout %ss)", timeout)
            return False
        except Exception as e:
            log.warning("claude CLI 호출 오류: %s", e)
    return False


# Claude Code 공개 OAuth client_id (Anthropic CLI 가 쓰는 고정 공개값).
_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"


def refresh_oauth_token(timeout: float = 30.0) -> dict | None:
    """refresh_token 으로 새 access_token 을 직접 발급받아 저장 (2026.05.30 신규).

    핵심: `claude --version` 은 토큰을 갱신하지 않으므로(유신님 401 사고 근본원인),
    OAuth refresh_token grant 를 토큰 엔드포인트에 직접 POST 한다. 성공 시 새
    토큰을 원래 저장소(파일/키체인)에 다시 써서 영속화.

    반환: 갱신된 creds dict {access_token, refresh_token, expires_at} | 실패 시 None.
    """
    creds = load_credentials()
    if not creds or not creds.get("refresh_token"):
        log.warning("refresh_oauth_token: refresh_token 없음 — 직접 갱신 불가")
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
            log.warning("OAuth refresh HTTP %s: %s", r.status_code, r.text[:200])
            return None
        data = r.json()
        new_access = data.get("access_token")
        if not new_access:
            log.warning("OAuth refresh 응답에 access_token 없음")
            return None
        new_refresh = data.get("refresh_token") or creds["refresh_token"]
        expires_in = int(data.get("expires_in") or 0)
        new_exp = int(time.time()) + expires_in if expires_in else creds.get("expires_at", 0)
        new_creds = {"access_token": new_access, "refresh_token": new_refresh,
                     "expires_at": new_exp}
        # 저장소에 다시 쓰기 (영속화 — 이걸 안 하면 매번 만료)
        _save_credentials(new_creds)
        log.info("✅ OAuth 토큰 직접 갱신 성공 (만료까지 %.0f초)", new_exp - time.time())
        return new_creds
    except Exception as e:
        log.warning("OAuth refresh 예외: %s: %s", type(e).__name__, str(e)[:120])
        return None


def _save_credentials(creds: dict) -> bool:
    """갱신된 토큰을 원래 저장소에 다시 쓴다. 파일 우선, macOS 키체인도 갱신.

    claudeAiOauth 스키마(밀리초 expiresAt)로 저장해 Claude CLI 와 호환 유지.
    """
    payload = {"claudeAiOauth": {
        "accessToken": creds["access_token"],
        "refreshToken": creds.get("refresh_token"),
        "expiresAt": int(creds["expires_at"]) * 1000,  # ms
        "subscriptionType": "max",
    }}
    ok = False
    # 1) 파일이 있으면 파일에 저장
    path = _find_credentials_file()
    if path:
        try:
            path.write_text(json.dumps(payload))
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            log.info("갱신 토큰 파일 저장: %s", path)
            ok = True
        except Exception as e:
            log.warning("토큰 파일 저장 실패: %s", e)
    # 2) macOS 키체인도 갱신 (키체인 우선 로드라 동기화 필수)
    import sys
    if sys.platform == "darwin":
        try:
            subprocess.run(
                ["security", "add-generic-password", "-U", "-s",
                 "Claude Code-credentials", "-a", os.environ.get("USER", "claude"),
                 "-w", json.dumps(payload)],
                capture_output=True, text=True, timeout=10,
            )
            log.info("갱신 토큰 키체인 저장")
            ok = True
        except Exception as e:
            log.debug("키체인 저장 실패(무시): %s", e)
    return ok


def refresh_oauth_if_needed(threshold_sec: int = 7200) -> dict:
    """OAuth 토큰 선제 갱신 (2026.05.31 유신님 설계 — API 끊겨도 OAuth 항상 준비).
    만료까지 threshold_sec(기본 2h) 미만이면 refresh_token 으로 직접 갱신.
    주기적(데몬)으로 호출 → OAuth 항상 신선 → API 소진 시 즉시 Haiku 폴백.
    반환: {state, detail, expires_in_sec}. 토큰 없으면 state='none'."""
    creds = load_credentials()
    if not creds or not creds.get("access_token"):
        return {"state": "none", "detail": "OAuth 자격증명 없음", "expires_in_sec": 0}
    exp = int(creds.get("expires_at") or 0)
    remain = (exp - time.time()) if exp else 0
    if exp and remain >= threshold_sec:
        return {"state": "fresh", "detail": "갱신 불필요", "expires_in_sec": int(remain)}
    refreshed = refresh_oauth_token()
    if refreshed and refreshed.get("access_token"):
        nr = refreshed["expires_at"] - time.time()
        return {"state": "refreshed", "detail": "직접 갱신 성공", "expires_in_sec": int(nr)}
    return {"state": "stale", "detail": "갱신 실패 — refresh_token 만료 가능",
            "expires_in_sec": int(remain)}


def get_access_token(refresh_threshold_sec: int = 3600) -> str | None:
    """현재 유효한 access_token 반환. 만료 임박이면 CLI 호출로 갱신 후 재시도.

    반환:
    - 정상: access_token 문자열
    - 실패(파일 없음/CLI 없음/갱신 실패): None
    """
    creds = load_credentials()
    if creds is None:
        return None

    if not is_expiring_soon(creds, threshold_sec=refresh_threshold_sec):
        return creds["access_token"]

    log.info(
        "access_token 만료 임박 (expires_at=%d, 남은=%ds). 갱신 시도.",
        creds["expires_at"], int(creds["expires_at"] - time.time()),
    )
    # 1순위: refresh_token 으로 직접 OAuth 갱신 (claude --version 은 갱신 안 됨).
    refreshed = refresh_oauth_token()
    if refreshed and refreshed.get("access_token"):
        return refreshed["access_token"]
    # 2순위(폴백): CLI 호출 후 재독 (혹시 CLI 가 백그라운드 갱신했을 수도)
    log.info("직접 OAuth 갱신 실패 → CLI 폴백 시도")
    if not trigger_refresh():
        log.warning("CLI 호출도 실패. 만료 임박 토큰 그대로 반환.")
        return creds["access_token"]
    creds2 = load_credentials()
    if creds2 is None:
        return creds["access_token"]
    if creds2["access_token"] != creds["access_token"]:
        log.info("토큰 갱신 완료 (새 expires_at=%d)", creds2["expires_at"])
    return creds2["access_token"]


# ──────────────────────────────────────────────────────────────────────────
# agentic-dart 전용: 3티어 클라이언트 빌더 (2026.05.31 유신님 — 메키키/단타와 동일).
#   Tier 1) ANTHROPIC_API_KEY (있으면 종량제 API)
#   Tier 2) OAuth 파일 (~/.claude/.credentials.json — 로컬 우선)
#   Tier 3) macOS Keychain (파일 없을 때 폴백) + 만료 임박 시 자동 갱신/연장
# 키 없어도 OAuth(구독) 로 동작 → API 비용 0.
# ──────────────────────────────────────────────────────────────────────────
def build_anthropic_client(timeout: float = 600.0):
    """3티어 인증 Anthropic 클라이언트. 못 만들면 None (호출부가 mock 폴백)."""
    try:
        import anthropic
    except ImportError:
        return None
    # Tier 1: API 키 (있으면 우선 — 종량제)
    if os.environ.get("ANTHROPIC_API_KEY"):
        log.info("[dart-auth] Tier1: ANTHROPIC_API_KEY 사용")
        return anthropic.Anthropic(timeout=timeout, max_retries=0)
    # Tier 2+3: OAuth (파일 우선 → Keychain 폴백, load_credentials 가 최신 선택)
    creds = load_credentials()
    if creds and creds.get("access_token"):
        # 만료 임박하면 직접 갱신 시도 (연장)
        try:
            if is_expiring_soon(creds, threshold_sec=3600):
                refreshed = refresh_oauth_token()
                if refreshed and refreshed.get("access_token"):
                    creds = refreshed
        except Exception as e:
            log.debug("[dart-auth] OAuth 갱신 시도 실패(무시): %s", e)
        src = creds.get("_path", "?")
        log.info("[dart-auth] OAuth 사용 (출처: %s) — API 비용 0", src)
        return anthropic.Anthropic(auth_token=creds["access_token"],
                                   timeout=timeout, max_retries=0)
    log.warning("[dart-auth] API 키·OAuth 모두 없음 → 클라이언트 생성 불가")
    return None


def has_any_credentials() -> bool:
    """API 키 또는 OAuth 자격증명이 하나라도 있으면 True (live 모드 가능 판정)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    creds = load_credentials()
    return bool(creds and creds.get("access_token"))
