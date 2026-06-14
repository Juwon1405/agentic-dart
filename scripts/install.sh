#!/usr/bin/env bash
# Agentic-DART installer.
#
# OS-aware, venv-first installer for Agentic-DART and its collector adapter.
# Optionally stages the SANS SIFT toolchain (via `cast`) and the Eric Zimmerman
# Tools (.NET 9 builds). Nothing is silently faked: every optional component
# reports clearly whether it was installed, skipped, or unavailable.
#
# Usage:
#   bash scripts/install.sh [options]
#
# Common cases:
#   bash scripts/install.sh           # Agentic-DART + adapter (no SIFT). Easiest.
#   bash scripts/install.sh --full    # the above + SIFT toolchain + EZ Tools.
#
# Options:
#   --full                          One-shot full setup: --install-sift
#                                   --install-eztools --yes (Ubuntu/SIFT).
#   --os auto|ubuntu|centos|macos   Target OS (default: auto-detect).
#   --install-sift                  Install the SIFT toolchain via `cast`.
#   --skip-sift                     Do not touch SIFT (default).
#   --install-eztools               Stage Eric Zimmerman Tools (.NET 9) to ./bin/zimmerman/.
#   --skip-eztools                  Do not stage EZ Tools (default).
#   --skip-velociraptor             Do not let the adapter fetch Velociraptor.
#                                   (--source image needs it; --source zip does not.)
#   --adapter-dir <path>            Where to clone the collector adapter
#                                   (default: ../agentic-dart-collector-adapter).
#   --yes                           Non-interactive; assume yes to prompts.
#   --help                          Show this help and exit.
set -euo pipefail

# ---- defaults --------------------------------------------------------------
OS_TARGET="auto"
DO_SIFT=0
DO_EZTOOLS=0
SKIP_VELOCIRAPTOR=0
ASSUME_YES=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADAPTER_DIR="$(cd "${REPO_ROOT}/.." && pwd)/agentic-dart-collector-adapter"
ADAPTER_URL="https://github.com/Juwon1405/agentic-dart-collector-adapter.git"
EZ_BASE="https://download.ericzimmermanstools.com/net9"
EZ_TOOLS=(EvtxECmd MFTECmd PECmd RECmd AmcacheParser SBECmd)

log()  { printf '\033[1;34m[agentic-dart]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
sect() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---- argument parser -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)           DO_SIFT=1; DO_EZTOOLS=1; ASSUME_YES=1; shift ;;
    --os)             OS_TARGET="${2:-}"; shift 2 ;;
    --install-sift)   DO_SIFT=1; shift ;;
    --skip-sift)      DO_SIFT=0; shift ;;
    --install-eztools) DO_EZTOOLS=1; shift ;;
    --skip-eztools)   DO_EZTOOLS=0; shift ;;
    --skip-velociraptor) SKIP_VELOCIRAPTOR=1; shift ;;
    --adapter-dir)    ADAPTER_DIR="${2:-}"; shift 2 ;;
    --yes|-y)         ASSUME_YES=1; shift ;;
    --help|-h)        usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

case "${OS_TARGET}" in auto|ubuntu|centos|macos) ;; *) die "invalid --os '${OS_TARGET}'" ;; esac

detect_os() {
  if [[ "${OS_TARGET}" != "auto" ]]; then echo "${OS_TARGET}"; return; fi
  case "$(uname -s)" in
    Darwin) echo macos ;;
    Linux)
      if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
          *ubuntu*|*debian*) echo ubuntu ;;
          *rhel*|*centos*|*fedora*) echo centos ;;
          *) echo ubuntu ;;  # default Linux assumption
        esac
      else echo ubuntu; fi ;;
    *) die "unsupported platform $(uname -s)" ;;
  esac
}
OS="$(detect_os)"

sect "Agentic-DART installer (os=${OS}, sift=${DO_SIFT}, eztools=${DO_EZTOOLS}, velociraptor=$([ "${SKIP_VELOCIRAPTOR}" == 1 ] && echo skip || echo auto))"

# ---- 1. system dependencies ------------------------------------------------
sect "1. System dependencies"
install_os_deps() {
  case "${OS}" in
    ubuntu)
      if command -v apt-get >/dev/null; then
        # yara is a small, apt-available SIFT-adapter tool (sift_yara_*); the
        # other adapter binaries (Volatility 3, EZ Tools, Plaso) are heavier and
        # stay opt-in under --install-sift / --install-eztools.
        local pkgs=(python3 python3-venv python3-pip git curl unzip yara)
        log "apt-get install: ${pkgs[*]}"
        if [[ "${ASSUME_YES}" == 1 ]]; then sudo apt-get update -qq || warn "apt update failed (continuing)"; fi
        sudo apt-get install -y "${pkgs[@]}" || warn "some apt packages failed (optional ones are non-fatal)"
      else warn "apt-get not found; install python3/venv/pip/git/curl/unzip manually"; fi ;;
    centos)
      local mgr=""; command -v dnf >/dev/null && mgr=dnf || { command -v yum >/dev/null && mgr=yum; }
      if [[ -n "${mgr}" ]]; then
        local pkgs=(python3 python3-pip git curl unzip)
        log "${mgr} install: ${pkgs[*]}"
        sudo "${mgr}" install -y "${pkgs[@]}" || warn "some ${mgr} packages failed (non-fatal)"
      else warn "neither dnf nor yum found; install python3/pip/git/curl/unzip manually"; fi ;;
    macos)
      if command -v brew >/dev/null; then
        log "brew install: python git curl"
        brew install python git curl || warn "some brew formulae failed (non-fatal)"
      else warn "Homebrew not found; install from https://brew.sh then re-run, or install python3/git manually"; fi ;;
  esac
}
install_os_deps
command -v python3 >/dev/null || die "python3 is required"
command -v git     >/dev/null || die "git is required"
PYV="$(python3 -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
[[ "${PYV}" =~ ^3\.(1[0-9]|[2-9][0-9])$ ]] || warn "Python 3.10+ recommended; found ${PYV}"
ok "python3 ${PYV}, git present"

# ---- 2. Python venv + packages --------------------------------------------
sect "2. Python virtualenv + packages (venv-first)"
cd "${REPO_ROOT}"
VENV_OK=0
if python3 -m venv .venv 2>/dev/null; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python3 -m pip install --upgrade pip wheel >/dev/null
  VENV_OK=1
  ok "virtualenv ready: ${REPO_ROOT}/.venv"
else
  warn "python3 -m venv failed (python3-venv missing?)."
  warn "Falling back to a CONTROLLED system install. Never uninstalling OS pip/wheel."
fi

pip_install() {
  if [[ "${VENV_OK}" == 1 ]]; then
    python3 -m pip install "$@"
  else
    # Controlled non-venv fallback: do not disturb OS-managed pip/wheel.
    python3 -m pip install --break-system-packages --ignore-installed wheel pip "$@"
  fi
}

log "Installing third-party requirements (requirements.txt)"
pip_install -r requirements.txt
log "Installing Agentic-DART packages (editable)"
pip_install -e ./dart_audit -e './dart_mcp[stdio]' -e ./dart_corr -e './dart_agent[live]'
ok "dart_audit, dart_mcp, dart_corr, dart_agent installed"

# ---- 3. collector adapter (same venv) -------------------------------------
sect "3. Collector adapter"
if [[ -d "${ADAPTER_DIR}/.git" ]]; then
  log "Updating adapter checkout at ${ADAPTER_DIR}"
  git -C "${ADAPTER_DIR}" pull --ff-only || warn "adapter pull failed (continuing with existing checkout)"
else
  log "Cloning adapter into ${ADAPTER_DIR}"
  git clone --depth 1 "${ADAPTER_URL}" "${ADAPTER_DIR}" || warn "adapter clone failed"
fi
if [[ -d "${ADAPTER_DIR}" ]]; then
  pip_install -e "${ADAPTER_DIR}" || warn "adapter editable install failed"
  ok "adapter installed: python3 -m dart_collector_adapter --help"

  # Chain into the adapter's own installer to stage Velociraptor (and verify
  # its SHA-256). The adapter repo is the single source of truth for which
  # Velociraptor version to fetch and how to verify it; this script only
  # decides whether to call it at all. Skip cleanly when the user passed
  # --skip-velociraptor, or when --source image is already satisfied by an
  # existing binary on PATH / DART_VELOCIRAPTOR_BIN / ${ADAPTER_DIR}/bin.
  if [[ "${SKIP_VELOCIRAPTOR}" == 1 ]]; then
    log "Velociraptor staging skipped (--skip-velociraptor)."
    log "--source image will fail until you stage one manually; --source zip"
    log "does not require Velociraptor."
  elif command -v velociraptor >/dev/null; then
    ok "Velociraptor on PATH: $(command -v velociraptor) (adapter installer skipped)"
  elif [[ -n "${DART_VELOCIRAPTOR_BIN:-}" && -x "${DART_VELOCIRAPTOR_BIN}" ]]; then
    ok "Velociraptor via DART_VELOCIRAPTOR_BIN=${DART_VELOCIRAPTOR_BIN} (adapter installer skipped)"
  elif [[ -x "${ADAPTER_DIR}/bin/velociraptor" ]]; then
    ok "Velociraptor already staged at ${ADAPTER_DIR}/bin/velociraptor (adapter installer skipped)"
  elif [[ -x "${ADAPTER_DIR}/scripts/install.sh" ]]; then
    log "Running adapter installer to stage Velociraptor (SHA-256 verified upstream)..."
    if ( cd "${ADAPTER_DIR}" && bash scripts/install.sh --install-dir "${ADAPTER_DIR}/bin" ); then
      ok "Velociraptor staged at ${ADAPTER_DIR}/bin/velociraptor"
    else
      warn "adapter installer failed; --source image will be unavailable until you"
      warn "rerun: ( cd ${ADAPTER_DIR} && bash scripts/install.sh )"
      warn "(--source zip does not require Velociraptor.)"
    fi
  else
    warn "Adapter installer not found at ${ADAPTER_DIR}/scripts/install.sh."
    warn "Velociraptor binary missing; --source image will be unavailable until"
    warn "you stage one into ${ADAPTER_DIR}/bin/ or export DART_VELOCIRAPTOR_BIN."
    warn "(--source zip does not require Velociraptor.)"
  fi
fi

# ---- 4. SIFT toolchain (optional) -----------------------------------------
sect "4. SIFT toolchain"
SIFT_CORE=(vol log2timeline.py psort.py yara)
detect_sift() {
  local found=0
  for b in "${SIFT_CORE[@]}"; do command -v "${b}" >/dev/null 2>&1 && found=$((found+1)); done
  echo "${found}"
}
if [[ "${DO_SIFT}" == 1 ]]; then
  if [[ "${OS}" != "ubuntu" ]]; then
    warn "SIFT install via cast is supported on Ubuntu/SIFT only; skipping on ${OS}."
  elif command -v cast >/dev/null; then
    log "Installing SIFT via: sudo cast install teamdfir/sift-saltstack"
    sudo cast install teamdfir/sift-saltstack || warn "cast install returned non-zero"
  else
    warn "SIFT full install not run: 'cast' is not installed."
    warn "Prerequisite: install cast first ->"
    warn "  curl -L https://github.com/ekristen/cast/releases/latest/download/cast-linux-amd64 -o /usr/local/bin/cast && chmod +x /usr/local/bin/cast"
    warn "then re-run with --install-sift."
  fi
else
  log "SIFT install skipped (--skip-sift). Probing for existing SIFT core tools..."
fi
FOUND_SIFT="$(detect_sift)"
if [[ "${FOUND_SIFT}" -gt 0 ]]; then
  ok "SIFT core tools detected on PATH: ${FOUND_SIFT}/${#SIFT_CORE[@]}"
else
  warn "No SIFT core tools (vol/log2timeline/psort/yara) on PATH."
  warn "SIFT adapters will raise SiftToolNotFoundError; native tools still work."
fi

# ---- 5. Eric Zimmerman Tools (.NET 9) -------------------------------------
sect "5. Eric Zimmerman Tools (.NET 9)"
if [[ "${DO_EZTOOLS}" == 1 ]]; then
  EZ_DIR="${REPO_ROOT}/bin/zimmerman"
  mkdir -p "${EZ_DIR}"
  command -v unzip >/dev/null || warn "unzip not found; EZ Tools extraction may fail"
  for tool in "${EZ_TOOLS[@]}"; do
    url="${EZ_BASE}/${tool}.zip"
    # Validate the URL with a real request before downloading.
    code="$(curl -s -o /dev/null -w '%{http_code}' -I "${url}" || echo 000)"
    if [[ "${code}" != "200" ]]; then
      warn "${tool}: ${url} returned HTTP ${code}; skipping"
      continue
    fi
    log "Fetching ${tool} (.NET 9) ..."
    if curl -fsSL "${url}" -o "${EZ_DIR}/${tool}.zip"; then
      unzip -oq "${EZ_DIR}/${tool}.zip" -d "${EZ_DIR}/${tool}" || warn "${tool}: unzip failed"
      ok "${tool} staged -> ${EZ_DIR}/${tool}/"
    else
      warn "${tool}: download failed"
    fi
  done
  # Print env-var overrides for the adapters that consume these binaries.
  echo ""
  log "Export these so dart_mcp SIFT adapters find the staged EZ Tools:"
  declare -A EZ_ENV=(
    [EvtxECmd]=DART_EVTXECMD_BIN [MFTECmd]=DART_MFTECMD_BIN [PECmd]=DART_PECMD_BIN
    [RECmd]=DART_RECMD_BIN [AmcacheParser]=DART_AMCACHEPARSER_BIN [SBECmd]=DART_SBECMD_BIN
  )
  for tool in "${EZ_TOOLS[@]}"; do
    bin="$(find "${EZ_DIR}/${tool}" -maxdepth 2 -iname "${tool}*" -type f 2>/dev/null | head -1 || true)"
    [[ -n "${bin}" ]] && printf "  export %s=%s\n" "${EZ_ENV[$tool]}" "${bin}"
  done
else
  log "EZ Tools staging skipped (--skip-eztools). Source: ${EZ_BASE}/<TOOL>.zip"
fi

# ---- 6. healthcheck --------------------------------------------------------
sect "6. Healthcheck (API-free)"
if python3 scripts/healthcheck.py; then
  :
else
  warn "Healthcheck reported issues above; review before running live."
fi

sect "Install complete"
cat <<'EOF'

Next steps:
  1. export ANTHROPIC_API_KEY='sk-...'
  2. python3 run_eval.py --case self-evaluation/case-01

Docs:
  README          quickstart + architecture
  CHANGELOG       release history
  Wiki            https://github.com/Juwon1405/agentic-dart/wiki
EOF
