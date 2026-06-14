#!/usr/bin/env bash
# =============================================================================
# Agentic-DART installer — complete, idempotent, quiet.
#
#   bash scripts/install.sh
#
# That's it. No flags to remember. Every run:
#   - pulls the latest agentic-dart + collector adapter (clones if missing)
#   - installs Python packages, Velociraptor, the SIFT toolchain (yara /
#     Volatility3 / Plaso), and Eric Zimmerman Tools
#   - checks each piece first and SKIPS whatever is already working
#   - shows one clean line per step (progress + ✓ / ✗), and only dumps a log
#     when something actually fails
#
# Re-running is always safe. The only option is --help.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADAPTER_DIR="$(cd "${REPO_ROOT}/.." && pwd)/agentic-dart-collector-adapter"
REPO_URL="https://github.com/Juwon1405/agentic-dart.git"
ADAPTER_URL="https://github.com/Juwon1405/agentic-dart-collector-adapter.git"
EZ_BASE="https://download.ericzimmermanstools.com/net9"
EZ_TOOLS=(EvtxECmd MFTECmd PECmd RECmd AmcacheParser SBECmd)
LOGDIR="$(mktemp -d /tmp/dart-install.XXXXXX)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

# ---- pretty output ---------------------------------------------------------
BOLD=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; RED=$'\033[31m'
YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
STEP=0
TOTAL=9
WARNINGS=0

# run_step "Label" cmd args...  — runs quietly, prints one line.
# Captures all output to a per-step log; on failure prints the tail.
run_step() {
  local label="$1"; shift
  STEP=$((STEP+1))
  local logf="${LOGDIR}/step-${STEP}.log"
  printf "${CYN}[%d/%d]${RST} %-34s" "${STEP}" "${TOTAL}" "${label}"
  local start; start=$(date +%s)
  if "$@" >"${logf}" 2>&1; then
    local dur=$(( $(date +%s) - start ))
    printf " ${GRN}✓${RST} ${DIM}(%ds)${RST}\n" "${dur}"
    return 0
  else
    printf " ${RED}✗ FAILED${RST}\n"
    printf "      ${DIM}└─ %s (last 20 lines):${RST}\n" "${logf}"
    tail -20 "${logf}" | sed 's/^/      /'
    return 1
  fi
}

# A step that's already satisfied — no work, just say so.
skip_step() {
  local label="$1"; local why="$2"
  STEP=$((STEP+1))
  printf "${CYN}[%d/%d]${RST} %-34s ${GRN}✓${RST} ${DIM}%s${RST}\n" \
    "${STEP}" "${TOTAL}" "${label}" "${why}"
}

note() { printf "      ${DIM}%s${RST}\n" "$*"; }
warn() { printf "      ${YEL}! %s${RST}\n" "$*"; WARNINGS=$((WARNINGS+1)); }
have() { command -v "$1" >/dev/null 2>&1; }

# pip/apt wrappers that stay quiet (output goes to the step log via run_step).
_pip() { python3 -m pip install -q "$@" 2>/dev/null || python3 -m pip install -q --break-system-packages "$@"; }
_apt() { sudo apt-get install -y -qq "$@"; }

printf "\n${BOLD}Agentic-DART installer${RST}  ${DIM}(idempotent — skips what already works)${RST}\n\n"

# ---- 1. repositories (FIRST — pull latest before anything else) ------------
update_repos() {
  # self
  if [[ -d "${REPO_ROOT}/.git" ]]; then
    git -C "${REPO_ROOT}" pull --ff-only || echo "self pull skipped"
  fi
  # adapter: clone if missing, else pull
  if [[ -d "${ADAPTER_DIR}/.git" ]]; then
    git -C "${ADAPTER_DIR}" pull --ff-only
  else
    git clone --depth 1 "${ADAPTER_URL}" "${ADAPTER_DIR}"
  fi
}
run_step "Repositories (pull/clone)" update_repos || true

# ---- 2. OS base packages ---------------------------------------------------
os_base() {
  if have apt-get; then
    sudo apt-get update -qq || true
    _apt python3 python3-pip git curl unzip
  elif have dnf; then sudo dnf install -y -q python3 python3-pip git curl unzip
  elif have yum; then sudo yum install -y -q python3 python3-pip git curl unzip
  elif have brew; then brew install python git curl
  else echo "no known package manager"; return 1; fi
}
if have python3 && have git && have curl && have unzip; then
  skip_step "OS base packages" "already present"
else
  run_step "OS base packages" os_base || true
fi

# ---- 3. Python packages ----------------------------------------------------
py_pkgs() {
  _pip -r "${REPO_ROOT}/requirements.txt"
  _pip -e "${REPO_ROOT}/dart_audit" \
       -e "${REPO_ROOT}/dart_mcp[stdio]" \
       -e "${REPO_ROOT}/dart_corr" \
       -e "${REPO_ROOT}/dart_agent[live]"
}
run_step "Agentic-DART Python packages" py_pkgs || true

# ---- 4. collector adapter --------------------------------------------------
adapter_pkg() {
  [[ -d "${ADAPTER_DIR}" ]] || { echo "adapter dir missing"; return 1; }
  _pip -e "${ADAPTER_DIR}"
}
run_step "Collector adapter package" adapter_pkg || true

# ---- 5. Velociraptor (staged + SHA-256 verified by adapter installer) ------
velo_stage() {
  ( cd "${ADAPTER_DIR}" && bash scripts/install.sh --install-dir "${ADAPTER_DIR}/bin" )
  # ensure a stable 'velociraptor' symlink next to the versioned binary
  local versioned
  versioned="$(ls "${ADAPTER_DIR}"/bin/velociraptor-v* 2>/dev/null | head -1 || true)"
  if [[ -n "${versioned}" && ! -e "${ADAPTER_DIR}/bin/velociraptor" ]]; then
    ln -sf "$(basename "${versioned}")" "${ADAPTER_DIR}/bin/velociraptor"
  fi
}
if have velociraptor; then
  skip_step "Velociraptor" "on PATH: $(command -v velociraptor)"
elif [[ -x "${ADAPTER_DIR}/bin/velociraptor" ]]; then
  skip_step "Velociraptor" "already staged"
elif [[ -x "${ADAPTER_DIR}/scripts/install.sh" ]]; then
  run_step "Velociraptor (download+verify)" velo_stage || true
else
  skip_step "Velociraptor" "adapter installer absent — skipped"
fi

# ---- 6. yara ---------------------------------------------------------------
if have yara; then
  skip_step "yara" "already present"
else
  if have apt-get; then run_step "yara (apt)" _apt yara || true
  elif have brew; then run_step "yara (brew)" brew install yara || true
  else skip_step "yara" "no package manager — skipped"; fi
fi

# ---- 7. Volatility 3 + Plaso ----------------------------------------------
if have vol && have log2timeline.py && have psort.py; then
  skip_step "Volatility3 + Plaso" "already present"
else
  vol_plaso() {
    have vol || _pip volatility3
    { have log2timeline.py && have psort.py; } || _pip plaso
  }
  run_step "Volatility3 + Plaso (pip)" vol_plaso || true
fi

# ---- 8. Eric Zimmerman Tools (staged into bin/zimmerman, auto-discovered) --
ez_stage() {
  local EZ_DIR="${REPO_ROOT}/bin/zimmerman"
  mkdir -p "${EZ_DIR}"
  have unzip || { echo "unzip missing"; return 1; }
  local got=0
  for tool in "${EZ_TOOLS[@]}"; do
    # idempotent: skip if already staged + executable
    if compgen -G "${EZ_DIR}/${tool}/${tool}" >/dev/null 2>&1; then got=$((got+1)); continue; fi
    local url="${EZ_BASE}/${tool}.zip"
    local code; code="$(curl -s -o /dev/null -w '%{http_code}' -I "${url}" || echo 000)"
    [[ "${code}" == "200" ]] || { echo "${tool}: HTTP ${code}"; continue; }
    if curl -fsSL "${url}" -o "${EZ_DIR}/${tool}.zip"; then
      unzip -oq "${EZ_DIR}/${tool}.zip" -d "${EZ_DIR}/${tool}" && rm -f "${EZ_DIR}/${tool}.zip"
      find "${EZ_DIR}/${tool}" -maxdepth 2 -iname "${tool}*" -type f -exec chmod +x {} \; 2>/dev/null || true
      got=$((got+1))
    fi
  done
  echo "staged ${got}/${#EZ_TOOLS[@]} EZ tools"
  [[ "${got}" -gt 0 ]]
}
# already-staged check
_ez_dir="${REPO_ROOT}/bin/zimmerman"
_ez_have=0
for t in "${EZ_TOOLS[@]}"; do compgen -G "${_ez_dir}/${t}/${t}" >/dev/null 2>&1 && _ez_have=$((_ez_have+1)); done
if [[ "${_ez_have}" -eq "${#EZ_TOOLS[@]}" ]]; then
  skip_step "Eric Zimmerman Tools" "already staged (${_ez_have}/${#EZ_TOOLS[@]})"
else
  run_step "Eric Zimmerman Tools" ez_stage || true
fi

# ---- 9. healthcheck --------------------------------------------------------
run_step "Healthcheck" python3 "${REPO_ROOT}/scripts/healthcheck.py" || true

# ---- final: tool availability (always shown, never fails) ------------------
printf "\n${BOLD}SIFT adapter tools${RST}\n"
python3 "${REPO_ROOT}/scripts/check_sift_tools.py" 2>/dev/null | sed -n '1,13p' || true

rm -rf "${LOGDIR}" 2>/dev/null || true

printf "\n${BOLD}Done.${RST}"
[[ "${WARNINGS}" -gt 0 ]] && printf " ${YEL}(%d warning(s) above)${RST}" "${WARNINGS}"
printf "\n  Next: ${DIM}export ANTHROPIC_API_KEY='sk-ant-...' && python3 run_eval.py --case self-evaluation/case-01${RST}\n\n"
