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
# We refuse to run under sudo (see the EUID check below), so pip always runs as
# your normal user — no SUDO_USER juggling needed. Try a plain install first,
# fall back to --break-system-packages for PEP-668 'externally managed' envs.
_pip() {
  python3 -m pip install -q "$@" 2>/dev/null \
    || python3 -m pip install -q --break-system-packages "$@"
}
_apt() { sudo apt-get install -y -qq "$@"; }

printf "\n${BOLD}Agentic-DART installer${RST}  ${DIM}(idempotent — skips what already works)${RST}\n\n"

# Do NOT run this under sudo. Running as root makes pip/healthcheck resolve
# against root's environment instead of yours (why step 9 reports deps "missing"
# even when they're installed for your user), and leaves root-owned files in the
# repo (which then breaks `git pull` with a permission error). yara — the only
# thing that ever wanted root — is handled without it now. So we refuse outright.
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  printf "${RED}✗ Do not run this installer with sudo / as root.${RST}\n\n" >&2
  printf "  Running as root resolves packages against root's environment (not\n" >&2
  printf "  yours), and leaves root-owned files in the repo that break ${BOLD}git pull${RST}.\n" >&2
  printf "  Nothing here needs root — yara is staged without it.\n\n" >&2
  printf "  Run it as your normal user:\n" >&2
  printf "      ${BOLD}bash scripts/install.sh${RST}\n\n" >&2
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf "  ${DIM}(If a previous sudo run already left root-owned files, fix them with:\n" >&2
    printf "   sudo chown -R ${SUDO_USER} . )${RST}\n\n" >&2
  fi
  exit 1
fi

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
# Show what HEAD is now on, so you can see at a glance you're on the latest
# commit without having to run `git log` yourself.
if [[ -d "${REPO_ROOT}/.git" ]]; then
  note "HEAD: $(git -C "${REPO_ROOT}" log --oneline -1 2>/dev/null)"
fi

# ---- 2. OS base packages ---------------------------------------------------
# Linux only (Ubuntu/SIFT is the supported target; RHEL/CentOS/Fedora work via
# dnf/yum). sleuthkit (mmls/tsk_recover) and ewf-tools (ewfmount) are needed to
# turn raw whole-disk images / E01s into an evidence tree for the external
# benchmark cases. macOS is intentionally unsupported (see README): the Plaso /
# libyal toolchain doesn't build cleanly there, so we don't pretend to install
# it.
os_base() {
  if have apt-get; then
    sudo apt-get update -qq || true
    _apt python3 python3-pip git curl unzip sleuthkit ewf-tools
  elif have dnf; then
    sudo dnf install -y -q python3 python3-pip git curl unzip sleuthkit libewf-tools
  elif have yum; then
    sudo yum install -y -q python3 python3-pip git curl unzip sleuthkit libewf-tools
  else
    echo "no supported Linux package manager (need apt-get, dnf, or yum)"
    return 1
  fi
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
# Skip the pip pass entirely if all four packages already import — pip would
# otherwise spend ~40s re-resolving an already-satisfied environment.
if python3 -c "import dart_audit, dart_mcp, dart_corr, dart_agent" 2>/dev/null; then
  skip_step "Agentic-DART Python packages" "already importable"
else
  run_step "Agentic-DART Python packages" py_pkgs || true
fi

# ---- 4. collector adapter --------------------------------------------------
adapter_pkg() {
  [[ -d "${ADAPTER_DIR}" ]] || { echo "adapter dir missing"; return 1; }
  _pip -e "${ADAPTER_DIR}"
}
if python3 -c "import dart_collector_adapter" 2>/dev/null; then
  skip_step "Collector adapter package" "already importable"
elif [[ -d "${ADAPTER_DIR}" ]]; then
  run_step "Collector adapter package" adapter_pkg || true
else
  skip_step "Collector adapter package" "adapter dir absent — skipped"
fi

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
# Resolve yara the same way the adapters do (DART_YARA_BIN -> PATH -> repo
# bin/), so this step and the availability table can't disagree.
#
# KEY INSIGHT (the bug you hit): yara can be INSTALLED but invisible to this
# account — e.g. it's at /usr/bin/yara (root sees it) but the user's PATH or
# shutil.which doesn't surface it. That's an environment problem, not an
# install problem. So we STAGE FIRST: scan the standard system locations
# directly (PATH-independent) and symlink whatever we find into repo bin/,
# where the adapter's _search_repo_bins() finds it with zero PATH/env setup.
# Only if nothing exists anywhere do we fall back to installing. This also
# fixes the old ordering bug where a failed 'apt-get install' short-circuited
# the staging step, leaving an already-present yara unused.
yara_adapter_path() {
  python3 - <<'PY' 2>/dev/null
import sys
sys.path.insert(0, "dart_mcp/src")
try:
    from dart_mcp.sift_adapters._common import _which
    print(_which("yara", env_var="DART_YARA_BIN"))
except Exception:
    sys.exit(1)
PY
}
_find_yara_binary() {
  # Look everywhere a yara binary could be, independent of this shell's PATH.
  local c
  c="$(command -v yara 2>/dev/null || true)"
  if [[ -n "${c}" && -x "${c}" ]]; then echo "${c}"; return 0; fi
  for c in /usr/bin/yara /usr/local/bin/yara /bin/yara /sbin/yara \
           /opt/yara/bin/yara /snap/bin/yara /usr/sbin/yara; do
    [[ -x "${c}" ]] && { echo "${c}"; return 0; }
  done
  # last resort: a filesystem search of common prefixes (bounded, fast)
  c="$(find /usr /opt /snap -maxdepth 4 -name yara -type f -perm -u+x 2>/dev/null | head -1)"
  [[ -n "${c}" ]] && { echo "${c}"; return 0; }
  return 1
}
_stage_yara_into_bin() {
  # Symlink a real yara binary into repo bin/ so _search_repo_bins() finds it
  # regardless of PATH or env. Returns 0 if a binary was staged.
  local found
  found="$(_find_yara_binary)" || return 1
  mkdir -p "${REPO_ROOT}/bin"
  ln -sf "${found}" "${REPO_ROOT}/bin/yara"
  return 0
}
_yara_try_install() {
  # Best-effort install when yara is genuinely absent. sudo only if available
  # AND passwordless; refresh the index first; keep output (no -qq) so the log
  # is useful.
  local SUDO=""
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then SUDO="sudo"; fi
  if command -v apt-get >/dev/null 2>&1; then
    ${SUDO} apt-get update -y || true
    ${SUDO} apt-get install -y yara || return 1
  elif command -v brew >/dev/null 2>&1; then
    brew install yara || return 1
  elif command -v dnf >/dev/null 2>&1; then
    ${SUDO} dnf install -y yara || return 1
  else
    echo "no supported package manager (apt-get/brew/dnf) for yara"; return 1
  fi
}

STEP=$((STEP+1))
ylog="${LOGDIR}/step-${STEP}.log"
if yara_adapter_path >/dev/null; then
  printf "${CYN}[%d/%d]${RST} %-34s ${GRN}✓${RST} ${DIM}adapter resolves: %s${RST}\n" \
    "${STEP}" "${TOTAL}" "yara" "$(yara_adapter_path)"
elif _stage_yara_into_bin >"${ylog}" 2>&1 && yara_adapter_path >/dev/null; then
  # yara existed on the box but wasn't visible to the adapter — staged it.
  printf "${CYN}[%d/%d]${RST} %-34s ${GRN}✓${RST} ${DIM}staged into bin/: %s${RST}\n" \
    "${STEP}" "${TOTAL}" "yara" "$(yara_adapter_path)"
else
  # genuinely absent — try to install, then stage + verify.
  printf "${CYN}[%d/%d]${RST} %-34s" "${STEP}" "${TOTAL}" "yara (optional)"
  if { _yara_try_install && _stage_yara_into_bin; yara_adapter_path >/dev/null; } \
       >>"${ylog}" 2>&1; then
    printf " ${GRN}✓${RST} ${DIM}installed: %s${RST}\n" "$(yara_adapter_path)"
  else
    printf " ${YEL}! skipped${RST}\n"
    note "yara not found anywhere on this system, and install didn't succeed."
    note "sift_yara_scan_* will fall back to native tools (analysis is unaffected)."
    note "to enable: sudo apt-get install yara, then re-run — it'll be auto-staged."
    WARNINGS=$((WARNINGS+1))
  fi
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

# Keep the per-step logs around if anything failed or warned, so the paths
# printed above (…/step-N.log) are still readable for debugging. Only clean up
# on a fully clean run.
if [[ "${WARNINGS}" -gt 0 ]]; then
  printf "\n${DIM}Step logs kept for inspection in: %s${RST}\n" "${LOGDIR}"
else
  rm -rf "${LOGDIR}" 2>/dev/null || true
fi

printf "\n${BOLD}Done.${RST}"
[[ "${WARNINGS}" -gt 0 ]] && printf " ${YEL}(%d warning(s) above)${RST}" "${WARNINGS}"
printf "\n"

# ---- external benchmark images: offer to download now ----------------------
# External (full-disk public images) is a first-class half of the benchmark,
# not an afterthought. A fresh install usually means you intend to test, and the
# images aren't huge — so offer to pull them all now. Pressing 'y' finishes
# SETUP (download + the images sit ready under datasets/); it does NOT run any
# analysis. Pressing 'n' just ends here; you can fetch them later.
_DATASETS_DIR="${REPO_ROOT}/datasets"
_EXT_GB="13.1"   # cfreds 5.0 + hadi 2.9 + m57 5.2 (approx)
# Show current free space on the target filesystem.
_FREE_HUMAN="$(df -h "${REPO_ROOT}" 2>/dev/null | awk 'NR==2{print $4}')"
printf "\n${BOLD}External benchmark images${RST}\n"
printf "  The external cases (NIST CFReDS, Ali Hadi, M57) run on real full-disk\n"
printf "  images. Downloading all of them adds ${BOLD}~%s GB${RST}.\n" "${_EXT_GB}"
printf "  Free space on this filesystem right now: ${BOLD}%s${RST}\n" "${_FREE_HUMAN:-unknown}"
printf "  (Pressing y only DOWNLOADS them — no analysis runs. You can skip and\n"
printf "   fetch later with: ${DIM}python3 -m scripts.eval.download all datasets/${RST})\n\n"
if [[ -t 0 ]]; then
  read -r -p "  Download the external images now? [y/N] " _dl_ans
else
  _dl_ans="n"   # non-interactive (piped) install: don't block, default no
  printf "  (non-interactive install — skipping download; fetch later as above)\n"
fi
if [[ "${_dl_ans}" =~ ^[Yy]$ ]]; then
  printf "\n  Downloading external images to %s ...\n" "${_DATASETS_DIR}"
  python3 -m scripts.eval.download all "${_DATASETS_DIR}" || \
    printf "  ${YEL}Download had issues; rerun: python3 -m scripts.eval.download all datasets/${RST}\n"
  printf "  ${GRN}Setup complete.${RST} Images are staged; run a benchmark when ready.\n"
fi

# ---- how to run: api key + the four benchmark entry points -----------------
printf "\n${BOLD}Run a benchmark${RST}\n"
printf "  First, set your API key (live mode):\n"
printf "    ${DIM}export ANTHROPIC_API_KEY='sk-ant-...'${RST}\n\n"
printf "  Then pick one:\n"
printf "    ${BOLD}demo${RST}     ${DIM}python3 -m scripts.eval.demo${RST}\n"
printf "             deterministic taster — no key, proves the rig stands up.\n"
printf "    ${BOLD}self${RST}     ${DIM}python3 -m scripts.eval.self     --models claude-haiku-4-5-20251001${RST}\n"
printf "             8 bundled cases with ready evidence (fast, no images).\n"
printf "    ${BOLD}external${RST} ${DIM}python3 -m scripts.eval.external --models claude-haiku-4-5-20251001${RST}\n"
printf "             full-disk public images (downloads + adapts if missing).\n"
printf "\n  Multiple models? Append them: ${DIM}--models claude-haiku-4-5-20251001 claude-sonnet-4-6 claude-opus-4-8${RST}\n"
printf "  Results: ${DIM}docs/benchmarks/SUMMARY.md${RST} (latest) + ${DIM}HISTORY.md${RST} (trend over time)\n\n"

# ---- persistent shell aliases (idempotent) ---------------------------------
# dart-pull = pull latest; dart-auth = show oauth/api credential status.
# Re-running the installer updates these in place (grep -v old line, append
# current) instead of duplicating — and grep -v sidesteps sed escaping when the
# alias body contains '&'.
_install_alias() {
  local _name="$1" _body="$2" _rc="${HOME}/.bashrc"
  touch "${_rc}"
  grep -vE "^alias ${_name}=" "${_rc}" > "${_rc}.dart.tmp" 2>/dev/null || true
  mv "${_rc}.dart.tmp" "${_rc}"
  printf "alias %s='%s'\n" "${_name}" "${_body}" >> "${_rc}"
}
_install_alias dart-pull "cd ${REPO_ROOT} && git pull && cd ${ADAPTER_DIR} && git pull && cd ${REPO_ROOT}"
_install_alias dart-auth "python3 ${REPO_ROOT}/dart_agent/src/dart_agent/auth.py"
printf "${BOLD}Shell aliases${RST} (written to ~/.bashrc)\n"
printf "  ${GRN}dart-pull${RST}  → cd repo && git pull latest\n"
printf "  ${GRN}dart-auth${RST}  → oauth/api credential status\n"
printf "  Run ${DIM}source ~/.bashrc${RST} or open a new shell to use them now.\n\n"
