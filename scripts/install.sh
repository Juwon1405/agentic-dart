#!/usr/bin/env bash
# Agentic-DART — One-command deploy on a clean SANS SIFT Workstation OVA
#
# Usage (from a SIFT Workstation terminal):
#   curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash
#
# What this script does (v0.5):
#   1. Verifies prerequisites (Python 3.10+, git, curl, RAM, disk)
#   2. Clones agentic-dart into ~/agentic-dart
#   3. Creates an isolated Python venv
#   4. Installs the dart_mcp package (60 typed read-only tools)
#   5. Probes for SIFT Workstation tool binaries (Volatility 3, MFTECmd,
#      EvtxECmd, PECmd, RECmd, AmcacheParser, YARA, Plaso) and prints
#      the env-var overrides needed for any binary not found on PATH
#   6. Runs the tool-registration test to confirm 60 tools are exposed
#   7. Prints next-step commands

set -euo pipefail

REPO_URL="https://github.com/Juwon1405/agentic-dart.git"
INSTALL_DIR="${HOME}/agentic-dart"
MIN_RAM_GB=8
MIN_DISK_GB=20

log()  { printf '\033[1;34m[agentic-dart]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m            %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m         %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m        %s\n' "$*" >&2; exit 1; }
sect() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }

sect "Bootstrapping Agentic-DART on $(uname -srm)"

# --- 1. Prerequisite checks ---
sect "1. Prerequisite checks"
command -v git     >/dev/null || die "git is required (apt install git)"
command -v python3 >/dev/null || die "python3 is required"
command -v curl    >/dev/null || die "curl is required"
ok "git / python3 / curl present"

PYV=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
log "Python ${PYV} detected"
[[ "${PYV}" =~ ^3\.(1[0-9]|[2-9][0-9])$ ]] || warn "Python 3.10+ required; continuing with ${PYV}"

if command -v free >/dev/null; then
  RAM_GB=$(free -g | awk '/^Mem:/ {print $2}')
  log "Available RAM: ${RAM_GB} GB"
  (( RAM_GB >= MIN_RAM_GB )) || warn "Less than ${MIN_RAM_GB} GB RAM"
fi

# --- 2. Clone repo ---
sect "2. Clone agentic-dart"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  log "Updating existing checkout at ${INSTALL_DIR}"
  git -C "${INSTALL_DIR}" pull --ff-only
else
  log "Cloning into ${INSTALL_DIR}"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
fi
cd "${INSTALL_DIR}"
ok "Repo at ${INSTALL_DIR}"

# --- 3. Virtualenv + package install ---
sect "3. Python virtualenv + package install"
if [[ ! -d .venv ]]; then
  log "Creating Python virtualenv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel >/dev/null
log "Installing dart_mcp package (editable)"
pip install -e ./dart_mcp/ >/dev/null
ok "dart_mcp installed in venv"

# --- 4. SIFT Workstation tool detection ---
sect "4. SIFT Workstation tool detection"
log "Probing PATH for SIFT-bundled tool binaries..."

# Tool binary -> override env var name (for fall-back instructions)
SIFT_BINARIES=(
  "vol|DART_VOLATILITY3_BIN|Volatility 3 (memory forensics, 12 plugins)"
  "MFTECmd|DART_MFTECMD_BIN|Eric Zimmerman MFT parser"
  "EvtxECmd|DART_EVTXECMD_BIN|Eric Zimmerman EVTX parser"
  "PECmd|DART_PECMD_BIN|Eric Zimmerman Prefetch parser"
  "RECmd|DART_RECMD_BIN|Eric Zimmerman Registry parser"
  "AmcacheParser|DART_AMCACHEPARSER_BIN|Eric Zimmerman Amcache parser"
  "yara|DART_YARA_BIN|YARA signature matcher"
  "log2timeline.py|DART_LOG2TIMELINE_BIN|Plaso log2timeline"
  "psort.py|DART_PSORT_BIN|Plaso psort"
)

FOUND=0
MISSING=0
MISSING_LIST=()

for entry in "${SIFT_BINARIES[@]}"; do
  binary="${entry%%|*}"
  rest="${entry#*|}"
  envvar="${rest%%|*}"
  desc="${rest#*|}"

  if command -v "${binary}" >/dev/null 2>&1; then
    found_at=$(command -v "${binary}")
    ok "${binary} → ${found_at}"
    FOUND=$((FOUND+1))
  else
    warn "${binary} NOT on PATH (${desc})"
    MISSING_LIST+=("${envvar}|${binary}|${desc}")
    MISSING=$((MISSING+1))
  fi
done

echo ""
log "SIFT tool detection summary: ${FOUND} found, ${MISSING} missing"

if (( MISSING > 0 )); then
  echo ""
  warn "Missing binaries — add these env-var overrides to ~/.bashrc if installed elsewhere:"
  for entry in "${MISSING_LIST[@]}"; do
    envvar="${entry%%|*}"
    rest="${entry#*|}"
    binary="${rest%%|*}"
    desc="${rest#*|}"
    printf "  export %-30s=/path/to/%-22s # %s\n" "${envvar}" "${binary}" "${desc}"
  done
  echo ""
  warn "Adapters whose binary is missing will raise SiftToolNotFoundError when called."
  warn "The agent loop will fall back to native pure-Python tools where possible."
  warn "To install the SIFT toolchain see:"
  warn "  https://github.com/teamdfir/sift-saltstack"
  warn "  https://ericzimmerman.github.io/  (Eric Zimmerman tool kit)"
fi

# --- 5. Tool registration test ---
sect "5. Verify MCP tool registration (60 tools expected)"
TOOL_COUNT=$(python3 -c "
import os
os.environ.setdefault('DART_EVIDENCE_ROOT', '/tmp/dart-bootstrap-evidence')
os.makedirs('/tmp/dart-bootstrap-evidence', exist_ok=True)
from dart_mcp import list_tools
tools = list_tools()
native = [t for t in tools if not t['name'].startswith('sift_')]
sift = [t for t in tools if t['name'].startswith('sift_')]
print(f'{len(tools)}|{len(native)}|{len(sift)}')
")

TOTAL="${TOOL_COUNT%%|*}"
REST="${TOOL_COUNT#*|}"
NATIVE="${REST%|*}"
SIFT="${REST##*|}"

if [[ "${TOTAL}" == "60" && "${NATIVE}" == "35" && "${SIFT}" == "25" ]]; then
  ok "MCP surface verified: ${NATIVE} native + ${SIFT} SIFT adapters = ${TOTAL} tools"
else
  warn "Tool count drift: total=${TOTAL} native=${NATIVE} sift=${SIFT}"
  warn "(expected 60 / 35 / 25 — check your install)"
fi

# --- 6. Anthropic API key ---
sect "6. Anthropic API key"
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  warn "ANTHROPIC_API_KEY is not set."
  warn "Export it before running live mode:  export ANTHROPIC_API_KEY=sk-ant-..."
else
  ok "ANTHROPIC_API_KEY is set (length: ${#ANTHROPIC_API_KEY})"
fi

# --- 7. Next steps ---
sect "Bootstrap complete"
cat <<'EOF'

Next steps:

  cd ~/agentic-dart
  source .venv/bin/activate

  # Run the offline demo (uses native tools; works without SIFT binaries)
  bash examples/demo-run.sh

  # Run the SIFT adapter demo (requires SIFT binaries on PATH or env-vars set)
  bash examples/sift-adapter-demo.sh

  # Run the full test suite
  for t in tests/test_*.py; do python3 "$t"; done

  # Live mode against Anthropic API
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 -m dart_agent --case my-case --out ./out/my-case --mode live

Documentation:
  README          architecture + judging-criteria alignment
  CHANGELOG       release history
  Wiki            https://github.com/Juwon1405/agentic-dart/wiki
  SIFT adapters   https://github.com/Juwon1405/agentic-dart/wiki/SIFT-adapter-layer

EOF
