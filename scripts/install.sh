#!/usr/bin/env bash
# Agentic-DART — One-command deploy on a clean SANS SIFT Workstation OVA
# Usage (from a SIFT Workstation terminal):
#   curl -fsSL https://raw.githubusercontent.com/Juwon1405/agentic-dart/main/scripts/install.sh | bash
#
# Status: SCAFFOLDING — full implementation in progress through June 15, 2026.
# This script currently verifies prerequisites and clones the repo. Module
# installation steps will be populated as each module reaches alpha.

set -euo pipefail

REPO_URL="https://github.com/Juwon1405/agentic-dart.git"
INSTALL_DIR="${HOME}/agentic-dart"
MIN_RAM_GB=16
MIN_DISK_GB=100

log()  { printf '\033[1;34m[agentic-dart]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

log "Bootstrapping Agentic-DART on $(uname -srm)"

# --- Prerequisite checks ---
command -v git >/dev/null    || die "git is required (apt install git)"
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null    || die "curl is required"

PYV=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
log "Python ${PYV} detected"
[[ "${PYV}" =~ ^3\.(1[1-9]|[2-9][0-9])$ ]] || warn "Python 3.11+ recommended; continuing with ${PYV}"

RAM_GB=$(free -g | awk '/^Mem:/ {print $2}')
log "Available RAM: ${RAM_GB} GB"
(( RAM_GB >= MIN_RAM_GB )) || warn "Less than ${MIN_RAM_GB} GB RAM — memory analysis may be slow"

DISK_GB=$(df -BG --output=avail "${HOME}" | tail -1 | tr -dc '0-9')
log "Available disk at \$HOME: ${DISK_GB} GB"
(( DISK_GB >= MIN_DISK_GB )) || warn "Less than ${MIN_DISK_GB} GB disk free at \$HOME"

# --- Anthropic API key ---
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  warn "ANTHROPIC_API_KEY is not set. Export it before running dart-agent."
fi

# --- Clone repo ---
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  log "Updating existing checkout at ${INSTALL_DIR}"
  git -C "${INSTALL_DIR}" pull --ff-only
else
  log "Cloning into ${INSTALL_DIR}"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

# --- Virtualenv ---
if [[ ! -d .venv ]]; then
  log "Creating Python virtualenv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel >/dev/null

# --- Module installs (populated as modules land) ---
# pip install -e ./dart-mcp
# pip install -e ./dart-agent
# pip install -e ./dart-corr
# pip install -e ./dart-audit
log "Module install step reserved — populated as dart-mcp / dart-agent reach alpha"

# --- Claude Code MCP registration (placeholder) ---
# claude mcp add dart-mcp --transport stdio --command dart-mcp-server
log "Claude Code MCP registration reserved — runs after dart-mcp alpha"

log "Bootstrap complete. See docs/troubleshooting.md if anything looks off."
log "Next: export ANTHROPIC_API_KEY and run dart-agent --help"
