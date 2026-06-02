#!/usr/bin/env bash
set -euo pipefail

# Sentri OT -- Update Script
# Pulls latest code, rebuilds if needed, restarts service

INSTALL_DIR="/opt/sentri-ot"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- Pre-flight ---
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    log_error "Not a git repository: $INSTALL_DIR"
    exit 1
fi

cd "$INSTALL_DIR"

# --- Check for updates ---
log_info "Checking for updates..."
git fetch origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{upstream} 2>/dev/null || echo "")

if [[ "$LOCAL" == "$REMOTE" ]]; then
    log_info "Already up to date."
    if systemctl is-active --quiet sentri-ot 2>/dev/null; then
        log_info "Service is running. No action needed."
    fi
    exit 0
fi

# --- Pull changes ---
log_info "Pulling latest code..."
git pull

# --- Detect changes ---
CHANGED_FILES=$(git diff --name-only HEAD@{1} HEAD 2>/dev/null || echo "")
NEED_FRONTEND=false
NEED_BACKEND=false

for file in $CHANGED_FILES; do
    case "$file" in
        frontend/*)  NEED_FRONTEND=true ;;
        backend/requirements.txt) NEED_BACKEND=true ;;
        backend/*)   NEED_BACKEND=true ;;
    esac
done

# --- Rebuild frontend if needed ---
if [[ "$NEED_FRONTEND" == true ]]; then
    log_info "Frontend changes detected. Rebuilding..."
    if command -v npm &>/dev/null && [[ -f "$INSTALL_DIR/frontend/package.json" ]]; then
        cd "$INSTALL_DIR/frontend"
        npm ci
        npm run build
        log_info "Frontend rebuilt successfully."
    else
        log_warn "npm not found. Skipping frontend build."
    fi
fi

# --- Update Python deps if needed ---
if [[ "$NEED_BACKEND" == true ]]; then
    log_info "Backend changes detected. Updating dependencies..."
    if [[ -f "$INSTALL_DIR/venv/bin/pip" ]]; then
        source "$INSTALL_DIR/venv/bin/activate"
        pip install --quiet --upgrade pip
        pip install --quiet -r "$INSTALL_DIR/backend/requirements.txt"
        log_info "Python dependencies updated."
    fi
fi

# --- Restart service ---
log_info "Restarting sentri-ot service..."
if systemctl is-active --quiet sentri-ot 2>/dev/null; then
    systemctl restart sentri-ot
    log_info "Service restarted successfully."
else
    log_warn "Service not running. Start with: sudo systemctl start sentri-ot"
fi

cd "$INSTALL_DIR"
log_info "Update complete. Current commit: $(git rev-parse --short HEAD)"
