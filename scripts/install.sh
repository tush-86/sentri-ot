#!/usr/bin/env bash
set -euo pipefail

# Sentri OT -- Installation Script
# For Raspberry Pi / Linux bare-metal deployment

REPO_URL="https://github.com/tush-86/flying-unicorn.git"
INSTALL_DIR="/opt/sentri-ot"
DATA_DIR="/var/lib/sentri-ot"
SENTRI_USER="sentri"
SENTRI_GROUP="sentri"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- Pre-flight Checks ---
log_info "Checking prerequisites..."

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)."
    exit 1
fi

PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
    log_error "Python 3 not found. Install python3 and python3-venv first."
    exit 1
fi

PY_VER=$($PYTHON --version 2>&1 | awk '{print $2}' | cut -d. -f1-2)
if [[ $(echo "$PY_VER >= 3.12" | bc -l 2>/dev/null || echo 0) -eq 0 ]]; then
    log_warn "Python $PY_VER detected. Python 3.12+ is recommended."
    log_warn "Continuing anyway."
fi

if ! command -v git &>/dev/null; then
    log_error "git not found."
    exit 1
fi

# --- System Dependencies ---
log_info "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential libffi-dev python3-venv python3-dev curl tcpdump tshark nodejs npm 2>/dev/null || true

# --- Create User ---
if id "$SENTRI_USER" &>/dev/null; then
    log_info "User $SENTRI_USER already exists."
else
    log_info "Creating user $SENTRI_USER..."
    addgroup --system "$SENTRI_GROUP"
    adduser --system --ingroup "$SENTRI_GROUP" --home "$INSTALL_DIR" --disabled-password "$SENTRI_USER"
fi

# --- Clone Repository ---
if [[ -d "$INSTALL_DIR/.git" ]]; then
    log_info "Repository exists, pulling latest..."
    cd "$INSTALL_DIR"
    git pull
else
    log_info "Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# --- Python Virtual Environment ---
log_info "Setting up Python venv..."
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    $PYTHON -m venv "$INSTALL_DIR/venv"
fi

source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet -r "$INSTALL_DIR/backend/requirements.txt"

# --- Frontend Build ---
if [[ -f "$INSTALL_DIR/frontend/package.json" ]]; then
    if command -v npm &>/dev/null; then
        log_info "Building frontend..."
        (cd "$INSTALL_DIR/frontend" && npm ci --quiet && npm run build)
    else
        log_warn "npm not found; API will run but the web UI will not be built. Install Node.js/npm and run: cd $INSTALL_DIR/frontend && npm ci && npm run build"
    fi
fi

# --- Data Directory ---
log_info "Creating data directory..."
mkdir -p "$DATA_DIR"
chown -R "$SENTRI_USER:$SENTRI_GROUP" "$DATA_DIR"
chown -R "$SENTRI_USER:$SENTRI_GROUP" "$INSTALL_DIR"

# --- Environment File ---
log_info "Writing environment configuration..."
cat > /etc/default/sentri-ot <<EOF
SENTRI_OT_DB_PATH=$DATA_DIR/sentri_ot.db
SENTRI_OT_SCAN_MODE=passive
SENTRI_OT_BACNET_DISCOVERY=whois
SENTRI_OT_SCAN_INTERVAL=60
SENTRI_OT_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000
# Set this before exposing Sentri OT beyond a trusted lab/LAN:
# SENTRI_OT_API_KEY=change-me
EOF
chmod 640 /etc/default/sentri-ot
chown root:"$SENTRI_GROUP" /etc/default/sentri-ot

# --- Systemd Service ---
log_info "Installing systemd service..."
cp "$INSTALL_DIR/systemd/sentri-ot.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentri-ot.service

# --- Make Scripts Executable ---
chmod +x "$INSTALL_DIR/scripts/"*.sh

# --- Summary ---
echo ""
echo "============================================"
echo -e "${GREEN}  Sentri OT Installation Complete!${NC}"
echo "============================================"
echo ""
echo "  Install directory:  $INSTALL_DIR"
echo "  Data directory:     $DATA_DIR"
echo "  Service name:       sentri-ot"
echo ""
echo "  To start:           sudo systemctl start sentri-ot"
echo "  To stop:            sudo systemctl stop sentri-ot"
echo "  To check status:    sudo systemctl status sentri-ot"
echo "  View logs:          sudo journalctl -u sentri-ot -f"
echo "============================================"
