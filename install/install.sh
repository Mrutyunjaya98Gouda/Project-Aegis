#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Project Aegis — Production Installer
#  Zero-Trust USB Security Suite
#
#  Usage: sudo bash install/install.sh [--uninstall]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

AEGIS_VERSION="0.1.0"
DAEMON_BIN="target/release/aegis-daemon"
UI_DEB="aegis-ui/src-tauri/target/release/bundle/deb/project-aegis_${AEGIS_VERSION}_amd64.deb"

INSTALL_BIN="/usr/local/bin/aegis-daemon"
INSTALL_CONFIG_DIR="/etc/aegis"
INSTALL_LOG_DIR="/var/log/aegis"
INSTALL_SERVICE="/etc/systemd/system/aegis-daemon.service"
INSTALL_UDEV="/etc/udev/rules.d/99-aegis.rules"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   PROJECT AEGIS v${AEGIS_VERSION} — Installer      ║"
echo "  ║   Zero-Trust USB Security Suite          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── Ensure running as root ──
if [[ "$EUID" -ne 0 ]]; then
    log_error "This installer must be run as root. Try: sudo bash install/install.sh"
fi

# ── Ensure we're in the project root ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# ── Uninstall mode ──
if [[ "${1:-}" == "--uninstall" ]]; then
    log_info "Uninstalling Project Aegis..."

    systemctl stop aegis-daemon 2>/dev/null || true
    systemctl disable aegis-daemon 2>/dev/null || true
    rm -f "$INSTALL_SERVICE"
    rm -f "$INSTALL_BIN"
    rm -f "$INSTALL_UDEV"
    udevadm control --reload-rules 2>/dev/null || true
    systemctl daemon-reload

    log_ok "Project Aegis uninstalled."
    log_warn "Configuration at $INSTALL_CONFIG_DIR and logs at $INSTALL_LOG_DIR were preserved."
    exit 0
fi

# ── Step 1: Build the Rust daemon in release mode ──
log_info "[1/6] Building aegis-daemon (release)..."
cargo build -p aegis-daemon --release 2>&1 | tail -5

if [[ ! -f "$DAEMON_BIN" ]]; then
    log_error "Build failed: $DAEMON_BIN not found."
fi
log_ok "Daemon binary built: $DAEMON_BIN"

# ── Step 2: Install daemon binary ──
log_info "[2/6] Installing daemon binary to $INSTALL_BIN..."
install -m 755 "$DAEMON_BIN" "$INSTALL_BIN"
log_ok "Binary installed."

# ── Step 3: Install configuration ──
log_info "[3/6] Installing configuration to $INSTALL_CONFIG_DIR..."
mkdir -p "$INSTALL_CONFIG_DIR"
chmod 700 "$INSTALL_CONFIG_DIR"
if [[ ! -f "$INSTALL_CONFIG_DIR/aegis.toml" ]]; then
    # Generate a strong random HMAC key
    HMAC_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1 || openssl rand -hex 32)

    sed "s/change-me-in-production-use-a-strong-random-key/${HMAC_KEY}/" \
        config/aegis.toml > "$INSTALL_CONFIG_DIR/aegis.toml"
    # Update log path to production location
    sed -i "s|log_file = \"/tmp/aegis/audit.jsonl\"|log_file = \"/var/log/aegis/audit.jsonl\"|g" \
        "$INSTALL_CONFIG_DIR/aegis.toml"
    chmod 600 "$INSTALL_CONFIG_DIR/aegis.toml"
    log_ok "Config installed with generated HMAC key."
else
    log_warn "Config already exists at $INSTALL_CONFIG_DIR/aegis.toml — skipping (no overwrite)."
    chmod 600 "$INSTALL_CONFIG_DIR/aegis.toml"
fi

# ── Step 4: Create log directory ──
log_info "[4/6] Creating log directory $INSTALL_LOG_DIR..."
mkdir -p "$INSTALL_LOG_DIR"
chmod 700 "$INSTALL_LOG_DIR"
log_ok "Log directory ready."

# ── Step 5: Install udev rules ──
log_info "[5/6] Installing udev rules and notify script..."
cp scripts/aegis-udev-notify.sh /usr/local/bin/aegis-udev-notify.sh
chmod +x /usr/local/bin/aegis-udev-notify.sh
cp rules/99-aegis-usb.rules "$INSTALL_UDEV"
udevadm control --reload-rules
udevadm trigger
log_ok "udev rules installed and reloaded."

# ── Step 6: Install and enable systemd service ──
log_info "[6/6] Installing systemd service..."
cp install/aegis-daemon.service "$INSTALL_SERVICE"
systemctl daemon-reload
systemctl enable aegis-daemon
systemctl restart aegis-daemon

log_ok "Systemd service installed and started."

# ── Status check ──
echo ""
echo "  ══════════════════════════════════════════"
if systemctl is-active --quiet aegis-daemon; then
    log_ok "✅ Project Aegis daemon is RUNNING."
    echo ""
    echo "  Useful commands:"
    echo "    sudo systemctl status aegis-daemon    # Check daemon status"
    echo "    sudo journalctl -u aegis-daemon -f    # Follow daemon logs"
    echo "    sudo systemctl stop aegis-daemon      # Stop the daemon"
    echo ""
    echo "  Config: $INSTALL_CONFIG_DIR/aegis.toml"
    echo "  Logs:   $INSTALL_LOG_DIR/audit.jsonl"
else
    log_warn "⚠️  Daemon may not have started. Check: sudo journalctl -u aegis-daemon -n 50"
fi
echo "  ══════════════════════════════════════════"
echo ""
