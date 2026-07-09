#!/bin/bash
set -e

echo "╔══════════════════════════════════════════╗"
echo "║   PROJECT AEGIS — Full Stack Launcher    ║"
echo "╚══════════════════════════════════════════╝"

# Ensure we're in the project root
cd "$(dirname "$0")"

# 1. Kill any existing instances to prevent port/socket collisions
pkill -f "aegis-daemon" || true
rm -f /tmp/aegis.sock 2>/dev/null

echo "Select Launch Mode:"
echo "1) Launch Desktop App / GUI (Full Stack)"
echo "2) Launch Terminal Interface (Headless Daemon)"
read -p "Select option [1/2]: " choice

echo ""
echo "=> [1/4] Compiling Rust Workspace..."
cargo build

if [ "$choice" == "2" ]; then
    echo "=> [2/4] Starting Aegis Security Daemon in Terminal Mode..."
    echo "=========================================================="
    # Run fully in the foreground so the terminal becomes the interface
    cargo run -p aegis-daemon
    exit 0
fi

echo "=> [2/4] Starting Aegis Security Daemon (Background)..."
cargo run -p aegis-daemon &
DAEMON_PID=$!

# Ensure the background daemon is gracefully killed when the user closes the UI
trap 'echo "=> [4/4] UI Closed. Terminating background Aegis Daemon..."; kill -INT $DAEMON_PID 2>/dev/null; exit' EXIT INT TERM

echo "=> [3/4] Waiting for IPC socket (/tmp/aegis.sock) to initialize..."
for i in {1..60}; do
    if [ -S /tmp/aegis.sock ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S /tmp/aegis.sock ]; then
    echo "❌ Error: Daemon failed to bind /tmp/aegis.sock within 30 seconds."
    exit 1
fi

echo "=> ✅ IPC Socket bound!"
echo "=> [4/4] Launching Tauri Dashboard UI..."

cd aegis-ui
npm run tauri dev
