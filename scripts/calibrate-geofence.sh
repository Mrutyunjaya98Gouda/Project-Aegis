#!/usr/bin/env bash
# Geofence Calibration Script for Aegis USB Sentinel
# This script helps administrators map physical USB ports to logical geofence locations (e.g. FrontPanel, RearIO).

set -e

CONFIG_FILE=${1:-/etc/aegis/aegis.toml}

echo "=== Aegis Geofence Calibration ==="
echo "This tool will help you map your physical USB ports."
echo "Please unplug any removable USB devices you want to calibrate."
read -p "Press Enter when ready..."

echo "Please insert a USB drive into a FRONT PANEL port now..."

# Wait for a udev add event
PORT_PATH=$(udevadm monitor --environment --udev --subsystem-match=usb | grep -m 1 "DEVPATH" | grep -oP '(?<=DEVPATH=/devices/pci.*/usb[0-9]/).*(?=/)' || echo "")

if [ -z "$PORT_PATH" ]; then
    echo "Timeout or error detecting device."
    exit 1
fi

echo "Detected device on port: $PORT_PATH"
read -p "What location is this port? [FrontPanel/RearIO/Hub] (Default: FrontPanel): " LOC
LOC=${LOC:-FrontPanel}

echo "Adding rule to configure port $PORT_PATH as $LOC..."
# Note: A real implementation would parse and update the TOML cleanly using a tool like yq or a small python script.
# For now, append a note to the admin to add this to the config.

cat <<EOF

Calibration successful. Please add the following to your $CONFIG_FILE:

[policy.geofence_rules."$PORT_PATH"]
location = "$LOC"
allowed = true # Set to false to block
EOF

echo "Calibration complete."
