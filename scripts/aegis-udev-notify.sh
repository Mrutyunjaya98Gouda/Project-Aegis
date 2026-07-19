#!/bin/bash
# Aegis USB Event Notification Script
# Called by udev rules to notify the daemon of USB events.
# Install: sudo cp aegis-udev-notify.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/aegis-udev-notify.sh

SOCKET="/tmp/aegis.sock"
ACTION="$1"
KERNEL="$2"
VENDOR_ID="$3"
MODEL_ID="$4"
SERIAL="$5"
DEVPATH="$6"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build JSON payload.
JSON=$(cat <<EOF
{"id":"$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)","payload":{"type":"device_event","action":"${ACTION}","kernel":"${KERNEL}","vendor_id":"${VENDOR_ID}","model_id":"${MODEL_ID}","serial":"${SERIAL}","devpath":"${DEVPATH}","timestamp":"${TIMESTAMP}"}}
EOF
)

# Send to daemon socket if it exists.
if [ -S "$SOCKET" ]; then
    echo "$JSON" | socat - UNIX-CONNECT:"$SOCKET" 2>/dev/null
fi

# Log the event regardless.
logger -t aegis-udev "USB ${ACTION}: kernel=${KERNEL} vid=${VENDOR_ID} pid=${MODEL_ID} serial=${SERIAL}"
