#!/bin/bash
# Setup daily auto-update for Phishguard ALL sources on macOS
# Uses launchd (macOS native scheduler) to run auto_update_v2.js daily

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PHISHGUARD_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_NAME="com.phishguard.autoupdate"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
LOG_DIR="$SCRIPT_DIR/logs"
NODE="$(which node)"

if [ -z "$NODE" ]; then
  echo "ERROR: node not found. Please install Node.js first."
  exit 1
fi

mkdir -p "$LOG_DIR"
mkdir -p "$HOME/Library/LaunchAgents"

cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${NODE}</string>
        <string>${SCRIPT_DIR}/auto_update_v2.js</string>
        <string>--sources</string>
        <string>${SCRIPT_DIR}/config/sources.json</string>
        <string>--out</string>
        <string>${PHISHGUARD_DIR}/data/blocklist.json</string>
        <string>--shards_dir</string>
        <string>${PHISHGUARD_DIR}/data/blocklist-shards</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>8</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/auto_update.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/auto_update_error.log</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF

# Unload old agents
launchctl unload "$PLIST_PATH" 2>/dev/null
launchctl unload "$HOME/Library/LaunchAgents/com.phishguard.update165.plist" 2>/dev/null

# Load the new agent
launchctl load "$PLIST_PATH"

echo "Auto-update scheduled!"
echo "  Schedule: Daily at 8:00 AM"
echo "  Script: ${SCRIPT_DIR}/auto_update_v2.js"
echo "  Sources: ${SCRIPT_DIR}/config/sources.json"
echo "  Output: ${PHISHGUARD_DIR}/data/blocklist-shards/"
echo "  Logs: ${LOG_DIR}/"
echo "  Plist: ${PLIST_PATH}"
echo ""
echo "To manually run:"
echo "  node ${SCRIPT_DIR}/auto_update_v2.js --sources ${SCRIPT_DIR}/config/sources.json --out ${PHISHGUARD_DIR}/data/blocklist.json --shards_dir ${PHISHGUARD_DIR}/data/blocklist-shards"
echo ""
echo "To uninstall:"
echo "  launchctl unload ${PLIST_PATH} && rm ${PLIST_PATH}"
