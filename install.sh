#!/bin/sh
set -e

# =========================================================
# Vexon Edge Node: Autonomous Installer & Auto-Updater
# =========================================================

HUB_URL="https://vexon-cloud.goldman-ao.workers.dev"
INSTALL_DIR="/opt/vexon"
CRON_FILE="/etc/crontabs/root"

echo "[VEXON] Starting autonomous agent check..."

mkdir -p "$INSTALL_DIR"

echo "[VEXON] Fetching latest sync agent from hub..."
curl -sSL -k "${HUB_URL}/release/sync_agent.py" -o "${INSTALL_DIR}/sync_agent.py" || {
    echo "[VEXON ERROR] Failed to fetch sync_agent from edge hub."
    exit 1
}

chmod +x "${INSTALL_DIR}/sync_agent.py"

if [ -d "/etc/init.d" ]; then
    cat << 'EOF' > /etc/init.d/vexon
#!/bin/sh /etc/rc.common
START=95
STOP=10

USE_PROCD=1
PROG=/usr/bin/python3
ARGS="/opt/vexon/sync_agent.py"

start_service() {
    procd_open_instance
    procd_set_param command $PROG $ARGS
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
    chmod +x /etc/init.d/vexon
    /etc/init.d/vexon enable
    /etc/init.d/vexon restart || true
fi

UPDATE_CMD="curl -sSL -k ${HUB_URL}/release/install.sh | sh >/dev/null 2>&1"
if [ -f "$CRON_FILE" ]; then
    if ! grep -q "vexon-cloud" "$CRON_FILE"; then
        echo "0 */6 * * * $UPDATE_CMD" >> "$CRON_FILE"
        /etc/init.d/cron restart || true
    fi
fi

NODE_ID=$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo "edge-node")
curl -s -X POST "${HUB_URL}/api/heartbeat" \
  -H "Content-Type: application/json" \
  -d "{\"node_id\": \"${NODE_ID}\", \"status\": \"online\", \"action\": \"installed\"}" >/dev/null 2>&1 || true

echo "[VEXON] Node successfully configured and hooked to edge hub!"
