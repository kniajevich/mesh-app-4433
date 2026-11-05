#!/bin/sh
set -e

HUB_URL="https://vexon-cloud.goldman-ao.workers.dev"
REPO_RAW="https://raw.githubusercontent.com/kniajevich/vexon/main"
INSTALL_DIR="/opt/vexon"
SERVICE_FILE="/etc/init.d/vexon"

echo "[VEXON] Installing Autonomous Edge Agent with Adaptive Update..."
mkdir -p "$INSTALL_DIR"

# 1. Generate standalone POSIX agent with adaptive retry logic
cat << 'EOF' > "${INSTALL_DIR}/sync_agent.sh"
#!/bin/sh

HUB_URL="${VEXON_HUB_URL:-https://vexon-cloud.goldman-ao.workers.dev}"
REPO_RAW="https://raw.githubusercontent.com/kniajevich/vexon/main"
NODE_ID="${VEXON_NODE_ID:-$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo "edge-node")}"

# Standard interval (4 hours) vs Retry interval on failure (5 minutes)
NORMAL_INTERVAL=14400
RETRY_INTERVAL=300

STATE_FILE="${VEXON_STATE_FILE:-/opt/vexon/network_topology.json}"
SELF_PATH="/opt/vexon/sync_agent.sh"

send_heartbeat() {
    PAYLOAD="{\"node_id\": \"$NODE_ID\", \"status\": \"online\", \"hostname\": \"$NODE_ID\", \"timestamp\": $(date +%s)}"
    curl -m 10 --connect-timeout 5 -s -k -X POST "${HUB_URL}/api/heartbeat" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" >/dev/null 2>&1
}

sync_topology() {
    curl -m 10 --connect-timeout 5 -s -k "${HUB_URL}/api/topology" -o "$STATE_FILE" >/dev/null 2>&1
}

check_self_update() {
    TMP_INSTALL="/tmp/vexon_install_latest.sh"
    # Download installer to temporary location
    if curl -m 15 --connect-timeout 5 -s -k "${REPO_RAW}/install.sh" -o "$TMP_INSTALL"; then
        if head -n 1 "$TMP_INSTALL" 2>/dev/null | grep -q '#!/bin/sh'; then
            CURR_HASH=$(sha256sum "$SELF_PATH" 2>/dev/null | awk '{print $1}')
            # Execute install script if file is valid
            sh "$TMP_INSTALL" >/dev/null 2>&1 &
            exit 0
        fi
        rm -f "$TMP_INSTALL"
        return 1
    fi
    return 1
}

while true; do
    HB_OK=0
    UPDATE_OK=0

    send_heartbeat && HB_OK=1
    sync_topology

    if check_self_update; then
        UPDATE_OK=1
    fi

    # If GitHub or Hub was unreachable, retry in 5 minutes. Otherwise sleep 4 hours.
    if [ "$HB_OK" -eq 1 ] && [ "$UPDATE_OK" -eq 1 ]; then
        sleep "$NORMAL_INTERVAL"
    else
        sleep "$RETRY_INTERVAL"
    fi
done
EOF

chmod +x "${INSTALL_DIR}/sync_agent.sh"

# 2. Configure procd service
cat << 'EOF' > "$SERVICE_FILE"
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh /opt/vexon/sync_agent.sh
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF

chmod +x "$SERVICE_FILE"
"$SERVICE_FILE" enable
"$SERVICE_FILE" restart

echo "[VEXON] Agent operational! Adaptive update loop (5m retry / 4h idle) is active."
