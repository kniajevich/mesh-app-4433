#!/bin/sh
set -e

HUB_URL="https://vexon-cloud.goldman-ao.workers.dev"
INSTALL_DIR="/opt/vexon"
SERVICE_FILE="/etc/init.d/vexon"

echo "[VEXON] Installing Vexon Edge Agent..."
mkdir -p "$INSTALL_DIR"

# 1. Записываем автономный POSIX-агент
cat << 'EOF' > "${INSTALL_DIR}/sync_agent.sh"
#!/bin/sh

HUB_URL="${VEXON_HUB_URL:-https://vexon-cloud.goldman-ao.workers.dev}"
NODE_ID="${VEXON_NODE_ID:-$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo "edge-node")}"
SYNC_INTERVAL="${VEXON_SYNC_INTERVAL:-1800}"
STATE_FILE="${VEXON_STATE_FILE:-/opt/vexon/network_topology.json}"

send_heartbeat() {
    PAYLOAD="{\"node_id\": \"$NODE_ID\", \"status\": \"online\", \"hostname\": \"$NODE_ID\", \"timestamp\": $(date +%s)}"
    curl -m 10 --connect-timeout 5 -s -k -X POST "${HUB_URL}/api/heartbeat" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" >/dev/null 2>&1 || true
}

sync_topology() {
    curl -m 10 --connect-timeout 5 -s -k "${HUB_URL}/api/topology" -o "$STATE_FILE" >/dev/null 2>&1 || true
}

while true; do
    send_heartbeat
    sync_topology
    sleep "$SYNC_INTERVAL"
done
EOF

chmod +x "${INSTALL_DIR}/sync_agent.sh"

# 2. Настраиваем системную службу procd
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

echo "[VEXON] Done! Agent installed and started."
