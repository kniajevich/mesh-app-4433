#!/bin/sh
set -e

HUB_URL="https://vexon-cloud.goldman-ao.workers.dev"
REPO_RAW="https://raw.githubusercontent.com/kniajevich/vexon/main"
INSTALL_DIR="/opt/vexon"
SERVICE_FILE="/etc/init.d/vexon"

echo "[VEXON] Installing Autonomous Edge Agent with Telemetry & Update Reporter..."
mkdir -p "$INSTALL_DIR"

cat << 'EOF' > "${INSTALL_DIR}/sync_agent.sh"
#!/bin/sh

HUB_URL="${VEXON_HUB_URL:-https://vexon-cloud.goldman-ao.workers.dev}"
REPO_RAW="https://raw.githubusercontent.com/kniajevich/vexon/main"
NODE_ID="${VEXON_NODE_ID:-$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo "edge-node")}"

NORMAL_INTERVAL=14400
RETRY_INTERVAL=300

STATE_FILE="${VEXON_STATE_FILE:-/opt/vexon/network_topology.json}"
UPDATE_LOG_FILE="/opt/vexon/last_update.json"

collect_metrics() {
    UPTIME_SEC=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
    CPU_LOAD=$(awk '{print $1" "$2}' /proc/loadavg 2>/dev/null || echo "0.00 0.00")
    
    MEM_TOTAL_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    MEM_AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    
    if [ "$MEM_TOTAL_KB" -gt 0 ]; then
        MEM_USED_KB=$((MEM_TOTAL_KB - MEM_AVAIL_KB))
        MEM_PCT=$((MEM_USED_KB * 100 / MEM_TOTAL_KB))
        MEM_FREE_MB=$((MEM_AVAIL_KB / 1024))
        MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
    else
        MEM_PCT=0
        MEM_FREE_MB=0
        MEM_TOTAL_MB=0
    fi

    KERNEL_VER=$(uname -r 2>/dev/null || echo "unknown")

    # Считываем информацию о последнем апдейте
    if [ -f "$UPDATE_LOG_FILE" ]; then
        UPDATE_INFO=$(cat "$UPDATE_LOG_FILE" 2>/dev/null || echo "{}")
    else
        UPDATE_INFO="{\"version\":\"initial\",\"applied_at\":\"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\",\"status\":\"base-install\",\"details\":\"Installed via bootstrap\"}"
    fi

    PAYLOAD="{\"node_id\": \"$NODE_ID\", \"hostname\": \"$NODE_ID\", \"status\": \"online\", \"timestamp\": $(date +%s), \"uptime\": $UPTIME_SEC, \"cpu_load\": \"$CPU_LOAD\", \"mem_pct\": $MEM_PCT, \"mem_free_mb\": $MEM_FREE_MB, \"mem_total_mb\": $MEM_TOTAL_MB, \"kernel\": \"$KERNEL_VER\", \"update_report\": $UPDATE_INFO}"
}

send_heartbeat() {
    collect_metrics
    curl -m 10 --connect-timeout 5 -s -k -X POST "${HUB_URL}/api/heartbeat" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" >/dev/null 2>&1
}

sync_topology() {
    curl -m 10 --connect-timeout 5 -s -k "${HUB_URL}/api/topology" -o "$STATE_FILE" >/dev/null 2>&1
}

check_self_update() {
    TMP_INSTALL="/tmp/vexon_install_latest.sh"
    if curl -m 15 --connect-timeout 5 -s -k "${REPO_RAW}/install.sh?v=$(date +%s)" -o "$TMP_INSTALL"; then
        if head -n 1 "$TMP_INSTALL" 2>/dev/null | grep -q '#!/bin/sh'; then
            NEW_HASH=$(sha256sum "$TMP_INSTALL" 2>/dev/null | awk '{print substr($1,1,10)}' || echo "updated")
            CUR_HASH=$(cat /opt/vexon/current_version 2>/dev/null || echo "none")

            if [ "$NEW_HASH" != "$CUR_HASH" ]; then
                echo "$NEW_HASH" > /opt/vexon/current_version
                APPLIED_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
                
                cat << UPDATE_JSON > "$UPDATE_LOG_FILE"
{
  "version": "$NEW_HASH",
  "applied_at": "$APPLIED_TIME",
  "status": "success",
  "package": "kniajevich/vexon@main",
  "target": "/opt/vexon/sync_agent.sh",
  "details": "OTA Hotpatch synced and applied via procd"
}
UPDATE_JSON

                sh "$TMP_INSTALL" >/dev/null 2>&1 &
                exit 0
            fi
        fi
        rm -f "$TMP_INSTALL"
        return 0
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

    if [ "$HB_OK" -eq 1 ] && [ "$UPDATE_OK" -eq 1 ]; then
        sleep "$NORMAL_INTERVAL"
    else
        sleep "$RETRY_INTERVAL"
    fi
done
EOF

chmod +x "${INSTALL_DIR}/sync_agent.sh"

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

echo "[VEXON] Agent operational with OTA Update Telemetry!"
