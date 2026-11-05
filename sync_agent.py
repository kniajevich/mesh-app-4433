import os
import sys
import time
import json
import socket
import logging
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

HUB_URL = os.getenv("VEXON_HUB_URL", "https://vexon-cloud.goldman-ao.workers.dev")
NODE_ID = os.getenv("VEXON_NODE_ID", socket.gethostname())
SYNC_INTERVAL = int(os.getenv("VEXON_SYNC_INTERVAL", "1800"))
STATE_FILE = os.getenv("VEXON_STATE_FILE", "/opt/vexon/network_topology.json")

def send_heartbeat():
    payload = json.dumps({
        "node_id": NODE_ID,
        "status": "online",
        "hostname": socket.gethostname(),
        "timestamp": time.time()
    }).encode("utf-8")
    
    endpoint = f"{HUB_URL.rstrip('/')}/api/heartbeat"
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logging.info(f"Heartbeat delivered. Node ID: {NODE_ID}")
            else:
                logging.warning(f"Hub returned status: {resp.status}")
    except Exception as err:
        logging.error(f"Failed to send heartbeat: {err}")

def sync_topology():
    endpoint = f"{HUB_URL.rstrip('/')}/api/topology"
    req = urllib.request.Request(endpoint)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                nodes = data.get("network_map", [])
                logging.info(f"Topology synced. Active nodes: {len(nodes)}")
                os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
                with open(STATE_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
    except Exception as err:
        logging.error(f"Failed to sync topology: {err}")

def main():
    logging.info(f"Starting Vexon Sync Agent [Node: {NODE_ID}]")
    while True:
        send_heartbeat()
        sync_topology()
        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Stopping Vexon Sync Agent.")
