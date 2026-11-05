#!/bin/sh
set -e

INSTALL_DIR="/opt/vexon"
REPO="kniajevich/vexon"
RELEASE_URL="https://github.com/${REPO}/releases/download/latest"

echo "[*] Initializing Vexon autonomous deployment..."

download_file() {
    file_name="$1"
    target_path="${INSTALL_DIR}/${file_name}"
    url="${RELEASE_URL}/${file_name}"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "${target_path}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate -qO "${target_path}" "${url}"
    else
        echo "[-] Error: neither curl nor wget found in system."
        exit 1
    fi
}

mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

echo "[*] Fetching verified release artifacts..."
for f in vexond filter.bpf.o model.bin mlqos.nft SHA256SUMS; do
    echo " -> Downloading ${f}..."
    download_file "${f}"
done

chmod +x "${INSTALL_DIR}/vexond"

echo "[*] Configuring nftables rules..."
if [ -f "${INSTALL_DIR}/mlqos.nft" ]; then
    nft -f "${INSTALL_DIR}/mlqos.nft" || true
fi

echo "[*] Registering procd service definition..."
cat << 'EOF' > /etc/init.d/vexond
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

start_service() {
    procd_open_instance
    procd_set_param command /opt/vexon/vexond
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF

chmod +x /etc/init.d/vexond
/etc/init.d/vexond enable
/etc/init.d/vexond restart

echo "[+] Vexon deployed and running successfully."
