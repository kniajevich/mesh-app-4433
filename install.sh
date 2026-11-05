#!/bin/sh
set -e

REPO="kniajevich/vexon"
INSTALL_DIR="/opt/vexon"
IFACE="br-lan"

echo "=== [Vexon QoS Engine Installer] ==="

# 1. Проверка архитектуры
ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    echo "[-] Предупреждение: Архитектура $ARCH. Бинарники собраны под aarch64 (ARM64)."
fi

# 2. Подготовка каталога
echo "[+] Создание директории $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 3. Загрузка бинарных компонентов
BASE_URL="https://github.com/$REPO/releases/download/latest"
echo "[+] Загрузка модулей ядра и демона из релиза..."
wget -q -O vexond "$BASE_URL/vexond" || { echo "[-] Ошибка загрузки vexond"; exit 1; }
wget -q -O filter.bpf.o "$BASE_URL/filter.bpf.o" || { echo "[-] Ошибка загрузки filter.bpf.o"; exit 1; }
wget -q -O mlqos.nft "$BASE_URL/mlqos.nft" || { echo "[-] Ошибка загрузки mlqos.nft"; exit 1; }
wget -q -O model.bin "$BASE_URL/model.bin" || { echo "[-] Ошибка загрузки model.bin"; exit 1; }

chmod +x vexond

# 4. Настройка Procd службы
echo "[+] Регистрация службы /etc/init.d/vexond..."
cat << 'EOF' > /etc/init.d/vexond
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

PROG=/opt/vexon/vexond
BPF_OBJ=/opt/vexon/filter.bpf.o
IFACE="br-lan"

start_service() {
    [ -d /sys/fs/bpf ] || mount -t bpf bpf /sys/fs/bpf
    [ -f /opt/vexon/mlqos.nft ] && nft -f /opt/vexon/mlqos.nft

    tc qdisc del dev "$IFACE" clsact 2>/dev/null
    tc qdisc add dev "$IFACE" clsact 2>/dev/null
    tc filter add dev "$IFACE" ingress bpf da obj "$BPF_OBJ" sec classifier 2>/dev/null
    tc filter add dev "$IFACE" egress bpf da obj "$BPF_OBJ" sec classifier 2>/dev/null

    procd_open_instance
    procd_set_param command "$PROG"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    tc qdisc del dev "$IFACE" clsact 2>/dev/null
    killall vexond 2>/dev/null
}
EOF

chmod +x /etc/init.d/vexond

# 5. Активация и старт
echo "[+] Активация автозапуска и запуск службы..."
/etc/init.d/vexond enable
/etc/init.d/vexond restart

echo "=== [Успешно!] Vexon запущен и работает в фоне. ==="
echo "Для проверки логов выполните: logread | grep vexond"
