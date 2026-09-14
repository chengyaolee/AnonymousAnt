#!/usr/bin/env bash
# ==============================================================================
# AnonymousAnt — Singapore Exit Node Automated Setup Script
# Run this script on any Ubuntu/Debian/Alpine VPS in Singapore (AWS, DigitalOcean, etc.)
# Usage: curl -sSL https://raw.githubusercontent.com/chengyaolee/AnonymousAnt/main/deploy/singapore/setup.sh | sudo bash
# ==============================================================================
set -euo pipefail

echo "=================================================================="
echo "🇸🇬 Setting up AnonymousAnt Singapore Exit Node..."
echo "=================================================================="

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (sudo bash setup.sh)"
   exit 1
fi

# 1. Install prerequisites
echo "==> [1/5] Installing dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq curl git iptables iproute2 build-essential
elif command -v apk &>/dev/null; then
    apk update && apk add curl git iptables iproute2 build-base go
fi

# 2. Install Go if not present
if ! command -v go &>/dev/null; then
    echo "==> [2/5] Installing Go..."
    GO_VERSION="1.23.1"
    ARCH="amd64"
    if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
        ARCH="arm64"
    fi
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:${PATH}"
    rm -f /tmp/go.tar.gz
fi

# 3. Clone / Build AnonymousAnt
echo "==> [3/5] Building antserver..."
INSTALL_DIR="/opt/anonymousant"
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

if [[ -d "${INSTALL_DIR}/repo" ]]; then
    cd repo && git pull
else
    git clone https://github.com/chengyaolee/AnonymousAnt.git repo
    cd repo
fi

go build -o /usr/local/bin/antserver ./cmd/antserver
chmod 755 /usr/local/bin/antserver

# 4. Enable IPv4 Forwarding & NAT Masquerade
echo "==> [4/5] Enabling Kernel IPv4 Forwarding & NAT..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

WAN_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [[ -z "${WAN_IFACE}" ]]; then
    WAN_IFACE="eth0"
fi

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "${WAN_IFACE}" -j MASQUERADE || true
iptables -A FORWARD -i ant0 -j ACCEPT || true
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT || true

# 5. Generate Server Keypair
echo "==> [5/5] Generating persistent server keypair..."
KEY_FILE="${INSTALL_DIR}/server_key.txt"
if [[ ! -f "${KEY_FILE}" ]]; then
    # Generate random 32-byte base64 private key
    PRIV_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    echo "${PRIV_KEY}" > "${KEY_FILE}"
    chmod 600 "${KEY_FILE}"
else
    PRIV_KEY=$(cat "${KEY_FILE}")
fi

PUBLIC_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "YOUR_SERVER_IP")

# 6. Configure systemd service
SERVICE_FILE="/etc/systemd/system/anonymousant-server.service"
cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=AnonymousAnt VPN Server (Singapore Exit Node)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/antserver -udp :51820 -tls :8443 -key ${PRIV_KEY} -nat=true
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable anonymousant-server
systemctl restart anonymousant-server

# Allow ports in UFW if enabled
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw allow 51820/udp
    ufw allow 8443/tcp
fi

sleep 1

echo ""
echo "=================================================================="
echo "🎉 Singapore Exit Node is RUNNING!"
echo "=================================================================="
echo "Server Public IP:  ${PUBLIC_IP}"
echo ""
echo "To view your connection string, run:"
echo "  journalctl -u anonymousant-server -n 20 --no-pager"
echo ""
echo "Or check the server logs at any time with:"
echo "  systemctl status anonymousant-server"
echo "=================================================================="
