#!/usr/bin/env bash
# ==============================================================================
# AnonymousAnt — Instant iOS WireGuard Companion Setup
# For iPhones without a $99/year Apple Developer Account.
# Runs alongside antserver on the Singapore VPS and outputs a QR code for the
# official free WireGuard iOS App Store app.
# Usage: curl -sSL https://raw.githubusercontent.com/chengyaolee/AnonymousAnt/main/deploy/singapore/add_wireguard_ios.sh | sudo bash
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: Must be run as root (sudo bash add_wireguard_ios.sh)"
   exit 1
fi

echo "=================================================================="
echo "🇸🇬 Setting up WireGuard Companion for iOS (Zero-Apple-Fee Mode)..."
echo "=================================================================="

# 1. Install wireguard and qrencode
if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq wireguard qrencode iptables
elif command -v apk &>/dev/null; then
    apk update && apk add wireguard-tools libqrencode-tools iptables
fi

WG_DIR="/etc/wireguard"
mkdir -p "${WG_DIR}"
chmod 700 "${WG_DIR}"

# 2. Key generation
if [[ ! -f "${WG_DIR}/server.key" ]]; then
    wg genkey | tee "${WG_DIR}/server.key" | wg pubkey > "${WG_DIR}/server.pub"
fi
if [[ ! -f "${WG_DIR}/client.key" ]]; then
    wg genkey | tee "${WG_DIR}/client.key" | wg pubkey > "${WG_DIR}/client.pub"
fi

SERVER_PRIV=$(cat "${WG_DIR}/server.key")
SERVER_PUB=$(cat "${WG_DIR}/server.pub")
CLIENT_PRIV=$(cat "${WG_DIR}/client.key")
CLIENT_PUB=$(cat "${WG_DIR}/client.pub")

# 3. Detect WAN interface
WAN_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || echo "eth0")
if [[ -z "${WAN_IFACE}" ]]; then
    WAN_IFACE="eth0"
fi
PUBLIC_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "YOUR_SERVER_IP")

# 4. Generate wg0.conf
cat << EOF > "${WG_DIR}/wg0.conf"
[Interface]
Address = 10.9.0.1/24
ListenPort = 51821
PrivateKey = ${SERVER_PRIV}
PostUp = iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ${WAN_IFACE} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.9.0.0/24 -o ${WAN_IFACE} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = ${CLIENT_PUB}
AllowedIPs = 10.9.0.2/32
EOF

# 5. Start/Restart WireGuard
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl restart wg-quick@wg0 >/dev/null 2>&1 || wg-quick up wg0 >/dev/null 2>&1 || true

# 6. Allow port in ufw
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw allow 51821/udp
fi

# 7. Generate iOS client config
CLIENT_CONF="${WG_DIR}/ios_client.conf"
cat << EOF > "${CLIENT_CONF}"
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.9.0.2/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${PUBLIC_IP}:51821
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo ""
echo "=================================================================="
echo "🎉 iOS Configuration Generated! Scan with WireGuard on iPhone:"
echo "=================================================================="
echo ""
qrencode -t ansiutf8 < "${CLIENT_CONF}"
echo ""
echo "=================================================================="
echo "📱 Quick 3-Step Setup for iPhone:"
echo "1. Install the official 'WireGuard' app from the iOS App Store (Free)."
echo "2. Open WireGuard on your iPhone -> Tap '+' -> 'Create from QR code'."
echo "3. Point camera at the QR code above, name it 'Singapore', and toggle ON!"
echo "=================================================================="
