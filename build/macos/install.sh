#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing AnonymousAnt for macOS..."

if [[ $EUID -ne 0 ]]; then
   echo "Error: This installer must be run as root (sudo ./install.sh)" 
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "==> Building binaries from source..."
cd "${ROOT_DIR}"
go build -o /usr/local/bin/ant-daemon ./cmd/ant-daemon
go build -o /usr/local/bin/antclient ./cmd/antclient
go build -o /usr/local/bin/ant-ui ./cmd/ant-ui

chmod 755 /usr/local/bin/ant-daemon
chmod 755 /usr/local/bin/antclient
chmod 755 /usr/local/bin/ant-ui

echo "==> Installing privileged LaunchDaemon..."
PLIST_SRC="${SCRIPT_DIR}/com.anonymousant.daemon.plist"
PLIST_DEST="/Library/LaunchDaemons/com.anonymousant.daemon.plist"

cp "${PLIST_SRC}" "${PLIST_DEST}"
chown root:wheel "${PLIST_DEST}"
chmod 644 "${PLIST_DEST}"

echo "==> Loading LaunchDaemon service..."
launchctl unload "${PLIST_DEST}" 2>/dev/null || true
launchctl load -w "${PLIST_DEST}"

echo "==> AnonymousAnt daemon successfully installed and running!"
echo "You can now launch the user interface at any time with: ant-ui"
