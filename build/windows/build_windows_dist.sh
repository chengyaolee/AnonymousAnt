#!/usr/bin/env bash
set -euo pipefail

echo "==> Packaging AnonymousAnt for Windows (x64)..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/build/dist"
STAGING_DIR="${SCRIPT_DIR}/staging"
WINTUN_CACHE="${SCRIPT_DIR}/.wintun_cache"

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}" "${DIST_DIR}" "${WINTUN_CACHE}"

echo "==> Cross-compiling Windows x64 binaries..."
cd "${ROOT_DIR}"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "${STAGING_DIR}/ant-ui.exe" ./cmd/ant-ui
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "${STAGING_DIR}/ant-daemon.exe" ./cmd/ant-daemon
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "${STAGING_DIR}/antclient.exe" ./cmd/antclient

echo "==> Procuring 64-bit Wintun driver..."
if [[ ! -f "${WINTUN_CACHE}/wintun.dll" ]]; then
    echo "Downloading official Wintun 0.14.1 driver..."
    curl -sSL https://www.wintun.net/builds/wintun-0.14.1.zip -o "${WINTUN_CACHE}/wintun.zip"
    unzip -q -o "${WINTUN_CACHE}/wintun.zip" -d "${WINTUN_CACHE}/extracted"
    cp "${WINTUN_CACHE}/extracted/wintun/bin/amd64/wintun.dll" "${WINTUN_CACHE}/wintun.dll"
fi
cp "${WINTUN_CACHE}/wintun.dll" "${STAGING_DIR}/wintun.dll"

echo "==> Generating helper scripts and documentation..."
cp "${SCRIPT_DIR}/install_service.bat" "${STAGING_DIR}/install_service.bat"
cp "${SCRIPT_DIR}/uninstall_service.bat" "${STAGING_DIR}/uninstall_service.bat"
cp "${SCRIPT_DIR}/start_ui.bat" "${STAGING_DIR}/start_ui.bat"

cat << 'EOF' > "${STAGING_DIR}/README.txt"
========================================================================
                      AnonymousAnt Windows (x64)
           High-Speed Ephemeral Chameleon VPN (Zero-Logging)
========================================================================

QUICK START:
1. Right-click 'install_service.bat' and select "Run as administrator"
   to register the background tunnel driver service.
2. Double-click 'start_ui.bat' or 'ant-ui.exe' to open the control interface.
3. Paste your ant:// connection URL and click CONNECT!

FILES IN THIS PACKAGE:
- ant-ui.exe          : Desktop GUI Web Server & Control Hub
- ant-daemon.exe      : Privileged TUN & Routing Engine
- antclient.exe       : Command-Line Client Interface
- wintun.dll          : High-performance ring-0 Windows TUN driver
- install_service.bat : Helper to register background service with Windows
- uninstall_service.bat : Helper to stop and remove background service
- start_ui.bat        : Helper to launch GUI

UNINSTALLATION:
- Run 'uninstall_service.bat' as administrator.
- Delete this folder.
========================================================================
EOF

echo "==> Creating standalone portable ZIP distribution..."
ZIP_PATH="${DIST_DIR}/AnonymousAnt-Windows-x64.zip"
rm -f "${ZIP_PATH}"
(cd "${STAGING_DIR}" && zip -q -r "${ZIP_PATH}" ./*)

echo "==> Windows distribution package created at: ${ZIP_PATH}"
echo "==> Staging directory ready for Inno Setup compilation (iscc installer.iss)"
