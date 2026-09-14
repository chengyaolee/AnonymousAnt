#!/usr/bin/env bash
set -euo pipefail

echo "==> Packaging AnonymousAnt for macOS (Apple Silicon Arm64) DMG..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/build/dist"
STAGING_DIR="${DIST_DIR}/macos-staging"
APP_DIR="${STAGING_DIR}/AnonymousAnt.app"

rm -rf "${STAGING_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

echo "==> Compiling native Apple Silicon (arm64) binaries..."
cd "${ROOT_DIR}"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "${APP_DIR}/Contents/MacOS/ant-ui" ./cmd/ant-ui
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "${APP_DIR}/Contents/MacOS/ant-daemon" ./cmd/ant-daemon
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "${APP_DIR}/Contents/MacOS/antclient" ./cmd/antclient

chmod +x "${APP_DIR}/Contents/MacOS/"*

echo "==> Installing AppIcon and metadata..."
if [[ -f "${ROOT_DIR}/build/assets/AppIcon.icns" ]]; then
    cp "${ROOT_DIR}/build/assets/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
fi

cat << 'EOF' > "${APP_DIR}/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ant-ui</string>
    <key>CFBundleIdentifier</key>
    <string>com.anonymousant.app</string>
    <key>CFBundleName</key>
    <string>AnonymousAnt</string>
    <key>CFBundleDisplayName</key>
    <string>AnonymousAnt</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

echo "==> Creating Drag-and-Drop /Applications symlink..."
ln -s /Applications "${STAGING_DIR}/Applications"

echo "==> Creating DMG file with hdiutil..."
DMG_PATH="${DIST_DIR}/AnonymousAnt-macOS-arm64.dmg"
rm -f "${DMG_PATH}"
hdiutil create -volname "AnonymousAnt" -srcfolder "${STAGING_DIR}" -ov -format UDZO "${DMG_PATH}"
rm -rf "${STAGING_DIR}"

echo "==> DMG successfully created at: ${DMG_PATH}"
