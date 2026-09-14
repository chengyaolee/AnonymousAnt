#!/usr/bin/env bash
set -euo pipefail

echo "==> Packaging AnonymousAnt for macOS DMG..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/dist/macos"
APP_DIR="${BUILD_DIR}/AnonymousAnt.app"

rm -rf "${BUILD_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

echo "==> Compiling macOS binaries..."
cd "${ROOT_DIR}"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "${APP_DIR}/Contents/MacOS/ant-ui" ./cmd/ant-ui
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "${APP_DIR}/Contents/MacOS/ant-daemon" ./cmd/ant-daemon

# Create Info.plist
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
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
</dict>
</plist>
EOF

echo "==> Creating DMG file..."
DMG_PATH="${ROOT_DIR}/build/dist/AnonymousAnt-macOS-arm64.dmg"
mkdir -p "${ROOT_DIR}/build/dist"
hdiutil create -volname "AnonymousAnt" -srcfolder "${BUILD_DIR}" -ov -format UDZO "${DMG_PATH}"

echo "==> DMG successfully created at: ${DMG_PATH}"
