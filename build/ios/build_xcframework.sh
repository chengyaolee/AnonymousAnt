#!/usr/bin/env bash
set -euo pipefail

echo "==> Building AntTunnel.xcframework for iOS using gomobile..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/Frameworks"

mkdir -p "${OUTPUT_DIR}"

if ! command -v gomobile &> /dev/null; then
    echo "gomobile not found. Installing gomobile..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    gomobile init
fi

cd "${ROOT_DIR}"
echo "==> Compiling Go mobile bridge to iOS xcframework..."
gomobile bind -target=ios,iossimulator -o "${OUTPUT_DIR}/AntTunnel.xcframework" ./pkg/mobile

echo "==> Successfully generated ${OUTPUT_DIR}/AntTunnel.xcframework!"
