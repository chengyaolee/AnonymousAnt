#!/usr/bin/env bash
set -euo pipefail

echo "==> Building AnonymousAnt for iOS via xcodebuild..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if ! command -v xcodebuild &> /dev/null; then
    echo "xcodebuild not found. Please install full Xcode from Mac App Store."
    exit 1
fi

cd "${SCRIPT_DIR}"
xcodebuild -project AnonymousAnt.xcodeproj -scheme AnonymousAnt -configuration Release -sdk iphoneos build CODE_SIGNING_ALLOWED=NO

echo "==> iOS build complete!"
