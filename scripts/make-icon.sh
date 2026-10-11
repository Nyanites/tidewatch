#!/usr/bin/env bash
# Regenerate assets/AppIcon.icns from scripts/make-icon.swift (needs Xcode command line tools).
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
swift scripts/make-icon.swift "$tmp/icon_1024.png"
set=$tmp/AppIcon.iconset
mkdir "$set"
for s in 16 32 128 256 512; do
    sips -z $s $s "$tmp/icon_1024.png" --out "$set/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) "$tmp/icon_1024.png" --out "$set/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$set" -o assets/AppIcon.icns
cp "$tmp/icon_1024.png" assets/icon.png
sips -z 256 256 "$tmp/icon_1024.png" --out assets/icon-256.png >/dev/null
rm -rf "$tmp"
echo "Wrote assets/AppIcon.icns"
