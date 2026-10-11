#!/usr/bin/env bash
# Build "Tidewatch.app" (and optionally the release archive used by the installer).
#
# Usage: ./bundle-macos.sh [--universal] [--zip]
#   --universal   one binary for Apple Silicon + Intel
#   --zip         also create target/Tidewatch-<version>.zip (what docs/install.sh downloads)
set -euo pipefail
cd "$(dirname "$0")"

UNIVERSAL=0
ZIP=0
for arg in "$@"; do
    case "$arg" in
        --universal) UNIVERSAL=1 ;;
        --zip) ZIP=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

NAME="Tidewatch"
APP="target/$NAME.app"
BIN=tidewatch
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)

if [[ $UNIVERSAL == 1 ]]; then
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    cargo build --locked --release --target aarch64-apple-darwin
    cargo build --locked --release --target x86_64-apple-darwin
    OUT="target/release/$BIN-universal"
    mkdir -p target/release
    lipo -create -output "$OUT" \
        "target/aarch64-apple-darwin/release/$BIN" \
        "target/x86_64-apple-darwin/release/$BIN"
else
    cargo build --locked --release
    OUT="target/release/$BIN"
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$OUT" "$APP/Contents/MacOS/$BIN"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$NAME</string>
    <key>CFBundleDisplayName</key><string>$NAME</string>
    <key>CFBundleIdentifier</key><string>dev.tidewatch</string>
    <key>CFBundleExecutable</key><string>$BIN</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>

    <!-- Let Finder open .evtx files with this app (double-click / Open With). -->
    <key>UTImportedTypeDeclarations</key>
    <array>
        <dict>
            <key>UTTypeIdentifier</key><string>com.microsoft.windows.evtx</string>
            <key>UTTypeDescription</key><string>Windows Event Log</string>
            <key>UTTypeConformsTo</key><array><string>public.data</string></array>
            <key>UTTypeTagSpecification</key>
            <dict>
                <key>public.filename-extension</key><array><string>evtx</string></array>
            </dict>
        </dict>
    </array>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key><string>Windows Event Log</string>
            <key>CFBundleTypeRole</key><string>Viewer</string>
            <key>LSHandlerRank</key><string>Default</string>
            <key>LSItemContentTypes</key><array><string>com.microsoft.windows.evtx</string></array>
            <key>CFBundleTypeIconFile</key><string>AppIcon</string>
        </dict>
    </array>
</dict>
</plist>
PLIST

# Ad-hoc signature with the hardened runtime: required to run on Apple Silicon.
codesign --force --options runtime --sign - "$APP"
echo "Built: $APP"

if [[ $ZIP == 1 ]]; then
    ZIP_PATH="target/Tidewatch-$VERSION.zip"
    rm -f "$ZIP_PATH"
    # ditto keeps the bundle's code signature and metadata intact.
    ditto -c -k --keepParent "$APP" "$ZIP_PATH"
    echo "Built: $ZIP_PATH"
fi
