#!/usr/bin/env bash
# Build "Tidewatch.app" (and optionally a .dmg installer).
#
# Usage: ./bundle-macos.sh [--universal] [--dmg]
#   --universal   one binary for Apple Silicon + Intel
#   --dmg         also create target/Tidewatch-<version>.dmg (drag-to-Applications installer)
#
# Signing (optional, used by the release workflow):
#   MACOS_SIGN_IDENTITY  "Developer ID Application: Name (TEAMID)"; otherwise the app is ad-hoc signed
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD  also notarize the .dmg so Gatekeeper opens it without warnings
set -euo pipefail
cd "$(dirname "$0")"

UNIVERSAL=0
DMG=0
for arg in "$@"; do
    case "$arg" in
        --universal) UNIVERSAL=1 ;;
        --dmg) DMG=1 ;;
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

if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
    codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP"
else
    # Ad-hoc signature: required to run on Apple Silicon, but not trusted by Gatekeeper.
    codesign --force --options runtime --sign - "$APP"
fi
echo "Built: $APP"

if [[ $DMG == 1 ]]; then
    DMG_PATH="target/Tidewatch-$VERSION.dmg"
    STAGE=$(mktemp -d)
    trap 'rm -rf "$STAGE"' EXIT
    cp -R "$APP" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    rm -f "$DMG_PATH"
    hdiutil create -volname "$NAME" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG_PATH" >/dev/null
    rm -rf "$STAGE"
    if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
        codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG_PATH"
    fi
    if [[ -n "${MACOS_SIGN_IDENTITY:-}" && -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
        xcrun notarytool submit "$DMG_PATH" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_APP_PASSWORD" --wait
        xcrun stapler staple "$DMG_PATH"
    fi
    echo "Built: $DMG_PATH"
fi
