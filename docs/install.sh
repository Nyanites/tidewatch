#!/bin/bash
# Tidewatch installer for macOS.
#
#   curl -fsSL https://nyanites.github.io/tidewatch/install.sh | bash
#
# What it does, in order:
#   1. Downloads the latest Tidewatch release (Tidewatch.zip) and its SHA256SUMS.txt from
#      https://github.com/Nyanites/tidewatch/releases
#   2. Checks it against the published SHA-256 checksum and stops if it doesn't match.
#   3. Copies Tidewatch.app into /Applications (or ~/Applications if /Applications isn't
#      writable), replacing an older Tidewatch.app there.
#   4. Cleans up its temporary files.
#
# It never asks for your password and changes nothing else on your Mac.
#
# Options (environment variables):
#   TIDEWATCH_VERSION=0.1.0       install a specific release instead of the latest
#   TIDEWATCH_INSTALL_DIR=<dir>   install somewhere else
#
# Uninstall: drag Tidewatch from Applications to the Trash.
#
# Source: https://github.com/Nyanites/tidewatch/blob/main/docs/install.sh

TW_TMP=""

tw_cleanup() {
    if [ -n "$TW_TMP" ] && [ -d "$TW_TMP" ]; then
        rm -rf "$TW_TMP"
    fi
}

# Everything runs inside main(), called on the last line, so a partially downloaded script
# does nothing.
main() {
    set -euo pipefail

    local repo="Nyanites/tidewatch"
    local app="Tidewatch.app"

    say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
    fail() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

    [ "$(uname -s)" = "Darwin" ] || fail "Tidewatch is a macOS app; this installer only runs on macOS."
    local major
    major=$(sw_vers -productVersion | cut -d. -f1)
    [ "$major" -ge 11 ] 2>/dev/null || fail "Tidewatch needs macOS 11 or newer."
    for tool in curl shasum ditto; do
        command -v "$tool" >/dev/null || fail "missing required tool: $tool"
    done

    local base
    if [ -n "${TIDEWATCH_VERSION:-}" ]; then
        case "$TIDEWATCH_VERSION" in
            *[!0-9A-Za-z.-]*) fail "invalid TIDEWATCH_VERSION: $TIDEWATCH_VERSION" ;;
        esac
        base="https://github.com/$repo/releases/download/v${TIDEWATCH_VERSION#v}"
    else
        base="https://github.com/$repo/releases/latest/download"
    fi

    local dest="${TIDEWATCH_INSTALL_DIR:-/Applications}"
    if [ -z "${TIDEWATCH_INSTALL_DIR:-}" ] && [ ! -w "$dest" ]; then
        dest="$HOME/Applications"
    fi
    mkdir -p "$dest"
    [ -w "$dest" ] || fail "can't write to $dest"

    # Global (not local): the EXIT trap runs after main() has returned.
    TW_TMP=$(mktemp -d "${TMPDIR:-/tmp}/tidewatch-install.XXXXXX")
    trap tw_cleanup EXIT
    local tmp="$TW_TMP"

    say "Downloading Tidewatch"
    curl -fL --proto '=https' --tlsv1.2 --retry 3 --progress-bar -o "$tmp/Tidewatch.zip" "$base/Tidewatch.zip" \
        || fail "download failed"
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt" \
        || fail "couldn't download the checksum file"

    say "Verifying checksum"
    local expected actual
    expected=$(awk '$2 == "Tidewatch.zip" { print $1 }' "$tmp/SHA256SUMS.txt")
    [ -n "$expected" ] || fail "checksum for Tidewatch.zip not found in SHA256SUMS.txt"
    actual=$(shasum -a 256 "$tmp/Tidewatch.zip" | awk '{ print $1 }')
    [ "$expected" = "$actual" ] || fail "checksum mismatch (expected $expected, got $actual); not installing"

    say "Installing to $dest"
    mkdir -p "$tmp/unpacked"
    ditto -x -k "$tmp/Tidewatch.zip" "$tmp/unpacked" || fail "couldn't unpack the download"
    [ -d "$tmp/unpacked/$app" ] || fail "$app not found in the download"
    if pgrep -xq tidewatch; then
        say "Quitting the running Tidewatch"
        osascript -e 'quit app "Tidewatch"' >/dev/null 2>&1 || true
        sleep 1
    fi
    # Replace only an existing Tidewatch.app, never anything else.
    if [ -d "$dest/$app" ]; then
        rm -rf "${dest:?}/$app"
    fi
    ditto "$tmp/unpacked/$app" "$dest/$app"

    # Make Finder pick up the .evtx file association right away.
    local lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    [ -x "$lsregister" ] && "$lsregister" -f "$dest/$app" >/dev/null 2>&1 || true

    local version
    version=$(defaults read "$dest/$app/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "")
    say "Tidewatch ${version:+$version }is installed in $dest"
    printf '    Open it from Launchpad or Applications, or double-click any .evtx file.\n'
}

main "$@"
