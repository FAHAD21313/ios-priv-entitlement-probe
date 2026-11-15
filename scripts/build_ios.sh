#!/usr/bin/env bash
# Build the unsigned iOS app and package it as an IPA.
#
# No Xcode project is used: the app is a single Swift file, compiled directly
# against the iOS SDK, and the bundle is assembled by hand.  This keeps the
# repository free of generated project files.
#
#   ./scripts/build_ios.sh            # -> out/Probe-unsigned.ipa
#
# Requires macOS with the Xcode command line tools.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
TARGET=arm64-apple-ios16.0
OUT=out
BUNDLE_ID=com.research.ios27.privprobe

rm -rf "$OUT"
mkdir -p "$OUT/Probe.app"

echo "==> compiling for $TARGET"
swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
       -o "$OUT/Probe.app/Probe" Probe/ProbeApp.swift

echo "==> assembling the bundle"
# The placeholder bundle id is substituted here; codesign replaces it later.
sed "s|\$(PRODUCT_BUNDLE_IDENTIFIER)|$BUNDLE_ID|g; s|\$(EXECUTABLE_NAME)|Probe|g; s|\$(PRODUCT_NAME)|Probe|g" \
    Probe/Info.plist > "$OUT/Probe.app/Info.plist"

echo "==> packaging the IPA"
mkdir -p "$OUT/Payload"
cp -R "$OUT/Probe.app" "$OUT/Payload/"
( cd "$OUT" && zip -qry Probe-unsigned.ipa Payload )

echo
echo "built: $OUT/Probe-unsigned.ipa"
echo "next: ./scripts/resign.sh --help"
