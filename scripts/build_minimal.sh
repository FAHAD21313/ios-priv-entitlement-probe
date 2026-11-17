#!/usr/bin/env bash
# Build the single-button dyld4-OOB exploration probe (unsigned IPA).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OUT=out/Minimal
BUNDLE_ID=${BUNDLE_ID:-com.research.ios27.privprobe}
rm -rf "$OUT" out/Probe-minimal.ipa
mkdir -p "$OUT/Probe.app"

# C exploration helper: calls dyld's validation functions directly with
# synthetic state; compiled for arm64 iOS and linked into the Swift binary.
clang -target arm64-apple-ios16.0 -isysroot "$SDK" -O2 \
      -c Probe/explore_helper.c -o "$OUT/explore_helper.o"

swiftc -O -sdk "$SDK" -target arm64-apple-ios16.0 -parse-as-library \
       Probe/main.swift Probe/ProbeMinimal.swift "$OUT/explore_helper.o" \
       -o "$OUT/Probe.app/Probe"

sed "s|\$(PRODUCT_BUNDLE_IDENTIFIER)|$BUNDLE_ID|g; s|\$(EXECUTABLE_NAME)|Probe|g; s|\$(PRODUCT_NAME)|Probe|g" \
    Probe/Info.plist > "$OUT/Probe.app/Info.plist"
mkdir -p "$OUT/Payload"; cp -R "$OUT/Probe.app" "$OUT/Payload/"
( cd "$OUT" && zip -qry ../Probe-minimal.ipa Payload )
echo "built: out/Probe-minimal.ipa"
