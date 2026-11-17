#!/usr/bin/env bash
# Build the minimal dyld4-OOB + csparser collector probe (unsigned IPA).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OUT=out/Minimal
BUNDLE_ID=${BUNDLE_ID:-com.research.ios27.privprobe}
rm -rf "$OUT" out/Probe-minimal.ipa
mkdir -p "$OUT/Probe.app"
swiftc -O -sdk "$SDK" -target arm64-apple-ios16.0 -parse-as-library \
       -o "$OUT/Probe.app/Probe" Probe/ProbeMinimal.swift
sed "s|\$(PRODUCT_BUNDLE_IDENTIFIER)|$BUNDLE_ID|g; s|\$(EXECUTABLE_NAME)|Probe|g; s|\$(PRODUCT_NAME)|Probe|g" \
    Probe/Info.plist > "$OUT/Probe.app/Info.plist"
mkdir -p "$OUT/Payload"; cp -R "$OUT/Probe.app" "$OUT/Payload/"
( cd "$OUT" && zip -qry ../Probe-minimal.ipa Payload )
echo "built: out/Probe-minimal.ipa"
