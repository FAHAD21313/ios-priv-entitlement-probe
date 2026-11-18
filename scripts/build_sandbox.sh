#!/usr/bin/env bash
# Build the single-button sandbox reachability probe (unsigned IPA).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OUT=out/Sandbox
BUNDLE_ID=${BUNDLE_ID:-com.research.ios27.sandboxprobe}
rm -rf "$OUT" out/Sandbox-probe.ipa
mkdir -p "$OUT/Probe.app"

clang -target arm64-apple-ios16.0 -isysroot "$SDK" -O2 \
      -c Probe/sandbox_helper.c -o "$OUT/sandbox_helper.o"

swiftc -O -sdk "$SDK" -target arm64-apple-ios16.0 \
       Probe/main.swift Probe/SandboxProbe.swift "$OUT/sandbox_helper.o" \
       -framework IOKit \
       -o "$OUT/Probe.app/Probe"

sed "s|\$(PRODUCT_BUNDLE_IDENTIFIER)|$BUNDLE_ID|g; s|\$(EXECUTABLE_NAME)|Probe|g; s|\$(PRODUCT_NAME)|Probe|g" \
    Probe/Info.plist > "$OUT/Probe.app/Info.plist"
mkdir -p "$OUT/Payload"; cp -R "$OUT/Probe.app" "$OUT/Payload/"
( cd "$OUT" && zip -qry ../Sandbox-probe.ipa Payload )
echo "built: out/Sandbox-probe.ipa"
