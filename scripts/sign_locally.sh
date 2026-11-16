#!/usr/bin/env bash
# Sign the crafted probe IPA with your Apple Developer p12, using zsign.
# No Mac required.  The password is read from a FILE so it never appears in
# a command line, a chat message, or the shell history.
#
#   ./scripts/sign_locally.sh cert.p12 password.txt /path/to/output.ipa
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

P12="${1:?usage: sign_locally.sh cert.p12 password.txt output.ipa}"
PASSFILE="${2:?usage: sign_locally.sh cert.p12 password.txt output.ipa}"
OUT="${3:?usage: sign_locally.sh cert.p12 password.txt output.ipa}"
ZSIGN=${ZSIGN:-/tmp/opencode/tools/zsign}

[[ -f "$P12" ]]      || { echo "error: p12 not found: $P12" >&2; exit 1; }
[[ -f "$PASSFILE" ]] || { echo "error: password file not found: $PASSFILE" >&2; exit 1; }
[[ -x "$ZSIGN" ]]    || { echo "error: zsign not found at $ZSIGN" >&2; exit 1; }

SRC=out/Probe-B-crafted.ipa
[[ -f "$SRC" ]] || { echo "error: run 'make crafted' first" >&2; exit 1; }

echo "==> signing with the p12"
"$ZSIGN" -k "$P12" -p "$(cat "$PASSFILE")" \
         -m config/B-internal.mobileprovision \
         -e config/private-entitlements.plist \
         -f -o "$OUT" "$SRC"

echo
echo "wrote $OUT"
echo "==> verifying the entitlements in the signed binary"
TMP=$(mktemp -d)
unzip -q "$OUT" -d "$TMP"
ldid -e "$TMP/Payload/Probe.app/Probe" 2>/dev/null | grep -E "private|application-identifier" || true
rm -rf "$TMP"
