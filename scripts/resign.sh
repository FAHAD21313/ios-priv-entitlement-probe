#!/usr/bin/env bash
# Produce the signed variants of the probe that isolate one variable each.
#
#   VARIANT A (control)   Apple developer signature  + Apple's real profile
#   VARIANT B             Apple developer signature  + CRAFTED profile
#   VARIANT C             LOCAL re-signature        + CRAFTED profile
#                         (+ the private entitlements claimed in the signature)
#
# VARIANT B works because a provisioning profile is NOT covered by the code
# signature: the file can be replaced after signing.
#
# VARIANT C is the real probe: the code signature is ours, so Apple's signing
# service never sees (and therefore never filters) the private entitlements we
# declare.
#
#   ./scripts/resign.sh --variant C --identity "Apple Development: YOU (TEAM)" \
#        --real-profile ~/Downloads/Profile.mobileprovision
#
# Optional: --cert / --key (PEM) to wrap the crafted profile in a real CMS
# container signed with your own identity.  Without them the crafted profile
# is written as a plain plist.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VARIANT=A
IDENTITY=""
REAL_PROFILE=""
CERT=""
KEY=""
TEAM=""
OUT=out

while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant) VARIANT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --real-profile) REAL_PROFILE="$2"; shift 2 ;;
    --cert) CERT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --team) TEAM="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$IDENTITY" ]]; then
  echo "error: --identity is required (the codesigning identity to use)" >&2
  echo "       list them with: security find-identity -v -p codesigning" >&2
  exit 2
fi

APP="$OUT/Probe.app"
[[ -d "$APP" ]] || { echo "error: $APP not found — run ./scripts/build_ios.sh first" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PRIV_KEYS=(
  com.apple.private.mobileinstall.allowedSPI
  com.apple.private.installcoordinationd.daemon
  com.apple.private.security.no-sandbox
  com.apple.private.security.no-container
)

echo "==> variant $VARIANT"

# ---------------------------------------------------------------- entitlements
if [[ "$VARIANT" == "C" ]]; then
  PLIST="$WORK/entitlements.plist"
  cat > "$PLIST" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
	<key>com.apple.private.mobileinstall.allowedSPI</key>
	<true/>
	<key>com.apple.private.installcoordinationd.daemon</key>
	<true/>
	<key>com.apple.private.security.no-sandbox</key>
	<true/>
	<key>com.apple.private.security.no-container</key>
	<true/>
</dict>
</plist>
PL
else
  PLIST="$WORK/entitlements.plist"
  cat > "$PLIST" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>
PL
fi

# ------------------------------------------------------------------- the profile
PROFILE_SRC="$WORK/embedded.mobileprovision"
if [[ "$VARIANT" == "A" ]]; then
  if [[ -z "$REAL_PROFILE" || ! -f "$REAL_PROFILE" ]]; then
    echo "error: variant A needs --real-profile <your .mobileprovision>" >&2
    exit 2
  fi
  cp "$REAL_PROFILE" "$PROFILE_SRC"
  echo "    profile: real (Apple-signed)"
else
  ARGS=(--out "$WORK/profile.plist" --team "$TEAM")
  for k in "${PRIV_KEYS[@]}"; do ARGS+=(--entitlement "$k"); done
  ARGS+=(--apple-internal)
  python3 scripts/make_profile.py "${ARGS[@]}"
  if [[ -n "$CERT" && -n "$KEY" ]]; then
    openssl smime -sign -in "$WORK/profile.plist" -signer "$CERT" -inkey "$KEY" \
      -outform DER -nodetach -binary -out "$PROFILE_SRC"
    echo "    profile: crafted, CMS-wrapped with your own identity"
  else
    cp "$WORK/profile.plist" "$PROFILE_SRC"
    echo "    profile: crafted, plain plist (no --cert/--key given)"
  fi
fi
cp "$PROFILE_SRC" "$APP/embedded.mobileprovision"

# ----------------------------------------------------------------- the signature
codesign --force --sign "$IDENTITY" --entitlements "$PLIST" --timestamp=none "$APP" 2>&1 | sed 's/^/    /'
codesign --verify --verbose=2 "$APP" 2>&1 | sed 's/^/    /' || true

echo
echo "built: $APP  (variant $VARIANT)"
echo "verify with: codesign -d --entitlements - $APP"
