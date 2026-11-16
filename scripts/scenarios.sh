#!/usr/bin/env bash
#
# scenarios.sh — build the differential matrix of signed probe variants.
#
# The experiment is differential: the SAME app source is signed and packaged
# several ways, and each variant isolates exactly one variable.  Every variant
# carries a `variant.txt` marker inside the bundle (sealed by the signature,
# so the app can report which variant it is), and all variants use the SAME
# bundle identifier, so the report accumulates in one container and a single
# `collect.sh` pulls everything at the end.
#
#   ./scripts/scenarios.sh --identity "Apple Development: YOU (TEAM)" --team TEAMID
#
# Options
#   --identity NAME     codesigning identity for the Apple-signed variants
#   --team ID           team identifier (9XXXXXXXXX)
#   --real-profile PATH Apple's own .mobileprovision (for the control variant)
#   --self-cert PATH    certificate for the self-signed variant
#   --self-key PATH     its private key
#   --out DIR           output directory (default out/variants)
#
# The matrix
#   A-control      Apple cert, no private entitlements, Apple's real profile
#   B-internal     Apple cert, private entitlements CLAIMED in the signature,
#                  crafted profile with AppleInternalProfile = true
#   C-provisioned  Apple cert, crafted profile that PROVISIONS the private
#                  keys but has no AppleInternalProfile
#   D-selfsigned   self-signed chain, private entitlements claimed, crafted
#                  CMS profile signed by the same self-signed identity
#   E-expired      Apple cert, crafted profile that is EXPIRED and
#                  LocalProvision = true
#   F-noprofile    Apple cert, private entitlements claimed, no profile at all
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

IDENTITY=""
TEAM=""
REAL_PROFILE=""
SELF_CERT=""
SELF_KEY=""
OUT=out/variants
BUNDLE_ID=${BUNDLE_ID:-com.research.ios27.privprobe}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2 ;;
    --team) TEAM="$2"; shift 2 ;;
    --real-profile) REAL_PROFILE="$2"; shift 2 ;;
    --self-cert) SELF_CERT="$2"; shift 2 ;;
    --self-key) SELF_KEY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$IDENTITY" ]]; then
  echo "error: --identity is required" >&2
  echo "       list identities with: security find-identity -v -p codesigning" >&2
  exit 2
fi
if [[ ! -d out/Probe.app ]]; then
  echo "error: out/Probe.app not found — run ./scripts/build_ios.sh first" >&2
  exit 1
fi

PRIV_KEYS=(
  com.apple.private.mobileinstall.allowedSPI
  com.apple.private.installcoordinationd.daemon
  com.apple.private.security.no-sandbox
  com.apple.private.security.no-container
)

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> building the variant matrix"
echo "    bundle id : $BUNDLE_ID"
echo "    identity  : $IDENTITY"
echo "    team      : ${TEAM:-<none>}"
echo

build_profile() {          # $1 = out path, rest = make_profile.py flags
  local dest="$1"; shift
  local tmp
  tmp="$(mktemp -d)"
  python3 scripts/make_profile.py --out "$tmp/p.plist" --bundle-id "$BUNDLE_ID" "$@"
  cp "$tmp/p.plist" "$dest"
  rm -rf "$tmp"
}

build_entitlements() {     # $1 = out path, $2 = "private" | "control"
  local dest="$1" mode="$2"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
    echo '<dict>'
    echo '	<key>get-task-allow</key>'
    echo '	<true/>'
    if [[ "$mode" == "private" ]]; then
      for k in "${PRIV_KEYS[@]}"; do
        echo "	<key>$k</key>"
        echo '	<true/>'
      done
    fi
    echo '</dict>'
    echo '</plist>'
  } > "$dest"
}

make_variant() {           # $1 = id, $2 = sign target, $3 = entitlements mode, $4 = profile kind
  local id="$1" signmode="$2" entmode="$3" profkind="$4"
  local dir="$OUT/$id"
  local app="$dir/Probe.app"
  mkdir -p "$dir"
  cp -R out/Probe.app "$app"

  # The marker travels inside the sealed bundle so the app can name its variant.
  printf '%s\n' "$id" > "$app/variant.txt"

  build_entitlements "$dir/entitlements.plist" "$entmode"

  case "$profkind" in
    real)
      if [[ -z "$REAL_PROFILE" || ! -f "$REAL_PROFILE" ]]; then
        echo "  ! variant $id needs --real-profile; skipping" >&2
        return 1
      fi
      cp "$REAL_PROFILE" "$app/embedded.mobileprovision"
      ;;
    none)
      rm -f "$app/embedded.mobileprovision"
      ;;
    crafted)
      build_profile "$app/embedded.mobileprovision" \
        --team "$TEAM" --apple-internal \
        $(printf -- '--entitlement %s ' "${PRIV_KEYS[@]}")
      ;;
    crafted-provisioned)
      # the private keys are provisioned, but the profile is NOT apple-internal
      build_profile "$app/embedded.mobileprovision" \
        --team "$TEAM" \
        $(printf -- '--entitlement %s ' "${PRIV_KEYS[@]}")
      ;;
    crafted-expired-local)
      build_profile "$app/embedded.mobileprovision" \
        --team "$TEAM" --apple-internal --local-provision --expiry-past \
        $(printf -- '--entitlement %s ' "${PRIV_KEYS[@]}")
      ;;
    crafted-cms-selfsigned)
      local tmp
      tmp="$(mktemp -d)"
      python3 scripts/make_profile.py --out "$tmp/p.plist" --bundle-id "$BUNDLE_ID" \
        --team "$TEAM" --apple-internal \
        $(printf -- '--entitlement %s ' "${PRIV_KEYS[@]}")
      if [[ -n "$SELF_CERT" && -n "$SELF_KEY" ]]; then
        openssl smime -sign -in "$tmp/p.plist" -signer "$SELF_CERT" -inkey "$SELF_KEY" \
          -outform DER -nodetach -binary -out "$app/embedded.mobileprovision"
      else
        cp "$tmp/p.plist" "$app/embedded.mobileprovision"
      fi
      rm -rf "$tmp"
      ;;
  esac

  case "$signmode" in
    apple)
      codesign --force --sign "$IDENTITY" --entitlements "$dir/entitlements.plist" \
               --timestamp=none "$app" >/dev/null 2>&1
      ;;
    self)
      if [[ -n "$SELF_CERT" && -n "$SELF_KEY" ]]; then
        local p12
        p12="$(mktemp -d)/id.p12"
        openssl pkcs12 -export -inkey "$SELF_KEY" -in "$SELF_CERT" -out "$p12" \
          -passout pass:probe -name probe >/dev/null 2>&1
        codesign --force --sign "$p12" --entitlements "$dir/entitlements.plist" \
                 --timestamp=none "$app" >/dev/null 2>&1
      else
        codesign --force --sign - --entitlements "$dir/entitlements.plist" \
                 --timestamp=none "$app" >/dev/null 2>&1
      fi
      ;;
    adhoc)
      codesign --force --sign - --entitlements "$dir/entitlements.plist" \
               --timestamp=none "$app" >/dev/null 2>&1
      ;;
  esac

  ( cd "$dir" && zip -qry "$id.ipa" Probe.app )
  printf '%-18s signed=%-10s entitlements=%-8s profile=%s\n' "$id" "$signmode" "$entmode" "$profkind"
}

build_variant() { :; }

make_variant A-control        apple control  real                  || true
make_variant B-internal       apple private crafted              || true
make_variant C-provisioned    apple control  crafted-provisioned  || true
make_variant D-selfsigned     self  private crafted-cms-selfsigned || true
make_variant E-expired-local  apple private crafted-expired-local || true
make_variant F-noprofile      apple private none                  || true

cat > "$OUT/manifest.json" <<EOF
{
  "bundle_id": "$BUNDLE_ID",
  "variants": {
    "A-control":       "Apple cert, no private entitlements, Apple's real profile",
    "B-internal":      "Apple cert, private entitlements claimed, crafted profile with AppleInternalProfile=true",
    "C-provisioned":   "Apple cert, crafted profile provisions the private keys, no AppleInternalProfile",
    "D-selfsigned":    "self-signed chain, private entitlements claimed, crafted CMS profile signed by the same identity",
    "E-expired-local": "Apple cert, crafted profile expired and LocalProvision=true",
    "F-noprofile":     "Apple cert, private entitlements claimed, no profile at all"
  }
}
EOF

echo
echo "built in $OUT"
ls -1 "$OUT"/*.ipa 2>/dev/null || true
echo
echo "next:"
echo "  1. install each .ipa on the device (same bundle id → one container)"
echo "  2. open the app once per install (it runs automatically and copies the"
echo "     report to the pasteboard)"
echo "  3. ./scripts/collect.sh   # pull the accumulated report"
echo "  4. ./scripts/verdict.py reports/probe-report.txt"
