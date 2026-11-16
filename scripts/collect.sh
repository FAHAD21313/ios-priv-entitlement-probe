#!/usr/bin/env bash
#
# collect.sh — pull the accumulated probe report off the device.
#
# The probe appends every run to `Documents/probe-report.txt` inside its own
# container.  Because every variant uses the SAME bundle identifier, the
# container is shared, so one pull returns every run at once.
#
# It tries, in order:
#   1. pymobiledevice3  (python -m pymobiledevice3 ... / the `pymobiledevice3` CLI)
#   2. idevicefs        (libimobiledevice)
#   3. ideviceinstaller + afc (older tooling)
#
# If none is available it prints exactly what to do by hand (the app also
# copies the report to the pasteboard on every run).
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BUNDLE_ID=${BUNDLE_ID:-com.research.ios27.privprobe}
OUT=${OUT:-reports/probe-report.txt}
mkdir -p "$(dirname "$OUT")"

have() { command -v "$1" >/dev/null 2>&1; }

echo "==> collecting $BUNDLE_ID"

if have pymobiledevice3; then
  echo "    using pymobiledevice3"
  TMP="$(mktemp -d)"
  if pymobiledevice3 afc pull "$BUNDLE_ID" "$TMP/Documents" 2>/dev/null \
     || pymobiledevice3 developer dvt ls 2>/dev/null; then
    :
  fi
  if [[ -f "$TMP/Documents/probe-report.txt" ]]; then
    cp "$TMP/Documents/probe-report.txt" "$OUT"
    rm -rf "$TMP"
    echo "    wrote $OUT"
    exit 0
  fi
  rm -rf "$TMP"
fi

if have idevicefs; then
  echo "    using idevicefs"
  TMP="$(mktemp -d)"
  if idevicefs -u "$(idevice_id -u 2>/dev/null || echo 1)" \
       afc "${TMP}:/Documents" >/dev/null 2>&1; then
    :
  fi
  if [[ -f "$TMP/probe-report.txt" ]]; then
    cp "$TMP/probe-report.txt" "$OUT"
    rm -rf "$TMP"
    echo "    wrote $OUT"
    exit 0
  fi
  rm -rf "$TMP"
fi

cat <<EOF

    no automatic collector found.

    Do it by hand — any one of these works:

      A) the app already copied the report to the pasteboard on every run;
         paste it into a file and run:
             ./scripts/verdict.py your-file.txt

      B) enable the device's "Files" app and use the app's Documents folder
         (the app declares UIFileSharingEnabled):
             open the Files app → On My iPhone → Priv-Ent Probe →
             probe-report.txt → copy it here.

      C) install a collector:
             python3 -m pip install pymobiledevice3
         then re-run this script.

    Expected destination: $OUT
EOF
exit 1
