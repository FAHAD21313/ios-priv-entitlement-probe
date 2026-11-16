#!/usr/bin/env python3
"""
make_crafted_ipa.py — build the differential experiment IPA in CI.

It takes the unsigned IPA and produces `Probe-B-crafted.ipa`, which differs
from the baseline in exactly two ways:

  1. embedded.mobileprovision is our CRAFTED profile declaring
     com.apple.private.mobileinstall.allowedSPI and no-sandbox, with
     AppleInternalProfile = true;
  2. the executable carries those SAME entitlements in its code signature
     (adhoc, via `codesign -s -` on macOS or `ldid -S` elsewhere).

The resulting IPA is still UNSIGNED WITH YOUR APPLE CERTIFICATE. It is meant
to be downloaded from CI and re-signed with your free Developer certificate
by your usual sideload tool. Nothing here needs a Mac, a certificate, or a
password.

The report will name the variant through the `variant.txt` marker, and the
DELTA section answers the question: does the kernel HONOUR the private
entitlement, or does it merely store it?
"""

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILE = os.path.join(ROOT, "out", "variants", "B-internal.mobileprovision")
ENTITLEMENTS = os.path.join(ROOT, "out", "variants", "private-entitlements.plist")
VARIANT = "B-internal"


def sign(binary):
    if shutil.which("codesign"):
        # macOS: an adhoc signature is enough to place the entitlements blob
        # in the CodeDirectory. The user's tool replaces the signature later.
        r = subprocess.run(["codesign", "--force", "--sign", "-",
                            "--entitlements", ENTITLEMENTS,
                            "--timestamp=none", binary],
                           capture_output=True, text=True)
        return "codesign adhoc: " + ("ok" if r.returncode == 0 else r.stderr.strip()[:200])
    if shutil.which("ldid"):
        r = subprocess.run(["ldid", "-S" + ENTITLEMENTS, binary],
                           capture_output=True, text=True)
        return "ldid: " + ("ok" if r.returncode == 0 else r.stderr.strip()[:200])
    return "no signer found — the binary keeps its unsigned entitlements"


def main():
    src = os.path.join(ROOT, "out", "Probe-unsigned.ipa")
    dst = os.path.join(ROOT, "out", "Probe-B-crafted.ipa")
    if not os.path.exists(src):
        print("error:", src, "not found — run build_ios.sh first", file=sys.stderr)
        return 1
    for f in (PROFILE, ENTITLEMENTS):
        if not os.path.exists(f):
            print("error:", f, "missing", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(src) as z:
            z.extractall(td)
        app = os.path.join(td, "Payload", "Probe.app")
        binary = os.path.join(app, "Probe")
        shutil.copyfile(PROFILE, os.path.join(app, "embedded.mobileprovision"))
        with open(os.path.join(app, "variant.txt"), "w") as f:
            f.write(VARIANT + "\n")
        print("sign:", sign(binary))

        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as out:
            for base, _dirs, files in os.walk(os.path.join(td, "Payload")):
                for name in files:
                    full = os.path.join(base, name)
                    arc = os.path.relpath(full, td)
                    out.write(full, arc)

    p = plistlib.load(open(PROFILE, "rb"))
    print("wrote", dst)
    print("  profile entitlements:", sorted(k for k in p["Entitlements"]
                                            if k.startswith("com.apple.private")))
    print("  AppleInternalProfile:", p.get("AppleInternalProfile"))
    print()
    print("NEXT: re-sign this IPA with your FREE Apple Developer certificate,")
    print("then install it and open it once.  The report's DELTA section will")
    print("show whether the private entitlement was merely STORED or actually")
    print("HONOURED (private-entropy-honoured-count).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
