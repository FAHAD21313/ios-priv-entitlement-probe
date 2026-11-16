#!/usr/bin/env python3
"""
inject_profile.py — put a crafted embedded.mobileprovision into a signed IPA,
on any OS. This is only the PACKAGING step: re-signing with your Apple
certificate is still done by your usual sideload tool (Sideloadly, ESign,
AltStore, zsign, ...), using `private-entitlements.plist`.

    python3 scripts/inject_profile.py input.ipa \
        out/variants/B-internal.mobileprovision \
        -o Probe-B-internal.ipa

Why this is worth trying
------------------------
The device's own report showed the app launches with a provisioning profile
whose contents are attacker-writable (A15: the kernel parses it and never
verifies its CMS; A16: libmis does not re-verify it at launch). So the next
experiment is not about getting another certificate — it is about putting the
private entitlement in BOTH places:

  1. the app's code signature  -> private-entitlements.plist (your signing tool)
  2. the embedded profile      -> B-internal.mobileprovision (this script)

If the kernel honours the entitlement, the report's DELTA section will show
`private-entropy-honoured-count=1` and the install gate will read PRESENT.
"""

import argparse
import os
import shutil
import sys
import zipfile


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ipa")
    ap.add_argument("profile")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    with zipfile.ZipFile(args.ipa, "r") as z:
        names = z.namelist()
        targets = [n for n in names if n.endswith("embedded.mobileprovision")]
        if not targets:
            print("error: no embedded.mobileprovision in the IPA", file=sys.stderr)
            return 1
        profile = open(args.profile, "rb").read()
        tmp = args.output + ".tmp"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as out:
            for item in z.infolist():
                data = profile if item.filename in targets else z.read(item.filename)
                out.writestr(item, data)
        shutil.move(tmp, args.output)

    print(f"wrote {args.output}")
    print("  replaced:", ", ".join(targets))
    print("  with    :", args.profile, f"({len(profile)} bytes)")
    print()
    print("NEXT — re-sign with your free Apple Developer certificate and the")
    print("private entitlements, e.g. with zsign:")
    print()
    print("  zsign -k cert.p12 -p PASSWORD -m " + args.profile + " \\")
    print("        -e out/variants/private-entitlements.plist \\")
    print("        -o Probe-B-signed.ipa " + args.output)
    print()
    print("(or use the equivalent 'import entitlements' option in your tool)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
