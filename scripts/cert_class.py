#!/usr/bin/env python3
"""
cert_class.py — read the Apple signing class out of a provisioning profile or
a signed IPA, on ANY machine. No macOS, no `security`, no Xcode needed.

The probe already prints this on the device as `profile-cert[0]-apple-oids`;
this tool is the offline equivalent, for when you have the signed file but not
a Mac.

    python3 scripts/cert_class.py MyProfile.mobileprovision
    python3 scripts/cert_class.py MyApp.ipa
    python3 scripts/cert_class.py MyCert.p12 --password '...'   # needs openssl

For each certificate it prints the Apple class OID, the CT-policy bits that
class grants, and the path those bits produce with the intermediate measured
on iPhone19,7 / iOS 27.0.1.
"""

import argparse
import os
import re
import sys
import zipfile

# A17's table, confirmed by the device.
OID_BITS = {
    "1.2.840.113635.100.6.1.2": [7],
    "1.2.840.113635.100.6.1.3": [8],
    "1.2.840.113635.100.6.1.3.1": [9],
    "1.2.840.113635.100.6.1.4": [16],
    "1.2.840.113635.100.6.1.6": [10],
    "1.2.840.113635.100.6.1.6.1": [11],
    "1.2.840.113635.100.6.1.7": [17],
    "1.2.840.113635.100.6.1.9": [6],
    "1.2.840.113635.100.6.1.9.1": [46],
    "1.2.840.113635.100.6.1.12": [4],
    "1.2.840.113635.100.6.1.13": [5],
    "1.2.840.113635.100.6.1.15": [31],
    "1.2.840.113635.100.6.1.24": [12],
    "1.2.840.113635.100.6.1.24.1": [13],
    "1.2.840.113635.100.6.1.25.1": [14],
    "1.2.840.113635.100.6.1.25.2": [15],
    "1.2.840.113635.100.6.1.32": [37],
    "1.2.840.113635.100.6.1.34": [38],
    "1.2.840.113635.100.6.1.36": [43],
    "1.2.840.113635.100.6.1.36.1": [44],
}

# Measured from the running app's own CMS blob, iPhone19,7 / 24A446.
INTERMEDIATE_BITS = {4, 6, 7, 12, 13, 14, 15, 16, 17, 37, 38, 43, 44, 46}
ACCEPT_BITS = set(range(7, 17)) | {43, 44}
FASTPATH_BITS = {8, 12, 43}


def decode_oid(content):
    if not content:
        return None
    parts = [str(content[0] // 40), str(content[0] % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def apple_classes(der):
    out = []
    i = 0
    while i + 2 < len(der):
        if der[i] != 0x06:
            i += 1
            continue
        length = der[i + 1]
        start = i + 2
        if length & 0x80:
            n = length & 0x7f
            if not 0 < n <= 4 or start + n > len(der):
                i += 1
                continue
            length = int.from_bytes(der[start:start + n], "big")
            start += n
        if not 0 < length <= 32 or start + length > len(der):
            i += 1
            continue
        oid = decode_oid(der[start:start + length])
        if oid in OID_BITS and oid not in out:
            out.append(oid)
        i = start + length
    return out


def profile_bytes_from(data):
    """Pull the plist out of a CMS-wrapped mobileprovision."""
    import plistlib
    m = re.search(rb"<\?xml|bplist00", data)
    if not m:
        return None
    rest = data[m.start():]
    for end in (rest.find(b"</plist>"), len(rest)):
        if end <= 0:
            continue
        try:
            return plistlib.loads(rest[:end + 8 if end != len(rest) else end])
        except Exception:
            continue
    return None


def certs_from_path(path, password=None):
    import plistlib
    ext = os.path.splitext(path)[1].lower()
    if ext == ".ipa":
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if n.endswith("embedded.mobileprovision")]
            if not names:
                return [], "no embedded.mobileprovision in the IPA"
            data = z.read(names[0])
    elif ext in (".p12", ".pfx"):
        import subprocess
        cmd = ["openssl", "pkcs12", "-in", path, "-clcerts", "-nokeys",
               "-passin", "pass:" + (password or "")]
        out = subprocess.run(cmd, capture_output=True).stdout
        if not out:
            return [], "openssl could not read the p12 (wrong password?)"
        return [out], None
    else:
        data = open(path, "rb").read()

    p = profile_bytes_from(data)
    if not p:
        return [], "no plist found"
    return list(p.get("DeveloperCertificates", [])), p.get("TeamIdentifier")


def verdict(oid):
    bits = OID_BITS.get(oid, [])
    effective = set(bits) & INTERMEDIATE_BITS
    in_mask = bool(effective & ACCEPT_BITS)
    fast = bool(effective & FASTPATH_BITS)
    path = "APP-STORE-FAST-PATH" if fast else ("accepted-mask-only" if in_mask else "rejected")
    return bits, path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--password", default="", help="p12 password, if applicable")
    args = ap.parse_args()

    for path in args.files:
        print(f"\n=== {path}")
        certs, team = certs_from_path(path, args.password)
        if isinstance(team, str):
            print("  ", team)
            continue
        print("  team:", team, " certificates:", len(certs))
        if not certs:
            print("   no certificates found")
            continue
        for i, der in enumerate(certs):
            classes = apple_classes(der)
            print(f"  cert[{i}]:")
            if not classes:
                print("     no Apple signing class OID found")
            for oid in classes:
                bits, path_verdict = verdict(oid)
                print(f"     class  : {oid}")
                print(f"     bits   : {','.join(map(str, bits))}")
                print(f"     path   : {path_verdict}")
                if path_verdict == "APP-STORE-FAST-PATH":
                    print("     >>> THIS IS THE ONE <<<")
    return 0


if __name__ == "__main__":
    sys.exit(main())
