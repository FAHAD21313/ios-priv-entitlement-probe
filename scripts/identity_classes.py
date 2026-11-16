#!/usr/bin/env python3
"""
identity_classes.py — list every codesigning identity on this Mac and the
Apple signing class it carries.

Why
---
Device run #3 recovered the real chain and computed the WHAT-IF map:

    leaf class 100.6.1.2   (bit 7)  -> accepted-mask only     <- the free cert
    leaf class 100.6.1.24  (bit 12) -> App Store Fast Path
    leaf class 100.6.1.36  (bit 43) -> App Store Fast Path
    leaf class 100.6.1.4   (bit 16) -> accepted-mask only
    leaf class 100.6.1.3   (bit 8)  -> REJECTED by the AND

So the question is no longer "can we forge a signature" but "which class does
each certificate in my keychain carry?"  This script answers that in one
command, without rebuilding the probe.

    python3 scripts/identity_classes.py

It uses `security` to enumerate identities and certificates, and reads the
Apple class extension OID directly out of the DER.
"""

import re
import subprocess
import sys

# Authored by A17 from the CoreTrust classifier, confirmed on the device.
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

# Measured from the running app's own CMS blob on iPhone19,7 / 24A446.
INTERMEDIATE_BITS = {4, 6, 7, 12, 13, 14, 15, 16, 17, 37, 38, 43, 44, 46}
ACCEPT_BITS = set(range(7, 17)) | {43, 44}
FASTPATH_BITS = {8, 12, 43}

# DER content bytes of the OID arc 1.2.840.113635.100.6.1
PREFIX = bytes.fromhex("2a864886f763640601")


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


def apple_oids(der):
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
        if oid and (oid.startswith("1.2.840.113635.") or
                    der[start:start + length].startswith(PREFIX)):
            out.append(oid)
        i = start + length
    return out


def classes(der):
    return [o for o in apple_oids(der) if o in OID_BITS]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def main():
    identities = run(["security", "find-identity", "-v", "-p", "codesigning"])
    rows = []
    for line in identities.splitlines():
        m = re.match(r"\s*\d+\)\s+([0-9A-Fa-f]{40})\s+\"(.*)\"", line)
        if m:
            rows.append((m.group(1).lower(), m.group(2)))

    if not rows:
        print("no codesigning identities found")
        print(identities[:500])
        return 1

    # Map SHA-1 -> DER certificate.
    certs = {}
    for hash_, _ in rows:
        pem = run(["security", "find-certificate", "-Z", "-p", "-a", hash_])
        parts = re.split(r"-----BEGIN CERTIFICATE-----", pem)
        for p in parts[1:]:
            body = p.split("-----END CERTIFICATE-----")[0]
            body = re.sub(r"\s+", "", body)
            import base64
            try:
                der = base64.b64decode(body)
            except Exception:
                continue
            # the first line of this invocation carries the SHA-1
            sha = re.search(r"SHA-1 hash: ([0-9A-Fa-f]{40})", pem)
            if sha:
                certs[sha.group(1).lower()] = der

    print()
    print("identity".ljust(52) + "class".ljust(34) + "bits".ljust(16) + "path")
    print("-" * 120)
    for hash_, name in rows:
        der = certs.get(hash_)
        cls = classes(der) if der else []
        if not cls:
            print(name[:51].ljust(52) + ("-" if der else "cert-lookup-failed").ljust(34)
                  + "-".ljust(16) + "unknown")
            continue
        for oid in cls:
            bits = OID_BITS[oid]
            effective = set(bits) & INTERMEDIATE_BITS
            in_mask = bool(effective & ACCEPT_BITS)
            fast = bool(effective & FASTPATH_BITS)
            path = "APP-STORE-FAST-PATH" if fast else ("accepted-mask-only" if in_mask else "rejected")
            print(name[:51].ljust(52) + oid.ljust(34)
                  + ",".join(map(str, bits)).ljust(16) + path)
    print()
    print("intermediate bits (measured on iPhone19,7):",
          ",".join(map(str, sorted(INTERMEDIATE_BITS))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
