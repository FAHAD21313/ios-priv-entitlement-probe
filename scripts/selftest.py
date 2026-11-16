#!/usr/bin/env python3
"""
selftest.py — local checks that need neither a device nor macOS.

  1. the Swift source's OID -> CT-policy table satisfies the invariants the
     research depends on (bit 7 comes from 100.6.1.2; the App Store fast-path
     bits are 8, 12 and 43; the accept mask contains them where expected);
  2. make_profile.py produces a profile with the keys the probe reads;
  3. verdict.py splits an accumulated report into runs and produces the
     cross-run table.

Run:  python3 scripts/selftest.py
"""

import os
import plistlib
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWIFT = os.path.join(ROOT, "Probe", "ProbeApp.swift")

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {detail}")
        failures.append(name)


def swift_oid_table():
    """Parse the Swift table of OID -> BIT NUMBERS (not hex masks)."""
    src = open(SWIFT, encoding="utf-8").read()
    out = {}
    for m in re.finditer(r'"(1\.2\.840\.113635\.[0-9.]+)"\s*:\s*\[([0-9,\s]+?)\]', src):
        out[m.group(1)] = [int(x) for x in m.group(2).split(",") if x.strip()]
    return out


def test_oid_table():
    print("1. the OID -> CT-policy table")
    table = swift_oid_table()
    check("table is not empty", len(table) >= 30, f"(got {len(table)})")
    expect = {
        "1.2.840.113635.100.6.1.2": [7],
        "1.2.840.113635.100.6.1.3": [8],
        "1.2.840.113635.100.6.1.3.1": [9],
        "1.2.840.113635.100.6.1.4": [16],
        "1.2.840.113635.100.6.1.6": [10],
        "1.2.840.113635.100.6.1.6.1": [11],
        "1.2.840.113635.100.6.1.7": [17],
        "1.2.840.113635.100.6.1.9": [6],
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
        "1.2.840.113635.100.6.1.9.1": [46],
        "1.2.840.113635.100.6.2.6": [5],
        "1.2.840.113635.100.6.2.18": [8, 9, 10, 11],
        "1.2.840.113635.100.6.2.14": [22, 25, 48],
        "1.2.840.113635.100.6.2.17": [26, 39],
        "1.2.840.113635.100.6.2.20": [20, 47],
        "1.2.840.113635.100.6.22": [3, 20],
        "1.2.840.113635.100.6.22.1": [47],
        "1.2.840.113635.100.6.29": [25],
        "1.2.840.113635.100.6.64.3": [22],
        "1.2.840.113635.100.6.71.1": [34, 35],
        "1.2.840.113635.100.8.3": [23, 42, 45],
        "1.2.840.113635.100.12.14": [26],
        "1.2.840.113635.100.12.19": [39],
        "1.2.840.113635.100.6.2.1": [4, 6, 7, 12, 13, 14, 15, 16, 17, 37, 38, 43, 44, 46],
    }
    for oid, bits in expect.items():
        check(f"{oid} -> {bits}", table.get(oid) == bits,
              f"(got {table.get(oid)!r})")

    def mask(bits):
        m = 0
        for b in bits:
            m |= 1 << b
        return m

    accept = 0x0000_1800_0001_FF80
    fast = 0x0000_0800_0000_1100
    internal = 0x0000_1000_0001_EE80
    check("accept mask is bits 7..16,43,44",
          [i for i in range(64) if accept & (1 << i)] == list(range(7, 17)) + [43, 44])
    check("fast-path mask is bits 8,12,43",
          [i for i in range(64) if fast & (1 << i)] == [8, 12, 43])
    check("internal-profile mask is bits 7,9-11,13-16,44",
          [i for i in range(64) if internal & (1 << i)] == [7, 9, 10, 11, 13, 14, 15, 16, 44])
    check("fast-path mask is inside the accept mask", (fast & ~accept) == 0)

    # The classes that clear the fast path must exist and be Apple-issued.
    fast_sources = {oid for oid, b in table.items() if mask(b) & fast}
    check("fast-path bits have at least three sources", len(fast_sources) >= 3,
          f"({sorted(fast_sources)})")
    for oid in fast_sources:
        check(f"fast-path source {oid} is an Apple class",
              oid.startswith("1.2.840.113635.100."))
    # The free developer class must grant bit 7 and nothing outside the mask.
    dev = table.get("1.2.840.113635.100.6.1.2", [])
    check("100.6.1.2 grants exactly bit 7", dev == [7])
    check("bit 7 is inside the accept mask", bool(accept & (1 << 7)))


def test_profile():
    print("2. make_profile.py")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "p.plist")
        subprocess.run([sys.executable, os.path.join(HERE, "make_profile.py"),
                        "--out", out,
                        "--entitlement", "com.apple.private.mobileinstall.allowedSPI",
                        "--apple-internal", "--local-provision",
                        "--team", "TEAM123456"], check=True,
                       stdout=subprocess.DEVNULL)
        p = plistlib.load(open(out, "rb"))
        check("Entitlements carries the private key",
              "com.apple.private.mobileinstall.allowedSPI" in p["Entitlements"])
        check("AppleInternalProfile is true", p.get("AppleInternalProfile") is True)
        check("LocalProvision is true", p.get("LocalProvision") is True)
        check("application-identifier present",
              "application-identifier" in p["Entitlements"])
        check("UUID present", bool(p.get("UUID")))
        check("ExpirationDate present", "ExpirationDate" in p)


SYNTHETIC = """=== iOS private-entitlement probe — differential run ===
run-utc=2026-11-16T00:00:00Z
variant-label=A-control
scenario-id=apple-dev+plain-plist+no-priv+not-internal
predicted-ct-policy=0x0000000000000080
predicted-ct-policy-in-accept-mask=YES
claimed-private=-
honoured-private=-
private-entropy-honoured-count=0
write-outside-container=DENIED
mis-validate-self=0xe8008015
mis-profile-validate=0x00000000
install-gate-allowedSPI=absent
--- VERDICTS ---
VERDICT T01 CONFIRMED | runtime anchors | anchors-contains-public-apple-root=YES
VERDICT T02 CONFIRMED | bit 7 | leaf-bits=0x80
VERDICT T07 N/A | no profile | -
--- end of run ===
=== iOS private-entitlement probe — differential run ===
run-utc=2026-11-16T01:00:00Z
variant-label=B-internal
scenario-id=apple-dev+plain-plist+provisions-priv+internal
predicted-ct-policy=0x0000000000000080
predicted-ct-policy-in-accept-mask=YES
claimed-private=com.apple.private.mobileinstall.allowedSPI
honoured-private=com.apple.private.mobileinstall.allowedSPI
private-entropy-honoured-count=1
write-outside-container=ALLOWED
mis-validate-self=0x00000000
mis-profile-validate=0xe8008015
install-gate-allowedSPI=PRESENT
--- VERDICTS ---
VERDICT T01 CONFIRMED | runtime anchors | anchors-contains-public-apple-root=YES
VERDICT T02 CONFIRMED | bit 7 | leaf-bits=0x80
VERDICT T07 CONFIRMED | no CMS check | honoured despite a failing signature
--- end of run ===
"""


def test_verdict():
    print("3. verdict.py")
    with tempfile.TemporaryDirectory() as td:
        rep = os.path.join(td, "r.txt")
        open(rep, "w").write(SYNTHETIC)
        out = subprocess.run([sys.executable, os.path.join(HERE, "verdict.py"), rep],
                             capture_output=True, text=True)
        check("verdict.py exits 0", out.returncode == 0, out.stderr[-400:])
        check("two runs are found", "A-control" in out.stdout and "B-internal" in out.stdout)
        check("the table has T07", "T07" in out.stdout)
        check("the differentiator is reported", "DIFFERENTIATORS" in out.stdout)
        check("T07 differs between the runs",
              "T07" in out.stdout.split("DIFFERENTIATORS")[-1])


def main():
    test_oid_table()
    test_profile()
    test_verdict()
    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
