#!/usr/bin/env python3
"""
execsegflags.py — read the CT-policy candidate field out of a Mach-O's
embedded code signature.

Why
---
On iOS 27.0.1 the kernel's AMFI kept accepts a code signature only if the
CodeDirectory carries a bit from a specific mask:

    AMFI accept mask = 0x000018000001ff80   (bits 7-16, 43, 44)

That field is the CodeDirectory's `execSegFlags` (offset 0x50, CodeDirectory
version >= 0x20400).  Apple's own flags occupy bits 4-10:

    CS_EXECSEG_MAIN_BINARY      0x0001
    CS_EXECSEG_ALLOW_UNSIGNED   0x0010
    CS_EXECSEG_DEBUGGER         0x0020
    CS_EXECSEG_JIT              0x0040
    CS_EXECSEG_SKIP_LIBRARIES   0x0080
    CS_EXECSEG_CAN_LOAD_CDHASH  0x0100   (bit 8)
    CS_EXECSEG_CAN_EXEC_CDHASH  0x0200   (bit 9)
    CS_EXECSEG_APP_MAIN_BINARY  0x0400   (bit 10)

and AMFI's App Store fast path additionally wants bits {8, 12, 43}.

Measured baseline (iOS 27.0.1, free developer account, sideloaded):
    execSegFlags = 0x1100000000000000   (bits 60, 61)  -> correctly refused

So the target is an Apple-signed CodeDirectory whose execSegFlags carries a bit
from the accept mask.  This tool prints that value for any Mach-O you point it
at — in particular for an App Store signed app, which is the template we are
looking for.

Usage
-----
    ./execsegflags.py <path-to-macho> [<path-to-macho> ...]
    ./execsegflags.py --dir <directory>          # scan a directory tree
"""

import argparse
import os
import struct
import sys

ACCEPT_MASK = 0x000018000001FF80
CS_EXECSEG = {
    0x0001: "CS_EXECSEG_MAIN_BINARY",
    0x0010: "CS_EXECSEG_ALLOW_UNSIGNED",
    0x0020: "CS_EXECSEG_DEBUGGER",
    0x0040: "CS_EXECSEG_JIT",
    0x0080: "CS_EXECSEG_SKIP_LIBRARIES",
    0x0100: "CS_EXECSEG_CAN_LOAD_CDHASH",
    0x0200: "CS_EXECSEG_CAN_EXEC_CDHASH",
    0x0400: "CS_EXECSEG_APP_MAIN_BINARY",
}


def bits(v):
    return [i for i in range(64) if (v >> i) & 1]


def named(v):
    out = []
    for m, n in CS_EXECSEG.items():
        if v & m:
            out.append(f"{n}(0x{m:x})")
    return ",".join(out) if out else "-"


def thin_slice(d):
    """Return the arm64e slice of a Mach-O (thin or fat)."""
    if len(d) < 32:
        return None
    magic = struct.unpack_from("<I", d, 0)[0]
    if magic == 0xFEEDFACF:
        return d
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        n = struct.unpack_from(">I", d, 4)[0]
        best = None
        for i in range(n):
            cpu, sub, off, size, _ = struct.unpack_from(">iiIII", d, 8 + i * 20)
            if cpu == 0x0100000C:          # arm64
                sl = d[off:off + size]
                if best is None or sub == 2:  # prefer arm64e
                    best = sl
        return best
    return None


def read(path):
    try:
        with open(path, "rb") as f:
            d = f.read()
    except OSError as e:
        return [f"error: {e}"]
    sl = thin_slice(d)
    if not sl:
        return ["not a 64-bit Mach-O"]
    if len(sl) < 32:
        return ["truncated"]
    ncmds = struct.unpack_from("<I", sl, 16)[0]
    off = 32
    cs = None
    for _ in range(ncmds):
        if off + 8 > len(sl):
            break
        cmd, csz = struct.unpack_from("<II", sl, off)
        if csz < 8:
            break
        if cmd == 0x1D:                       # LC_CODE_SIGNATURE
            cs = struct.unpack_from("<II", sl, off + 8)
        off += csz
    if not cs:
        return ["no LC_CODE_SIGNATURE (not individually signed)"]
    do, dsz = cs
    if do + dsz > len(sl) or dsz < 16:
        return ["signature out of range"]
    sb = sl[do:do + dsz]
    if struct.unpack_from(">I", sb, 0)[0] != 0xFADE0CC0:
        return ["not an embedded-signature SuperBlob"]
    cnt = struct.unpack_from(">I", sb, 8)[0]
    slots = {}
    for k in range(min(cnt, 32)):
        t, o = struct.unpack_from(">II", sb, 12 + k * 8)
        slots.setdefault(t, o)
    if 0 not in slots:
        return ["no CodeDirectory slot"]
    cd = sb[slots[0]:]
    if len(cd) < 0x40 or struct.unpack_from(">I", cd, 0)[0] != 0xFADE0C02:
        return ["bad CodeDirectory"]
    ver = struct.unpack_from(">I", cd, 8)[0]
    flags = struct.unpack_from(">I", cd, 12)[0]
    ioff = struct.unpack_from(">I", cd, 20)[0]
    end = cd.find(b"\x00", ioff)
    ident = cd[ioff:end].decode("utf-8", "replace") if 0 < ioff < len(cd) else "-"
    out = [f"identifier            = {ident}",
           f"codedirectory-version = 0x{ver:x}",
           f"codedirectory-flags   = 0x{flags:x}"]
    if ver >= 0x20400 and len(cd) >= 0x58:
        # NOTE: every field of a CodeDirectory is BIG-ENDIAN, like the
        # SuperBlob header.  Only the Mach-O structures around it are
        # little-endian.  Reading these as little-endian silently byte-swaps
        # the value.
        ef = struct.unpack_from(">Q", cd, 0x50)[0]
        base = struct.unpack_from(">Q", cd, 0x40)[0]
        lim = struct.unpack_from(">Q", cd, 0x48)[0]
        out.append(f"execSegFlags          = 0x{ef:016x}")
        out.append(f"execSegFlags bits     = {bits(ef)}")
        out.append(f"execSegFlags named    = {named(ef)}")
        out.append(f"execSegBase/Limit     = 0x{base:x} / 0x{lim:x}")
        out.append(f"INTERSECTS ACCEPT     = {'YES' if ef & ACCEPT_MASK else 'no'}"
                   f"  (mask 0x{ACCEPT_MASK:016x}, bits {bits(ACCEPT_MASK)})")
    else:
        out.append("execSegFlags          = n/a (CodeDirectory < 0x20400)")
    # alternate CodeDirectory slots matter for fat binaries
    alts = [t for t in slots if 0x1000 <= t <= 0x1004]
    if alts:
        out.append(f"alternate-CD slots    = {[hex(t) for t in alts]}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--dir", help="scan a directory tree")
    args = ap.parse_args()

    targets = list(args.paths)
    if args.dir:
        for root, _d, files in os.walk(args.dir):
            for n in files:
                if n.endswith((".app", "")) or "." not in n:
                    targets.append(os.path.join(root, n))
    if not targets:
        ap.error("give a path, or --dir")
    for t in targets:
        print(f"=== {t}")
        for line in read(t):
            print(f"    {line}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
