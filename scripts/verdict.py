#!/usr/bin/env python3
"""
verdict.py — collapse the probe's device reports into ONE table of verdicts.

The probe is run several times (once per signed variant).  Each run appends a
block to a single report file.  This script splits the file into runs, reads
the verdict each run produced, and prints the cross-run table — so the
researcher reads one table instead of a pile of dumps.

    ./scripts/verdict.py reports/probe-report.txt
    ./scripts/verdict.py reports/*.txt --log amfi.log

Optional
    --log FILE   a Mac-side `log show` capture; used to resolve the
                 NEEDS-LOG verdicts (T04, T06) against the kernel's own words.

Output
    1. one row per theory, one column per run
    2. the raw verdict evidence for every non-trivial cell
    3. the differentiators: which pairs of runs actually separate which theory
"""

import argparse
import re
import sys
from collections import OrderedDict

THEORY_TITLES = {
    "T01": "runtime anchor set contains the PUBLIC Apple Root CA",
    "T02": "leaf Apple class grants CT-policy bit 7 (inside AMFI's accept mask)",
    "T03": "the CT-policy field is not signer-controlled",
    "T04": "the CT policy is the AND across the chain's certificates",
    "T05": "the App Store fast path is unreachable for a local signer",
    "T06": "the Locally Signed Fast Path (P9) is dead on iPhone",
    "T07": "the kernel does not verify the profile's own CMS chain",
    "T08": "a private entitlement needs a provisioned / Apple-internal profile",
    "T09": "the launch-time validator is not an independent wall",
    "T10": "libmis does not re-verify the profile's CMS at launch",
    "T11": "fat slices can carry different entitlements",
    "T12": "the privileged install channel opens with allowedSPI",
    "T13": "LocalProvision demotes but never grants",
    "T14": "a honoured no-sandbox entitlement really lifts the sandbox",
}

RUN_MARKER = "=== iOS private-entitlement probe"


def split_runs(text):
    """Split the accumulated report into runs."""
    runs = []
    cur = None
    for line in text.splitlines():
        if line.startswith(RUN_MARKER):
            cur = []
            runs.append(cur)
        if cur is not None:
            cur.append(line)
    return runs


def kv(lines):
    out = OrderedDict()
    for line in lines:
        if "=" in line and not line.startswith("---"):
            k, _, v = line.partition("=")
            out.setdefault(k.strip(), v.strip())
    return out


def read_verdicts(lines):
    out = OrderedDict()
    for line in lines:
        m = re.match(r"^VERDICT (T\d\d) (.*)$", line)
        if m:
            tid, rest = m.group(1), m.group(2)
            state, _, rest = rest.partition(" | ")
            title, _, evidence = rest.partition(" | ")
            out[tid] = (state.strip(), title.strip(), evidence.strip())
    return out


def read_log(path):
    if not path:
        return None
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def resolve_needs_log(verdicts, log):
    """T04/T06 are settled by the kernel's own words."""
    if log is None:
        return
    policy = re.findall(r"unsuitable CT policy (0x[0-9a-f]+|\d+)", log)
    locally = "locally signed" in log
    for tid in ("T04", "T06"):
        if tid not in verdicts:
            continue
        state, title, evidence = verdicts[tid]
        if tid == "T04":
            if policy:
                verdicts[tid] = ("NEEDS-RUN", title,
                                 "kernel logged CT policy " + ", ".join(sorted(set(policy))) +
                                 " ; compare with the app's predicted-ct-policy")
            else:
                verdicts[tid] = ("NEEDS-RUN", title,
                                 "no 'unsuitable CT policy' line in the capture")
        if tid == "T06":
            verdicts[tid] = (("REFUTED" if locally else "CONFIRMED"), title,
                             ("the log contains \"locally signed\" → P9 IS reachable"
                              if locally else
                              "the log has no \"locally signed\" line → P9 is dead"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="+")
    ap.add_argument("--log", default=None,
                    help="Mac-side 'log show' capture, to resolve the NEEDS-LOG verdicts")
    ap.add_argument("--evidence", action="store_true",
                    help="print the evidence line for every cell")
    args = ap.parse_args()

    log = read_log(args.log)

    runs = []
    for path in args.reports:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"!! cannot read {path}: {e}", file=sys.stderr)
            continue
        for block in split_runs(text):
            facts = kv(block)
            verdicts = read_verdicts(block)
            resolve_needs_log(verdicts, log)
            label = facts.get("variant-label") or facts.get("scenario-id") or "?"
            runs.append((label, facts, verdicts, path))

    if not runs:
        print("no runs found — is this the right file?", file=sys.stderr)
        return 1

    # ---- one table ---------------------------------------------------------
    ids = sorted({t for _, _, v, _ in runs for t in v})
    labels = [lbl for lbl, _, _, _ in runs]

    print()
    print("=" * 100)
    print("THEORY VERDICTS")
    print("=" * 100)
    w = 44
    hdr = "theory".ljust(6) + "statement".ljust(w) + "".join(l[:20].ljust(21) for l in labels)
    print(hdr)
    print("-" * 100)
    for tid in ids:
        row = tid.ljust(6) + (THEORY_TITLES.get(tid, "")[:w - 1]).ljust(w)
        for _, _, v, _ in runs:
            row += (v.get(tid, ("-", "", ""))[0] or "-")[:20].ljust(21)
        print(row)
    print("-" * 100)

    # ---- the run matrix ----------------------------------------------------
    print()
    print("RUN FACTS")
    print("-" * 100)
    keys = ["variant-label", "scenario-id", "scenario-signature", "scenario-profile",
            "scenario-profile-apple-internal", "signature-adhoc",
            "predicted-ct-policy", "predicted-ct-policy-bits",
            "predicted-ct-policy-in-accept-mask", "predicted-ct-policy-has-fastpath-bit",
            "claimed-private", "honoured-private", "private-entropy-honoured-count",
            "write-outside-container", "mis-validate-self", "mis-profile-validate",
            "install-gate-allowedSPI"]
    print("field".ljust(44) + "".join(l[:20].ljust(21) for l in labels))
    for k in keys:
        row = k.ljust(44)
        for _, facts, _, _ in runs:
            row += (facts.get(k, "-") or "-")[:20].ljust(21)
        print(row)
    print("-" * 100)

    # ---- evidence ----------------------------------------------------------
    if args.evidence:
        print()
        print("EVIDENCE")
        for label, facts, verdicts, _ in runs:
            print(f"\n--- {label} ---")
            for tid, (state, title, ev) in verdicts.items():
                print(f"  {tid} {state:<12} {ev}")

    # ---- differentiators ----------------------------------------------------
    print()
    print("DIFFERENTIATORS (runs that disagree on a theory)")
    print("-" * 100)
    found = False
    for tid in ids:
        states = [(lbl, v.get(tid, ("-",))[0]) for lbl, _, v, _ in runs]
        if len({s for _, s in states}) > 1:
            found = True
            print(f"  {tid}  {THEORY_TITLES.get(tid, '')}")
            for lbl, s in states:
                print(f"       {lbl:<24} {s}")
    if not found:
        print("  (none — every run agrees on every theory)")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
