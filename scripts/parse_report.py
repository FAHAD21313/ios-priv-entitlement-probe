#!/usr/bin/env python3
"""
parse_report.py — turn a `probe-report.txt` produced on the device into a
compact, comparable summary.

    ./scripts/parse_report.py probe-report.txt [probe-report-2.txt ...]

Each input is reduced to the fields that actually matter for the research, so
that two runs (for example variant B and variant C) can be diffed directly.
"""

import re
import sys


def parse(path):
    out = {"file": path, "raw": {}}
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if "=" in line:
            k, _, v = line.partition("=")
            out["raw"][k.strip()] = v.strip()
        elif line.startswith("ENTITLEMENT "):
            rest = line[len("ENTITLEMENT "):]
            k, _, v = rest.partition(" ")
            out["raw"][f"ent:{k}"] = v.strip()
        elif line.startswith("LOG hit:"):
            out.setdefault("log_hits", []).append(line)
    return out


def key_of(k):
    """Normalise a key so runs can be compared across variants."""
    return k.split(" ")[0]


def summarise(r):
    raw = r["raw"]
    lines = []
    lines.append(f"### {r['file']}")
    for k in ("device-os", "device-model", "bundle-id", "process-id",
              "signature-present", "identifier", "team-id",
              "codedirectory-version", "exec-seg-flags", "superblob-slots",
              "profile-present", "profile-kind", "profile-keys",
              "profile-apple-internal-profile", "profile-entitlements",
              "write-outside-container", "read-private-dir"):
        if k in raw:
            lines.append(f"  {k:<34} {raw[k]}")
    pol = sorted(k for k in raw if k.startswith("policy-field"))
    if pol:
        lines.append("  -- CT policy field candidates --")
        for k in pol:
            lines.append(f"  {k:<34} {raw[k]}")
    lines.append("  -- entitlements --")
    for k in sorted(raw):
        if k.startswith("ent:"):
            lines.append(f"  {k:<44} {raw[k]}")
    lines.append("  -- anchor --")
    for k in sorted(raw):
        if k.startswith("req:"):
            lines.append(f"  {k:<44} {raw[k]}")
    lines.append("  -- install --")
    for k in sorted(raw):
        if k.startswith("class:") or k.startswith("selectors:") or k == "attempt":
            lines.append(f"  {k:<44} {raw[k][:200]}")
    hits = r.get("log_hits", [])
    lines.append(f"  -- kernel log -- ({len(hits)} marker hits)")
    for h in hits[:40]:
        lines.append(f"    {h[:220]}")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    reports = [parse(p) for p in sys.argv[1:]]
    for r in reports:
        print(summarise(r))
        print()

    if len(reports) == 2:
        a, b = reports
        ka = {k: v for k, v in a["raw"].items()}
        kb = {k: v for k, v in b["raw"].items()}
        print("=== differences between the two runs ===")
        for k in sorted(set(ka) | set(kb)):
            if ka.get(k) != kb.get(k):
                print(f"  {k}\n     A: {ka.get(k, '-')}\n     B: {kb.get(k, '-')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
