# Priv-Ent Probe — a differential probe for the iOS 27.0.1 code-signing trust layer

**One app. One launch. One report. One table of verdicts.**

The probe installs the *same* binary several times with different
(signature, profile) combinations. Each run measures what the kernel
actually did and emits a verdict for every theory in
[`THEORIES.md`](THEORIES.md). `scripts/verdict.py` collapses all the runs into
a single cross-run table.

Nothing is pre-built: the app is compiled from source, every variant is signed
locally with your own identity, and every profile is generated locally.

---

## Quick start

```bash
# 1. build the unsigned app (macOS + Xcode command line tools)
./scripts/build_ios.sh

# 2. build the signed variant matrix (your identity, your team)
./scripts/scenarios.sh --identity "Apple Development: YOU (TEAM)" --team TEAMID

# 3. install each out/variants/*/<id>.ipa on the device, and OPEN the app once
#    per install — it runs by itself, writes the report, copies it to the
#    pasteboard, and shows one line of status.  No dialogs.

# 4. pull the accumulated report and print the verdict table
./scripts/collect.sh
./scripts/verdict.py reports/probe-report.txt

# 5. (optional) resolve the two NEEDS-LOG verdicts against the kernel's words
log show --last 30m --predicate 'process == "amfid" OR eventMessage CONTAINS[c] "AMFI"' > amfi.log
./scripts/verdict.py reports/probe-report.txt --log amfi.log --evidence
```

or through the Makefile:

```bash
make build
make scenarios IDENTITY="Apple Development: YOU (TEAM)" TEAM=TEAMID
make collect
make verdict
```

---

## What it measures

| section | what it produces |
|---|---|
| `SIGNATURE` | per-slice CodeDirectory facts, `execSegFlags`, the claimed entitlements, the CT-policy field candidates |
| `CHAIN` | the real signing chain recovered from the binary's own CMS blob, every Apple OID decoded, and the **CT-policy bits each certificate earns** |
| `PROFILE` | the embedded provisioning profile: `AppleInternalProfile`, `LocalProvision`, `IsXcodeManaged`, its entitlements, its certificates |
| `LIBMIS` | the launch-time validator's own verdict on this app, and on this profile |
| `ENTITLEMENTS` | what the **kernel honours** (via `SecTask`) |
| `DELTA` | claimed vs honoured — the difference is the finding |
| `EFFECTS` | whether the sandbox is actually off (a real write outside the container) |
| `ANCHOR` | the runtime trust-anchor set |
| `INSTALL` | whether the privileged install channel's gate is open |
| `VERDICTS` | one line per theory: state + evidence |

The CT-policy table in the app is transcribed from the CoreTrust kext
disassembly on iOS 27.0.1; the app recomputes the predicted policy from the
certificates it finds on the device, so the report is a measurement and not an
echo of the source.

---

## The variant matrix

| variant | signature | profile | isolates |
|---|---|---|---|
| `A-control` | Apple developer cert | Apple's real one | the baseline |
| `B-internal` | Apple developer cert | crafted, `AppleInternalProfile = true` | the main test |
| `C-provisioned` | Apple developer cert | crafted, private keys provisioned, **no** `AppleInternalProfile` | the other branch of the gate |
| `D-selfsigned` | self-signed chain | crafted CMS signed by the same identity | is an Apple chain required at all? |
| `E-expired-local` | Apple developer cert | crafted, expired, `LocalProvision = true` | `LocalProvision` and expiry |
| `F-noprofile` | Apple developer cert | none | the profile check with nothing to check |

All variants share the **same bundle identifier**, so the report accumulates in
one container and one `collect.sh` returns every run.

---

## Reading the output

```
theory  statement                                A-control           B-internal
------  ----------------------------------------  ------------------  ------------------
T01     runtime anchor set has the PUBLIC root    CONFIRMED           CONFIRMED
T02     leaf class grants CT-policy bit 7         CONFIRMED           CONFIRMED
T07     kernel does not verify the profile CMS    N/A                 CONFIRMED
T08     private entitlement needs provisioning    N/A                 CONSISTENT
T12     install channel opens with allowedSPI     REFUTED             CONFIRMED
```

* `CONFIRMED` / `REFUTED` — the measurement settled it.
* `CONSISTENT` — the run agrees with the theory but does not prove it alone.
* `INCONCLUSIVE` — this scenario cannot separate the theory from another
  explanation.
* `NEEDS-LOG` — the kernel's own words decide it; re-run `verdict.py --log`.

The `DIFFERENTIATORS` section at the bottom names the runs that disagree, and
therefore the pairs that actually decided each theory.

---

## Safety rails in the probe

* The report is flushed after **every** section, so a trap in a later probe
  cannot destroy earlier evidence.
* Risky calls run **after** the report is on disk.
* The app never asserts a conclusion from a single observation: every verdict
  names the measurement that produced it.
* There are no modal dialogs; the app copies the report to the pasteboard and
  shows a single status line.

---

## Repository layout

```
Probe/ProbeApp.swift        the whole app (one file, no Xcode project)
Probe/Info.plist            the bundle template
scripts/build_ios.sh        compile for iOS and package an IPA
scripts/scenarios.sh        build the signed variant matrix
scripts/make_profile.py     craft any shape of embedded.mobileprovision
scripts/collect.sh          pull the accumulated report off the device
scripts/verdict.py          collapse the reports into one verdict table
scripts/parse_report.py     the older field-by-field dump (kept)
scripts/execsegflags.py     read execSegFlags out of any Mach-O
THEORIES.md                 the contract: what is decided, and how
```

## Requirements

* macOS with the Xcode command line tools (to compile and to sign).
* A codesigning identity (`security find-identity -v -p codesigning`).
* A device in Developer Mode, with the probe installed through the ordinary
  development path.

## Scope and safety

This is a research probe for a code-signing trust-layer study on iOS 27.0.1.
It only ever inspects the state of the device it runs on; the "install
attempt" is deliberately **not** performed from the app — the app reports
whether the channel's gate is open, and the privileged call is left to a
follow-up step so that a crash can never take the evidence with it.
