# iOS 27.0.1 private-entitlement probe

A one-tap iOS app that measures, **from inside the device**, whether iOS 27.0.1
honours a `com.apple.private.*` entitlement in a binary that was **signed
locally** with an ordinary Apple Developer key.

It exists because of what static analysis of the AMFI kext on iOS 27.0.1
(build 24A446) showed:

* the kernel **never verifies a provisioning profile's own CMS chain** — the
  profile is DER/plist parsed and only a few dictionary keys are inspected;
* the profile arrives from `amfid` over MIG, and the kernel authenticates only
  the daemon's identity;
* every AMFI-side gate therefore reduces to bytes the attacker controls.

The one link that could not be read statically is `amfid` itself (a filesystem
binary behind a per-device AEA key). **This app measures the outcome instead.**

---

## What it measures

| Section | Signal | Why it matters |
|---|---|---|
| `PROVENANCE` | the leaf certificate, team id, CodeDirectory version, and **every candidate offset of the CT-policy field** | tells us which variant is running and what the signer wrote |
| `PROFILE` | the shipped `embedded.mobileprovision`: keys, `AppleInternalProfile`, declared entitlements | confirms the crafted profile survived parsing |
| `ENTITLEMENTS` | which `com.apple.private.*` keys are **visible** | a hint only — visibility is not honouring |
| `SANDBOX` | can the app write outside its container? | **authoritative**: `no-sandbox` honoured or not |
| `ANCHOR` | `anchor apple` / `anchor apple generic` evaluated against our own signature | measures the **runtime** trust-anchor set |
| `INSTALL` | the privileged install channel actually invoked, and its result | **authoritative**: the chain's step 3 |
| `KERNEL-LOG` | AMFI's own messages about this process | names the gate that fired |

---

## How to run it

### 1. Get the unsigned build

```bash
gh run download --repo <owner>/<repo> -n Probe-unsigned-ios-ipa
```

or build it yourself on macOS:

```bash
./scripts/build_ios.sh        # -> out/Probe-unsigned.ipa
```

### 2. Produce a signed variant

Three variants, each isolating one variable:

| Variant | Code signature | `embedded.mobileprovision` | Purpose |
|---|---|---|---|
| **A** | Apple developer certificate | Apple's real profile | **control** — must show nothing interesting |
| **B** | Apple developer certificate | **crafted** | is the profile the deciding input? |
| **C** | **re-signed locally** with private entitlements declared | **crafted** | the real probe |

```bash
# variant A — control
./scripts/resign.sh --variant A \
    --identity "Apple Development: YOUR NAME (TEAMID)" \
    --real-profile ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/<uuid>.mobileprovision

# variant C — the probe
./scripts/resign.sh --variant C \
    --identity "Apple Development: YOUR NAME (TEAMID)" \
    --team TEAMID
```

`resign.sh` writes `out/Probe.app`. Sign it with your own certificate; the
Apple "free" developer account is enough.

> **Why local re-signing matters:** Apple's signing service is what filters
> `com.apple.private.*` entitlements. Re-signing locally bypasses that filter
> while still producing a structurally valid CMS signature.

### 3. Install and run

Install `out/Probe.app` through the ordinary developer path (Developer Mode).
Then press **Run Probe**.

### 4. Send back the report

Press **Save** — the report lands in the app's Documents folder as
`probe-report.txt` — and share it. Include the **variant** you used.

```bash
./scripts/parse_report.py probe-report.txt              # summarise
./scripts/parse_report.py variantB.txt variantC.txt     # diff two runs
```

---

## Reading the result

| Observation | Meaning |
|---|---|
| `write-outside-container=ALLOWED` | the `no-sandbox` entitlement was **honoured** |
| `ENTITLEMENT …allowedSPI stored=true` | the entitlement is visible — **not** proof it is honoured |
| `INSTALL attempt-… -> object(...)` with no error | the privileged channel opened |
| `KERNEL-LOG` contains `disallowed entitlement key` | the restricted-entitlement table refused it |
| `KERNEL-LOG` contains `empty profile` | the crafted profile did not parse — a payload problem, not a system behaviour |
| `KERNEL-LOG` contains `AppleInternalProfile` | the profile path was consulted |

**A negative is a result.** If the entitlement is refused, the whole userspace
route is closed and that is worth knowing.

---

## Scope and safety

This app does **not** exploit anything. It re-signs a bundle with a key you
already own, ships a provisioning profile you wrote yourself, and then asks
the operating system to behave consistently. It contains no exploit, no shell,
no network code and no persistence.

See [SECURITY.md](SECURITY.md).

---

## Files

```
Probe/ProbeApp.swift          the whole app (one file)
scripts/build_ios.sh          compile + package the unsigned IPA
scripts/make_profile.py       craft the provisioning profile
scripts/resign.sh             build variants A / B / C
scripts/parse_report.py       summarise and diff the device reports
.github/workflows/build-ios.yml   CI: build the unsigned IPA
```
