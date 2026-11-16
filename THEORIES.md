# The theories this probe decides

**This file is the contract.** Every id below appears in the probe's verdict
section and is keyed on by `scripts/verdict.py`. If you add a theory to the
app, add it here; if you change one, change it here too.

The wording of each theory is deliberately *falsifiable*: it says what would
have to be observed for the theory to be wrong.

---

## How the states are read

| state | meaning |
|---|---|
| **CONFIRMED** | the observation the theory predicts was made |
| **REFUTED** | the opposite observation was made |
| **CONSISTENT** | the observation agrees with the theory but does not prove it alone (it is the expected outcome under this scenario) |
| **INCONCLUSIVE** | the scenario cannot separate the theory from another explanation |
| **NEEDS-LOG** | the decision comes from the kernel's own words; run `log show` on the Mac and re-run `verdict.py --log` |
| **N/A** | the scenario does not apply to this theory |

A theory is only ever **CONFIRMED** or **REFUTED** on the strength of a
measurement made in that run. Nothing is asserted from a prior run.

---

## T01 — the runtime anchor set contains the PUBLIC Apple Root CA

*Claim:* the trust anchors the running system actually uses include the
public "Apple Root CA", so "the chain must end at a private Apple root" is not
a wall.

*Decided by:* `SecGetAppleTrustAnchors()` / `SecCertificateCopyAppleCorporateRoots()`.

*Refuted if:* neither list contains a certificate whose SHA-256 starts with
`b0b1730ecbc7ff4505142c49`.

*Why it matters:* it decides whether the whole exercise is userspace-only.

---

## T02 — the leaf certificate's Apple class grants CT-policy bit 7

*Claim:* a certificate carrying `1.2.840.113635.100.6.1.2` contributes bit 7
to the CoreTrust policy accumulator, and bit 7 is inside AMFI's acceptance
mask `0x000018000001ff80`.

*Decided by:* reading the signing certificate out of the running binary's own
CMS blob and applying the OID → bit table transcribed from the CoreTrust
disassembly.

*Refuted if:* the leaf's OIDs grant no bit inside the mask.

*Why it matters:* it decides whether an ordinary free developer certificate
is enough to pass the CT-policy gate.

---

## T03 — the CT-policy field is not signer-controlled

*Claim:* whatever we put in the signature, the 8 bytes the kernel reads at
`blob+0xb8` are computed in-kernel from the verified chain; they are not part
of the signed content.

*Decided by:* comparing the on-disk value of every plausible CT-policy field
against the policy the chain predicts.

*Confirmed if:* the on-disk value is zero while the chain earns bits.

*Why it matters:* it closes "forge a signature with a good policy".

---

## T04 — the CT policy is the AND across the chain's certificates

*Claim:* CoreTrust accumulates the bits per certificate and ANDs them, so a
single Apple-issued class is not enough — every certificate in the chain has
to contribute.

*Decided by:* the app computes the per-certificate bits and their AND; the
kernel's own value comes from the log line
`unsuitable CT policy 0x…` (Mac side), and `verdict.py --log` correlates the
two.

*Why it matters:* it explains why the App Store fast path needs a whole
Apple-issued chain and not just one certificate.

---

## T05 — the App Store fast path is unreachable for a local signer

*Claim:* the fast path needs any one of bits {8, 12, 43}, and those come only
from Apple-issued App-Store-family intermediates.

*Decided by:* the predicted AND policy vs `0x0000080000001100`.

*Refuted if:* the predicted policy intersects the fast-path mask.

*Why it matters:* it decides whether the target is the App Store fast path at
all, or the locally-signed / OOP-JIT paths.

---

## T06 — the "Locally Signed Fast Path" (P9) is dead on iPhone

*Claim:* AMFI sets its "locally signed" flag from a byte that its own init
**explicitly zeroes on any device whose DeviceTree `model` starts with
"iPhone"** (the Swift Playgrounds JIT services flag). Therefore P9 is never
entered on iPhone, every signed binary goes down the default amfid-exchange
path (P11), and the provisioning-profile check always runs.

*Decided by:* the kernel's log. `verdict.py --log` looks for the line
`AMFI: '%s': locally signed`.

*Confirmed if:* that line never appears.
*Refuted if:* it appears.

*Why it matters:* it is the difference between "the profile check can be
skipped" and "the profile check always applies".

---

## T07 — the kernel does not verify the provisioning profile's own CMS chain

*Claim:* the profile is parsed, never chain-verified. A profile that libmis
itself rejects can still be honoured.

*Decided by:* a scenario whose profile has no valid Apple signature (a plain
plist, or a CMS signed by a non-Apple identity), plus the observation of
whether any private entitlement is actually honoured.

*Confirmed if:* a private entitlement is honoured while
`MISProfileValidateSignature` on the same profile fails.

*Refuted if:* the entitlement is refused.

*Why it matters:* it decides whether the profile is attacker-writable bytes.

---

## T08 — a private entitlement needs a provisioned or Apple-internal profile

*Claim:* AMFI's `sub_fffffe00092663d4` requires the claimed entitlement to be
**provisioned** by the profile, or the profile to carry
**`AppleInternalProfile`**.

*Decided by:* comparing the two scenarios —

| variant | profile | expectation |
|---|---|---|
| `B-internal` | private keys + `AppleInternalProfile = true` | honoured |
| `C-provisioned` | private keys provisioned, **no** `AppleInternalProfile` | honoured if "provisioned" alone suffices |

*Why it matters:* it says exactly which of the two branches of the gate a
crafted profile has to hit.

---

## T09 — the launch-time validator is not an independent wall

*Claim:* `libmis` trusts `mis.db` and does not re-verify the profile's
signature, so the launch gate only bites when the profile is missing from
`mis.db`.

*Decided by:* calling `MISValidateSignature` on the running executable
inside the app and reporting the `MISError`.

*Confirmed if:* it returns 0 for an app whose profile is crafted.
*Refuted if:* it returns a non-zero code.

*Why it matters:* it decides whether the launch step is a second exploit or a
consequence of the install step.

---

## T10 — libmis does not re-verify the profile's CMS at launch

*Claim:* the same as T07, but measured from inside `libmis` rather than
inferred.

*Decided by:* `MISProfileValidateSignature` on our own embedded profile.

*Why it matters:* it is the direct, one-line measurement of A16's claim.

---

## T11 — fat slices can carry different entitlements

*Claim:* the installer validates slice A while the kernel enforces slice B,
so the two can disagree about entitlements, hashes, requirements and cdhash.

*Decided by:* comparing the claimed entitlements of each slice of the running
binary.

*Confirmed if:* the slices differ.

*Why it matters:* it is the second, independent primitive — it does not depend
on the profile question at all.

---

## T12 — the privileged install channel opens with `allowedSPI`

*Claim:* the install daemon gates on
`com.apple.private.mobileinstall.allowedSPI` on the caller's `SecTask`.

*Decided by:* whether the running process holds that entitlement.

*Why it matters:* it is the last link of the chain — with the entitlement
honoured, the install channel opens.

---

## T13 — `LocalProvision` demotes but never grants

*Claim:* `LocalProvision` is stored as `is_local = 1` in `mis.db` and only
*demotes* (it denies the PPQ exemption and sorts the profile behind
non-local ones). It is never read by the validator.

*Decided by:* the `E-expired-local` scenario — the profile sets
`LocalProvision = true`; if the private entitlement is still refused, the
claim holds.

*Why it matters:* it closes "set LocalProvision and the entitlement is
honoured".

---

## T14 — a honoured `no-sandbox` entitlement really lifts the sandbox

*Claim:* the entitlement is not merely stored: it changes the sandbox.

*Decided by:* actually writing a file outside the container.

*Confirmed if:* the write succeeds.
*Refuted if:* it is denied while the entitlement is honoured.

*Why it matters:* it is the cleanest possible demonstration that a stored
entitlement became an honoured one.

---

## Scenarios and what each one isolates

| variant | signature | profile | isolates |
|---|---|---|---|
| `A-control` | Apple developer cert | Apple's real one | the baseline; everything else must be compared against it |
| `B-internal` | Apple developer cert | crafted, `AppleInternalProfile = true` | T07, T08, T12, T14 |
| `C-provisioned` | Apple developer cert | crafted, private keys provisioned, no `AppleInternalProfile` | T08 — the other branch of the gate |
| `D-selfsigned` | self-signed chain | crafted CMS signed by the same identity | is an Apple-issued chain required at all? |
| `E-expired-local` | Apple developer cert | crafted, expired, `LocalProvision = true` | T10, T13 |
| `F-noprofile` | Apple developer cert | none | the profile check with nothing to check |

---

## What the probe does NOT decide

* Whether `amfid` or `misagent` accept a crafted profile. Both are
  filesystem binaries behind a per-device AEA key — not in the dyld shared
  cache, not in the restore ramdisk. The probe observes their **effect**;
  it cannot read their **code**.
* Whether the CT-policy field is a bitmask or a certificate count (the two
  embedded codebases disagree). The probe reports the predicted value; the
  kernel's value comes from the log.
* Anything about the App Store fast path, which needs an Apple-issued chain
  that cannot be produced locally.
