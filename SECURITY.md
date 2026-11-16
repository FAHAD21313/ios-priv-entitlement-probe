# Security policy

## What this project is

A **research harness**. It measures how iOS 27.0.1 handles a code signature
and a provisioning profile that the *user themselves* produced, using a
signing key the user already owns.

The probe is deliberately **differential**: the same source is signed several
ways and installed several times, so that each hypothesis can be confirmed or
refuted against a control instead of against an opinion.

## What it does not do

* no exploit, no privilege escalation code, no kernel interaction;
* **no privileged install call from inside the app** — the app reports whether
  the install channel's gate is open, and stops there;
* no shell execution, no network calls, no persistence, no background work;
* nothing is uploaded anywhere — the report stays on the device until the user
  shares it;
* the app is unsigned in the repository. Signing is done locally by the user
  with their own identity, and the crafted provisioning profiles are generated
  locally by `scripts/make_profile.py`.

## What it writes

* `Documents/probe-report.txt` inside the app's own container — appended on
  every run, so several installs accumulate in one file;
* the pasteboard — the same report, so it can be pasted into a chat or a
  file;
* one file under `/private/var/mobile/Library/` while the sandbox probe runs,
  which it removes again immediately.

## What it reads

* its own bundle, its own embedded code signature and its own embedded
  provisioning profile;
* the system's trust-anchor list;
* the launch-time validator in `/usr/lib/libmis.dylib`.

## Reporting a problem

Open an issue. If you find something that makes the probe destructive, please
say so privately first.

## Responsible disclosure

If the probe confirms a security defect in iOS, the intended path is Apple's
Product Security Reporting portal. Please do not publish a working exploit
before the disclosure window closes.
