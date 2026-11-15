# Security policy

## What this project is

A **research harness**. It measures how iOS 27.0.1 handles a code signature
and a provisioning profile that the *user themselves* produced, using a
signing key the user already owns.

## What it does not do

* no exploit, no privilege escalation code, no kernel interaction;
* no shell execution, no network calls, no persistence, no background work;
* nothing is uploaded anywhere — the report stays on the device until the user
  shares it;
* the app is unsigned in the repository. Signing is done locally by the user
  with their own identity.

## Reporting a problem

Open an issue. If you find something that makes the probe destructive, please
say so privately first.

## Responsible disclosure

If the probe confirms a security defect in iOS, the intended path is Apple's
Product Security Reporting portal. Please do not publish a working exploit
before the disclosure window closes.
