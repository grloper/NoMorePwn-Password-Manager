# I built an offline password manager because I did not want my passwords on someone else's server

*A real capture of the app's own UI. I drove the real controller offscreen with a throwaway vault in a temp directory and obviously fake entries (`example.com`, `demo-user`). No real vault or password was used. The "security score" on the dashboard looks like that because every fake account has no MFA flag.*

## What it is

A PySide6 desktop app with a single SQLite vault file. It has groups, credential history, a password generator, a security dashboard, backup and restore, and an opt-in HIBP breach check that sends only a 5-character SHA-1 prefix. There is no browser extension and no autofill — credentials enter only through the desktop UI.

Password and note fields use AES-256-GCM. Service names, usernames and group labels stay plaintext in SQLite on purpose (filterable metadata). Key derivation is Argon2id with a PBKDF2 fallback. This has not had an independent security audit.

## What it defends against (and what it does not)

See [docs/THREAT_MODEL.md](../THREAT_MODEL.md). Short version: a stolen vault file is largely defended if the master password is strong. Same-user malware, memory dumps and a compromised GitHub release are out of scope.

## Evidence, not vibes

The Python unittest suite exercises the vault, crypto, backup, recovery and headless Qt views against disposable databases. Packaged installer behavior and live breach/update providers remain separately unverified.

## Closing

If you try it, use a disposable vault. Pre-release installers are unsigned. Report vulnerabilities privately via GitHub Security advisories.
