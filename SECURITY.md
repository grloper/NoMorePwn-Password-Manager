# Security policy

NoMorePwn is a **pre-release**, single-maintainer project. It has not had an independent security audit. Please read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it does and does not try to protect.

## Supported versions

Only the latest `main` / most recent release is considered for fixes. There is no long-term-support branch. Note that the release marked "Latest" on GitHub may lag behind the newest pre-releases.

## Reporting a vulnerability

Please report privately; do **not** open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability** (https://github.com/grloper/NoMorePwn-Password-Manager/security/advisories/new).

Helpful details: affected version or commit, platform, steps to reproduce, impact, and whether you only used disposable test vaults (please never send real vault data).

This is a volunteer project, so no response-time SLA is promised. The intent is to acknowledge a report within about a week and to aim for coordinated disclosure within 90 days, sooner if a fix ships earlier. There is no bug bounty.

## Scope

In scope: the vault and crypto code (`nomorepwn/`), the desktop app including local IPC and the updater (`nomorepwn_app/`), the browser extension and native messaging host (`extension/`), and the build/release workflows.

Out of scope: attacks that require an already-compromised, unlocked, same-user session (malware running as you, keyloggers, memory dumps), physical access to an unlocked machine, social engineering, and weaknesses in third-party dependencies that are not exploitable through this project (report those upstream).

## Known limitations

Windows installers are currently unsigned, and the update checksum is published in the same release as the installer. See the threat model for details.
