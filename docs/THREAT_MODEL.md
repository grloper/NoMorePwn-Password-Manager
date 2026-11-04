# Threat model

Status: informal, written from a code review (2026-10) and the source. It is **not** an independent audit. Statements below describe the intended design and what the code currently does; they are not guarantees.

## What is being protected

| Asset | Where it lives |
|---|---|
| Passwords and notes | Local SQLite vault (`vault.db` under the per-user data dir), encrypted per field |
| Master password / derived key | User's head; derived key in process memory while unlocked |
| Recovery Kit (optional) | A user-held file that escrows the master key, wrapped under a 256-bit recovery code (optionally plus an authenticator second factor) |
| Update path | Installer downloaded from GitHub Releases |

## Cryptography (as implemented)

- Key derivation: Argon2id (t=3, m=64 MiB, p=4, random 16-byte salt), PBKDF2-SHA256 (600k iterations) as fallback. KDF name and parameters are stored in the vault and bounds-checked when read.
- Encryption: AES-256-GCM, fresh random 96-bit nonce per encryption, additional authenticated data binds a ciphertext to its row and field.
- Password generator uses Python's `secrets`.
- Minimum master password length is 10 characters. There is no unlock rate-limit; offline guessing is the realistic attack and depends on master password strength.
- KDF parameters in the vault metadata are not themselves authenticated (a writer could cause unlock failure; not a key disclosure).
- Master password is not Unicode-normalized, so the same visible password typed on different systems could in principle fail to unlock.

## Adversaries

| Adversary | Defended? | Notes |
|---|---|---|
| Thief with a copy of the vault file or a backup (stolen disk, cloud sync leak) | Largely | Secrets are encrypted; strength depends on the master password and Argon2id cost. **Service names, usernames and group names are plaintext** in SQLite. Files are created 0600 on POSIX; on Windows protection relies on the per-user `%APPDATA%` ACL. |
| Other local user on the same machine | Partly | Data dir 0700, vault and backups 0600, IPC socket restricted to the owning user (POSIX). Windows relies on directory ACLs. |
| Malware running as the same user | **No** | It can read process memory, keylog the master password, read the clipboard, read the IPC token file, or drive the UI. Out of scope. |
| Memory forensics / swap / hibernation | **No** | The key is held in immutable Python `bytes` and passwords are Python `str`; locking drops references but cannot zeroize memory. |
| Local process injecting show-IPC messages | Mitigated | The single-instance IPC socket is user-only and every message must carry a per-install random token stored in a 0600 file (`ipc.token`). Same-user malware can read that token, so this stops other users and stray processes, not same-user malware. The channel only accepts `show` (bring the window forward); it does not accept credential writes. |
| Network attacker | Mostly | Update, password breach-check, and breach-catalog traffic use HTTPS with certificate verification. Password checks send only a 5-character SHA-1 prefix (k-anonymity). The public breach-catalog download sends nothing about the vault; service-domain matching is local. |
| Compromised GitHub account, Actions token or release | **No** | Installers are unsigned. The SHA256SUMS file comes from the same release as the installer, so it detects corruption, not a malicious publisher. The updater refuses releases with a missing or malformed checksum, refuses downgrades, only follows the GitHub "Latest" (non-prerelease) release, requires user confirmation, and locks the vault first. A compromised release could still run code on users' machines. Code signing and a signed checksum with a pinned offline key are not implemented. |
| Compromised dependency / build | Partly | `pip-audit` on `requirements.txt` found no known issues at review time. Runtime and build dependencies are version ranges, not hash-locked; builds are not reproducible. |

## Component notes

**Local IPC.** Used by a second app launch to ask the running instance to show itself. Mitigated as above; messages are read in a single read, so very large messages may be truncated (reliability, not security).

**Clipboard.** Copied passwords are cleared after a timeout only if the clipboard still holds the copied value. Copies carry the Windows hints that exclude content from clipboard history, cloud clipboard and clipboard monitors (best-effort; apps that ignore the hints can still read the clipboard while it holds the value, and non-Windows platforms ignore them).

**Auto-lock and sessions.** The desktop app auto-locks after inactivity. Re-keying revokes the old session.

**Recovery Kit.** Opt-in. Theft of both the kit and its recovery code (and authenticator, if enabled) yields the vault.

## Explicit non-goals and known gaps

- Protection against a compromised, unlocked or malware-infected device.
- Secure memory erasure.
- Metadata confidentiality (service names, usernames, groups are plaintext).
- Signed binaries and a signed update channel (planned, not done).
- Independent audit, reproducible builds, SBOM/provenance.
- Cross-platform packaged builds: only Windows builds are published.
- Browser login capture / autofill (not implemented; credentials enter only via the desktop UI).
