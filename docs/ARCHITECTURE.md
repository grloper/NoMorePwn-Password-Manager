# NoMorePwn — Architecture & Security Model

A local-first credential vault and security auditor. One SQLite file,
one Streamlit dashboard, zero required network access.

## 1. Design principles

1. **Local-first, zero-knowledge.** Every secret is encrypted on your
   machine with a key derived from your master password. Nothing that
   leaves the machine (the optional backup blob, the k-anonymity hash
   prefix) is usable without that password.
2. **The database is untrusted storage.** SQLite is treated as a dumb
   ciphertext container. Even with full read access to `vault.db`, an
   attacker learns service names and usernames at most — never
   passwords or notes. Write access is *detected* (tamper evidence).
3. **One narrow network path.** The only outbound call in the codebase
   is `nomorepwn/leakcheck.py`, and it transmits exactly 5 hex
   characters. Everything else is import-time provably offline.

## 2. Component map

```
┌─────────────────────────────────────────────────────────────┐
│  app.py (Streamlit UI)          scripts/ (CLI: init/import/ │
│  master key in session memory    backup — getpass, no echo) │
└───────────────┬─────────────────────────────┬───────────────┘
                ▼                             ▼
        ┌──────────────────────────────────────────┐
        │  nomorepwn/vault.py — orchestration      │
        │  unlock · CRUD · history · tamper sweep  │
        └──┬──────────────┬──────────────┬─────────┘
           ▼              ▼              ▼
   ┌──────────────┐ ┌────────────┐ ┌──────────────────┐
   │ validation.py│ │ crypto.py  │ │ db.py (SQLite)   │
   │ allowlists + │ │ Argon2id / │ │ parameterized    │
   │ length caps  │ │ AES-256-GCM│ │ queries ONLY     │
   └──────────────┘ └────────────┘ └──────────────────┘

   side modules: strength.py (zxcvbn, offline)
                 leakcheck.py (HIBP k-anonymity, 5 hash chars out)
```

## 3. Key derivation & the encryption lifecycle

### Vault creation
1. A random 16-byte salt is generated (`os.urandom`).
2. The master password + salt are stretched into a **256-bit master
   key** with **Argon2id** (64 MiB memory, time cost 3, parallelism 4 —
   OWASP guidance). If `argon2-cffi` is unavailable, the fallback is
   **PBKDF2-HMAC-SHA256 with 600,000 iterations**; the code refuses to
   derive with anything weaker.
3. KDF name, parameters, and salt are stored in `vault_meta` — the
   vault is self-describing, so parameters can be strengthened later
   without breaking old vaults.
4. A **verifier** — the constant `nomorepwn-master-key-verifier-v1`
   sealed under the master key — is stored. Unlocking attempts to
   decrypt it: success proves the password without ever storing the
   password or key.

### Unlock → use → lock
```
master password ──Argon2id(salt)──▶ 256-bit key (RAM only)
                                        │
        write path: plaintext ──AES-256-GCM(key, nonce, AAD)──▶ blob → SQLite
        read  path: blob ──GCM verify+decrypt──▶ plaintext (on Reveal only)
                                        │
        Lock / browser refresh ──▶ key dropped from session memory
```
* Every encryption uses a **fresh random 96-bit nonce**, stored as the
  blob prefix (`nonce ‖ ciphertext ‖ tag`). Nonces are never reused.
* Every blob is bound to its row with **AAD** (`cred:<uuid>:password`),
  so ciphertexts cannot be swapped between rows without failing GCM
  authentication.
* The key never touches disk. Decryption happens per-field, on demand.

## 4. Tamper-evident history tracking

Every password version — including the first — writes a row to
`password_history` containing the ciphertext, a **SHA-256 checksum of
the ciphertext blob**, and a `changed_at` timestamp.

On every unlock, `Vault.verify_integrity()` runs three layers of
checks, cheapest first:

| Layer | Check | Catches |
|---|---|---|
| 1 | SHA-256 of every history + current blob vs stored checksum | Corruption, casual edits |
| 2 | Current checksum == newest history row's checksum | Out-of-band swaps / rollbacks of the current password |
| 3 | Every current blob decrypts under the master key with its row-bound AAD | **Any** forgery — an attacker without the key cannot produce a valid GCM tag |

Honest threat framing: an attacker with write access to the file could
recompute SHA-256 checksums (they're not keyed), which is why layer 3
exists — AES-GCM tags are unforgeable without the master key. The
checksums provide a fast, key-independent sweep and per-row forensic
detail; GCM provides the cryptographic guarantee. What tamper evidence
cannot prevent is deletion — if rows vanish, layer 2 reports missing
history rather than proving what was there.

The `changed_at` chain also powers the dashboard's **"unchanged for N
days"** metric and the stale-password audit (warn at 180 days).

## 5. SQL injection defense (three rings)

1. **Parameterized queries only.** `nomorepwn/db.py` is the sole module
   that touches SQLite. Every statement is a static string literal;
   every value binds through `?` placeholders passed as tuples
   (`conn.execute("... WHERE id = ?", (cred_id,))`). No f-strings, no
   `%`, no `.format()`, no concatenation — and
   `tests/test_core.py::SqlInjectionPolicyTests` fails the build if any
   creep in.
2. **Strict input validation** (`validation.py`): allowlist regexes and
   hard length caps for service names (64) and usernames (128), applied
   server-side before any DB call; Streamlit `max_chars` mirrors them
   client-side. Passwords deliberately allow any printable character
   (restricting them would weaken security) — they're inert data thanks
   to ring 1, and length-capped at 1024.
3. **Encrypted-at-rest payloads.** Passwords/notes reach SQLite as
   AES-GCM binary blobs, so hostile strings like
   `x'; DROP TABLE credentials; --` are doubly inert: bound as
   parameters *and* opaque ciphertext.

## 6. Leak checking with k-anonymity

```
password ──SHA-1 (local)──▶ 21BD1...  (40 hex chars)
                             └──┬──┘
             first 5 chars ─────┘  ONLY these leave the machine
                     │
                     ▼
   GET https://api.pwnedpasswords.com/range/21BD1   (+ Add-Padding header)
                     │
                     ▼
   ~800-1000 breached suffixes with counts, compared LOCALLY
```
HIBP never sees the password, its full hash, or whether anything
matched — each prefix bucket contains hundreds of unrelated hashes
(that's the *k* in k-anonymity). The `Add-Padding` header makes HIBP
pad responses so response length can't fingerprint the bucket either.
Checks run only when you click the button — never automatically.

## 7. Zero-knowledge backup / sync strategy

`scripts/backup_tool.py export` wraps the **entire vault file** in one
more AES-256-GCM layer, keyed from the master password with a *fresh*
salt (backup key ≠ vault key). The resulting `.nmpbak` blob reveals
nothing — not even the schema or row count.

Recommended free-tier sync options (the provider only ever stores
ciphertext):

| Option | Flow |
|---|---|
| Google Drive / Dropbox | Drop the `.nmpbak` into a synced folder (manually or via cron) |
| Supabase Storage / S3 | `curl -X POST` the blob to a private bucket |
| Git private repo | Commit the blob — it's small and opaque (don't commit `vault.db` itself) |
| Syncthing | Peer-to-peer sync of the blob between your own devices, no cloud at all |

Restore anywhere with `backup_tool.py restore` + the master password.
Automating this later is a cron job around `export` — no code changes.

## 8. Threat model summary

| Threat | Defense |
|---|---|
| Stolen laptop / copied `vault.db` | Argon2id + AES-256-GCM; offline brute-force is the only attack, throttled by the KDF |
| Cloud provider snooping backups | Blob is GCM ciphertext keyed by a password the provider never sees |
| DB edited outside the app | Launch-time sweep: SHA-256 checksums + history cross-check + GCM tags |
| Ciphertext swapped between rows | Per-row AAD binding fails GCM authentication |
| SQL injection | Parameterized-only DB layer + allowlist validation + policy test |
| Password exposure during leak check | k-anonymity: 5 hash chars out, comparison local, padded responses |
| Shoulder surfing | Passwords masked by default; per-item, on-demand Reveal |

**Out of scope (v0.1):** malware/keyloggers on the host (no software
defeats a compromised OS), memory forensics while unlocked, and
multi-user concurrency.

## 9. Desktop app & background service

The primary interface is a native **PySide6 (Qt)** desktop app
(`nomorepwn_app/`) that packages into a single `NoMorePwn.exe`. It reuses
the `nomorepwn` core unchanged — the security model above is identical;
only the presentation layer is new. (A legacy Streamlit dashboard,
`app.py`, still works but is optional.)

Security-relevant lifecycle choices:

- **Master key in memory only.** The unlocked `Vault` holds the derived
  key on one object. Locking calls `Vault.lock()` (zeroes the reference)
  and tears down the entire unlocked "shell" widget tree, so no decrypted
  field lingers in a Qt widget after lock.
- **The window is not the process.** Closing the window never silently
  leaves an unlocked vault around: the ✕ button always locks first, then
  either hides to the tray or quits. The app runs as a tray-resident
  background service (`QSystemTrayIcon`), single-instance guarded via a
  `QLocalServer` named pipe.
- **Auto-lock.** A global input-activity filter resets an idle timer;
  when it fires, the vault locks and the tray notifies. Default 5 minutes,
  configurable (including "never").
- **Clipboard hygiene.** Copied secrets are wiped from the clipboard after
  a configurable delay (default 20 s) — but only if the clipboard still
  holds our value, so we never clobber something you copied since.
- **KDF/network off the UI thread.** Argon2id derivation (unlock/create)
  and HIBP breach checks run on a `QThreadPool` worker, so the interface
  never freezes and secrets stay on their worker stack frame.
- **Self-describing data location.** The vault and non-secret preferences
  live under the per-user app-data dir (`%APPDATA%\NoMorePwn` on Windows),
  overridable via `NOMOREPWN_DATA`.

Clipboard handling is now present and deliberately auto-wiping; the Reveal
box remains opt-in and per-item.
