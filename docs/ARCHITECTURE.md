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

## 6. Leak checking: multi-source k-anonymity + account exposure

**Why multiple sources.** A password corpus only contains passwords
that were dumped in plaintext or cracked form. Your account can be in
a breach while your exact password string never enters any one corpus —
a single-source check produces false "clean" verdicts. NoMorePwn
therefore checks every available corpus and flags a password if **any**
source knows it, and separately offers account-level exposure checks.

### Password corpora (k-anonymity — hash prefixes only)

| Source | Hash (computed locally) | Sent over the wire | Match happens |
|---|---|---|---|
| HIBP Pwned Passwords | SHA-1 (40 hex chars) | first **5** chars + `Add-Padding` | locally |
| XposedOrNot | Keccak-512 (128 hex chars) | first **10** chars | remotely by bucket, result verified locally |

```
password ──SHA-1 (local)──▶ 21BD1...   ──▶ 5 chars  ──▶ api.pwnedpasswords.com/range/
         ──Keccak-512 (local)─▶ a6818b8188... ──▶ 10 chars ──▶ passwords.xposedornot.com/api/v1/pass/anon/
                                    │
                                    ▼
     verdict = breached if ANY corpus reports the password
     (a source that can't be reached is reported as "unchecked",
      never silently treated as "clean")
```
Neither service ever sees the password or its full hash — each prefix
bucket contains many unrelated candidates (the *k* in k-anonymity).

### Account (email) exposure — opt-in, different privacy contract

`check_email_exposure()` asks: *has this email appeared in any breach
at all?* This catches breaches where the password dump was hashed and
never cracked (invisible to every password corpus). **Tradeoff:** the
FULL email address is sent to XposedOrNot (free) and, if you set
`HIBP_API_KEY`, to HIBP's breachedaccount API (paid). Because that is
not anonymized, the UI gates it behind a clearly-labeled button with a
privacy warning — it never runs automatically. Free-tier rate limits
apply (XposedOrNot: ~2 req/s, 25 email checks/hour).

All checks run only when you click — never in the background.

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
| Password exposure during leak check | k-anonymity: 5–10 hash chars out, comparison local, padded responses |
| Single-corpus false negatives ("clean" but actually breached) | Multi-source aggregation (HIBP + XposedOrNot) + opt-in account-level email exposure check |
| Shoulder surfing | Passwords masked by default; per-item, on-demand Reveal |

**Out of scope (v0.1):** malware/keyloggers on the host (no software
defeats a compromised OS), memory forensics while unlocked, and
multi-user concurrency. Clipboard handling is deliberately absent —
copy from the Reveal box consciously.
