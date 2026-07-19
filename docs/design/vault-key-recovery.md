# Design: master-key recovery (Recovery Kit) — DESIGN ONLY

> **Status: proposal for review. No code in this change implements it.**
> Recovery would be the repo's *first rekey path* and a threat-model-level
> change (see §6–§7), so it is written up before a line is written.

## 1. Problem & hard constraints

Today the master key `K` exists only in RAM on a live `Vault`. It is derived
directly from the master password (`K = Argon2id(password, salt)`, `crypto.py`)
and **every secret field is encrypted directly under `K`**. There is no
key-wrapping layer and **no rekey code anywhere in the repo** (CLAUDE.md
invariants 1 & 16). Forget the password and the vault is gone — `README.md`
says so in as many words ("There is no recovery.").

The threat model assumes an attacker with **read *and* write** access to
`vault.db` and to any `.nmpbak`, plus anyone who obtains a backup from cloud
storage. So the governing rule for any recovery feature is:

> **Recovery material must never touch `vault.db` or `.nmpbak`.** Anything
> stored there is, by assumption, in the attacker's hands. A "recover without
> the master password" feature is only safe if the secret that enables recovery
> lives entirely *out of band* — exported by the user and stored by the user.

The design below is bound by the task's constraints, restated here as
acceptance criteria:

- **C1.** Does not weaken or bypass the Argon2id/PBKDF2 derivation in
  `crypto.py` (no lowered costs, no shortcut key).
- **C2.** Adds no code path that decrypts the vault using anything other than
  the master password **or** an explicitly user-exported recovery secret.
- **C3.** TOTP (RFC 6238, `pyotp`, offline) is used **only as an access gate**
  on revealing/exporting the recovery material — never as a thing that
  reconstructs a key. MFA ≠ key recovery.
- **C4.** Spells out the threat-model doc changes (`docs/ARCHITECTURE.md` §1,
  `README.md`).
- **C5.** Explains the interaction with invariant 17 (pre-migration snapshot)
  and the "no rekey code" fact — does this *become* the first rekey path?

## 2. The one architectural fact that shapes everything

`K` is not a *wrapping* key — it is *the* content key. `password_enc`,
`notes_enc`, every `password_history.password_enc`, the `verifier`, and the
wrapped backup key are all sealed directly under `K` with row-bound AAD
(`cred:{uuid}:password`, etc.). Two consequences:

1. **Recovering `K` gives read access, but you cannot "reset the password"
   for free.** A new password derives a *different* `K'`, and nothing in the
   vault is encrypted under `K'`. So a usable recovery *must* re-encrypt every
   secret from `K` to `K'` — i.e. it must **rekey**. That code does not exist
   yet. This feature creates it (§5, §7).
2. There is **no "change master password" feature today either**, for exactly
   this reason. The missing primitive is `rekey`, not "recovery". Build `rekey`
   once, tested, and *both* recovery and change-password fall out of it.

## 3. Recovery secret & escrow blob

- **Recovery Key `R`** — 256 bits from the CSPRNG (`secrets.token_bytes(32)`;
  invariant 5), rendered as a grouped base32 **recovery code** shown **once**.
  Because `R` is full-entropy, it is used **directly** as an AES-256 key. It is
  deliberately **not** run through Argon2id/PBKDF2: a KDF over a full-entropy
  secret buys nothing, and stretching it would only invite confusion with the
  real password KDF. This satisfies **C1** — the password KDF is untouched, and
  no weaker derivation is introduced.
- **`wrapped_master`** — `crypto.encrypt(R, K, aad="nmp:recovery:v1:{vault_id}")`.
  The vault's own `K`, sealed under `R`, GCM-authenticated, and bound to a new
  per-vault random `vault_id` (a *non-secret* meta value) so a kit can never be
  replayed against a different vault. Tampering fails loudly, like every other
  blob.

`R` + `wrapped_master` ⇒ `K` ⇒ read access. That is the whole escrow.

## 4. Where the pieces live — the crux

**Recommended: a single out-of-band Recovery Kit; nothing in the vault files.**

At setup the app produces a **Recovery Kit** — an exported file (printable
PDF / `.txt` / QR) that the **user** saves themselves (safe, USB, password
manager of last resort). It contains: `vault_id`, `wrapped_master`
(nonce‖ciphertext), a format version, and the recovery code `R`. This mirrors
Bitwarden's *emergency kit*: one document that, with nothing else, restores
access — so **the kit is a master-password-equivalent and must be protected
like one.**

Crucially, **nothing recovery-related is written to `vault.db` or `.nmpbak`.**
An attacker with read+write to the vault file gains no recovery path and cannot
even tell recovery is configured. This is the literal reading of the governing
rule in §1.

**Rejected alternative — store `wrapped_master` in `vault_meta`.** It would be
*computationally* safe (breaking it means brute-forcing a full-entropy 256-bit
`R`, i.e. AES-256 — the same bar as the existing `backup_key_wrapped` meta).
But it violates the governing rule and creates a "stolen `vault.db` + stolen
recovery code = access" combination that the out-of-band split avoids entirely.
Keeping recovery material off-disk is strictly safer and is what the task asks
for. Rejected.

**Recovery flow**

1. *Recover with Recovery Kit* → pick the kit file → enter/confirm `R`.
2. `K = crypto.decrypt(R, wrapped_master, "nmp:recovery:v1:{vault_id}")`.
   GCM failure → "recovery code doesn't match this kit" (wrong-code and tamper
   are indistinguishable, per invariant 8).
3. Verify `K` against the vault's stored `verifier` — proves the kit belongs to
   *this* `vault.db`. If the file was swapped, this fails cleanly.
4. Force the user to set a **new master password** → **rekey** (§5). They have a
   working password again; offer to regenerate a fresh kit (the old kit still
   decrypts the *old* `K`, so it should be destroyed — call this out in the UI).

This satisfies **C2**: the only two ways to reach plaintext remain (a) the
master password, and (b) the user-exported `R`. Nothing else decrypts anything.

## 5. Rekey — the first rekey path in the repo

`Vault.rekey(new_password)`:

- Derive `K' = Argon2id(new_password, new_salt)` via `default_kdf()` (vault
  *creation* semantics; unlock still replays `vault_meta`, invariant 11).
- In **one** `db.connect` transaction (`PRAGMA foreign_keys = ON`, invariant 13):
  - each credential: decrypt `password_enc` under `K` with
    `cred:{uuid}:password`, re-encrypt under `K'` with the **same** AAD (fresh
    nonce via `crypto.encrypt`), recompute `password_sha256` over the **new**
    ciphertext (invariant 4). Same for `notes_enc` / `cred:{uuid}:notes`.
  - each `password_history` row: decrypt→re-encrypt `password_enc` under `K'`,
    recompute `ciphertext_sha256` (keeps `verify_integrity` green, invariant 7).
  - re-wrap `backup_key_wrapped` if present (`vault:backup-key`).
  - write new `kdf_salt`, `kdf_params`, and `verifier = make_verifier(K')`.
- **AAD is preserved verbatim** — every row keeps its uuid-bound AAD; only the
  key changes. This is the *safe* transform (decrypt-then-re-encrypt under the
  same uuid-AAD); it does **not** change the AAD format (invariant 1).
- **Snapshot first (sibling of invariant 17):** before rewriting a single
  ciphertext, write `<vault>.pre-rekey` with `db.snapshot_bytes` (SQLite
  online-backup API — never a torn page) and **never delete it**. A
  half-finished rekey is otherwise unrecoverable, exactly as a half-finished
  migration is. This mirrors `vault.migrate_schema`.

`rekey` is consumed by recovery (after §4 unwraps `K`) and, for free, by a
future *Settings → Change master password* (which just calls it with `K`
already in hand).

## 6. TOTP's role — honestly scoped (C3)

TOTP does **not** protect the vault and **cannot** reconstruct `K`. Its only
correct placement is an **access gate on recovery-surface actions performed
inside the already-unlocked app**:

- generating / exporting the Recovery Kit, and
- re-displaying the recovery code.

The TOTP seed is stored **encrypted under `K`** in `vault_meta`
(`aad="vault:totp-seed"`), so it is usable *only while unlocked* — which is
exactly the gate's scope (you can only export a kit while unlocked). `pyotp` is
**offline**: no network call, so this adds **no third network path** — the
"exactly two outbound requests" enumeration in `README.md` /
`docs/ARCHITECTURE.md` §1 stays true (and CLAUDE.md's "exactly two modules
touch the network" is unchanged).

**Honest assurance rating.** Once the session is unlocked the attacker already
holds `K` and can reveal every password or write a backup, so a TOTP gate on
kit export mostly stops an *opportunistic* passer-by at an unattended unlocked
screen — **not** a determined attacker who already has the unlocked session.
Rate it *low-assurance friction/confirmation*, and say so in the docs (this
repo's culture is to state what a control is and isn't worth).

**Why TOTP cannot gate recovery itself.** During recovery the vault is by
definition inaccessible, so a `K`-encrypted TOTP seed is unreadable. Putting the
seed *in the kit* would make it not a separate factor at all. So TOTP gates
*export*, never *recovery-from-kit*. If stronger at-rest protection of the kit
is wanted, the right primitive is a user-chosen **kit passphrase** (a knowledge
factor — encrypt the kit file under `Argon2id(kit_passphrase)`), not TOTP. This
keeps MFA and key recovery cleanly separate: the **kit** is the recovery
material; **TOTP** only ever gates an in-app action and never participates in
reconstructing `K`.

## 7. Threat-model & invariant changes required when this lands (C4, C5)

**Docs**

- `README.md` §"Security honesty": *"Your master password is the only key.
  There is no recovery."* becomes false → replace with: *"There is exactly one
  recovery path: the Recovery Kit you export at setup and store yourself. Lose
  both your password and the kit and the vault is unrecoverable. The kit is a
  master-password-equivalent — protect it like one."* Add the kit to *"Where
  your data lives"* — it lives **outside** `%APPDATA%`, wherever the user saved
  it, and is **not** auto-backed-up.
- `README.md` network bullet: reaffirm "exactly two outbound requests"; note
  `pyotp` is offline and adds none.
- `docs/ARCHITECTURE.md`: new §"Master-key recovery (Recovery Kit)" covering
  `R`, `wrapped_master`, out-of-band storage, rekey-on-recovery, the
  `<vault>.pre-rekey` snapshot, and TOTP's scope + assurance. §8 threat table
  gains: *recovery kit stolen → equivalent to master-password compromise*;
  *recovery code without the kit (or the kit without the code) → useless*;
  *`vault.db` stolen → still contains no recovery material (the kit is out of
  band)*.

**CLAUDE.md invariants (must change in the same commit as the code)**

- Invariants **1** and **16** both assert *"there is still no rekey code
  anywhere in the repo."* Landing this makes that **false**. Both must be
  reworded, and the `vault.migrate_schema` docstring ("there is no rekey path in
  this repo") updated.
- **New invariant:** *`Vault.rekey` re-encrypts every secret from `K` to `K'`
  preserving each row's uuid-bound AAD verbatim (only the key changes); it
  snapshots `<vault>.pre-rekey` via `db.snapshot_bytes` first and never deletes
  it (sibling of invariant 17); it runs inside one `db.connect` transaction.*

**Dependencies**

- Add `pyotp` (offline TOTP) to `requirements.txt`. New runtime dependency.

**Direct answers to C5**

- *Interaction with invariant 17:* rekey is the **same shape of danger** as a
  migration — a whole-file secret rewrite with no other recovery path — so it
  adopts 17's discipline verbatim (`db.snapshot_bytes` → `<vault>.pre-rekey`,
  never deleted). It does not conflict with 17; it extends its philosophy to a
  second operation and adds the sibling invariant above.
- *Does this become the first rekey path?* **Yes, explicitly.** "Recover `K`,
  then set a new password" requires re-encrypting every field from `K` to `K'` —
  the repo's first rekey code. That is the single biggest consequence, and the
  reason this is design-first: it invalidates a load-bearing fact that three
  places (invariants 1, 16, and the `migrate_schema` docstring) currently lean
  on.

## 8. Alternatives & tradeoffs

| Option | What | Cost | When |
|---|---|---|---|
| **A — recover `K`, then bulk-rekey to `K'` (recommended)** | §4–§5 as written | `O(n)` decrypt+re-encrypt at recovery (rare, small `n`); introduces one snapshot-guarded rekey path | Now |
| **B — VEK indirection** | Encrypt fields under a random Vault Encryption Key; `K` and `R` each *wrap* the VEK. Recovery / password-change become `O(1)` re-wraps, no field rekey ever | A one-time migration of every existing vault to introduce the VEK — itself a bulk rekey (you pay A's cost once, up front) — plus permanent indirection and new invariants (VEK never leaves RAM; wrap-AAD binding) | If frequent password changes, multiple recovery secrets, or a Shamir split become requirements — B's payoff is cheap re-wrapping |
| **Shamir split of `R`** | Split `R` into k-of-n shares for social/multi-location recovery | Orthogonal — only changes how `R` is transported/stored; escrow crypto unchanged | Future; not v1 |

Recommendation: **Option A**. It confines the first rekey to a rare, explicit,
snapshot-guarded, user-initiated event, and it delivers change-master-password
as a bonus. Option B is the industry end-state (Bitwarden/1Password), but its
real value is cheap *repeated* re-wrapping, which NoMorePwn does not need yet —
and its migration is Option A's cost anyway.

## 9. Explicitly NOT done (guards on the constraints)

- **No** recovery material in `vault.db`/`.nmpbak` — not `R`, not
  `wrapped_master`, not any recovery-derived key (§1, §4).
- **No** decrypt path keyed by anything but the master password or the exported
  `R` (C2). TOTP never decrypts anything (C3).
- **No** Argon2id/PBKDF2 over `R` (it is full-entropy), and **no** lowered KDF
  cost anywhere (C1).
- **No** use of `default_kdf()` on unlock (invariant 11) — rekey writes fresh
  KDF metadata; unlock keeps replaying `vault_meta`.

## 10. Open questions for the reviewer

1. **Kit shape.** Single-file kit (`R` + `wrapped_master` together, Bitwarden
   style — recommended) vs. present `R` separately for 2-of-2 storage (more
   friction, but the kit file alone is then useless)?
2. **Kit-at-rest protection.** Offer the optional `Argon2id(kit_passphrase)`
   wrapper on the kit file for users who can't store it somewhere trusted?
3. **Ship *Change master password* in the same release?** It is the same
   `rekey` primitive and would amortise the review of the riskiest new code.
4. **TOTP scope.** Given the honest assurance rating (§6), is TOTP-gating kit
   export worth the added dependency and UX, or should v1 ship recovery without
   TOTP and add it only alongside a genuinely second-factor use?

---

*Stopping here for review, per the design-first instruction. On approval, the
implementation order would be: (1) tested `Vault.rekey` + `<vault>.pre-rekey`
snapshot; (2) Recovery Kit export/import + `vault_id`; (3) optional TOTP gate;
(4) the doc/invariant edits in §7, all in the commit that lands the code.*
