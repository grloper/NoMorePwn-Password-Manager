# NoMorePwn

Offline Windows password manager: a PySide6 desktop app over an AES-256-GCM/SQLite vault
(`nomorepwn/`), plus an MV3 browser extension that captures credentials only after verifying a
login succeeded, bridged by a native-messaging host.

**Threat model:** an attacker with read *and write* access to `vault.db` or a `.nmpbak`, and
anyone who obtains a backup from cloud storage. Out of scope: memory dumps of the live process,
malware running as the user, multi-user concurrency.

The master key exists only in RAM on a live `Vault`. Exactly two modules touch the network:
`nomorepwn/leakcheck.py` (HIBP, 5 hex chars out) and `nomorepwn/updater.py` (GitHub Releases +
installer download). Adding a third is a threat-model change — update `README.md` and
`docs/ARCHITECTURE.md` §1 in the same commit, both of which enumerate them.

---

## ⚠️ Commands here operate on the user's REAL vault

`config.DATA_DIR` resolves to `%APPDATA%\NoMorePwn` — **not** the repo. There is also a real
36 KB `data/vault.db` in this working tree (gitignored). Before running anything that writes:

- `python scripts/backup_tool.py restore <file> --force` overwrites the **developer's live
  vault**. It resolves `--db` from `config.DB_PATH` at parser-construction time. It is the most
  destructive command in the repo and it is documented in `README.md:149-151` with no warning.
- `python NoMorePwn.py` opens the real vault and blocks on a GUI.
- To isolate, set `NOMOREPWN_DATA` **before the process imports `nomorepwn.config`** — it is read
  once at import (`config.py:40`). Setting it afterwards silently does nothing and you operate on
  live data. In-process, patch `config.DB_PATH` directly (see `tests/test_core.py` `NativeHostTests`).

## Shell

The agent shell here is **Windows PowerShell 5.1**, not bash. `&&` is a parser error; use `;` or
`if ($?) { }`. There is no inline `VAR=x cmd` prefix — use `$env:VAR = 'x'; cmd`. The Bash tool is
available separately and does take POSIX syntax.

## Commands

```
python -m unittest discover tests -v      # 69 tests, ~3s — from repo root
cd extension; npm install; npm test       # 52 checks, ~22s — NOT `npm ci` (lockfile gitignored)
python NoMorePwn.py                       # runs against the REAL vault (see above)
pip install -r requirements-build.txt     # covers both test and build deps
pyinstaller build/NoMorePwn.spec --distpath dist --workpath build/_work --noconfirm
```

`README.md:89`'s pyinstaller line omits `--workpath` and dumps work files into the tracked
`build/`. Use the form above; it matches CI. `build/NoMorePwn.spec` must run from the repo root
(`ROOT = os.getcwd()`); `build/installer.iss` is the opposite — its paths resolve against `build/`.

**CI reality:** `release.yml` runs `python -m unittest discover tests -v`, `build/make_icon.py`,
then pyinstaller. There is **no `pull_request` trigger** — tests run *after* merge, inside the
release job, and every push to main publishes a public Release tagged `v1.0.<run_number>`.
`npm test` is never run by CI. The published `.exe` is never executed before release.

## Non-negotiable invariants

1. **AAD is bound to the row's immutable `uuid`.** `_password_aad`/`_notes_aad` (`vault.py:64-69`)
   produce `cred:{uuid}:password` / `cred:{uuid}:notes`. Never re-bind to `id`, `service_name`, or
   `username` — `update_credential` renames those. Never change the literal format: **there is no
   rekey/migration code anywhere in the repo**, so a change makes every existing vault permanently
   undecryptable. No test asserts this; the suite stays green if you break it.
2. **Never change `_VERIFIER_PLAINTEXT` / `_VERIFIER_AAD`** (`crypto.py:57-58`). A failed verifier
   surfaces as "Master password is incorrect." — indistinguishable from a typo, so the user never
   learns their vault was bricked.
3. **`crypto.encrypt` takes no nonce parameter. Keep it that way** — it is the only thing
   guaranteeing the fresh `os.urandom(12)` at `crypto.py:124`.
4. **Checksum columns hash CIPHERTEXT, never plaintext.** `credentials.password_sha256` is
   misleadingly named — it is `sha256_hex(blob)` (`vault.py:170-171, 212-215`). Nothing tests it.
   Rename the column if it bothers you; never change what it hashes. Never store any hash or HMAC
   of a password, a note, or the master password.
5. **All randomness for secrets comes from `secrets`, never `random`.** `generator.py` uses
   `secrets.choice`/`secrets.randbelow` throughout, including a hand-rolled Fisher-Yates
   (`generator.py:96-99`) precisely because `random.shuffle` is not secure. No test would catch a
   swap — the generator tests only check character-class membership.
6. **`leakcheck` may never widen what leaves the machine.** Exactly `sha1[:5]` goes out
   (`leakcheck.py:42-43`); the full-hash compare is local. `Add-Padding: true` (`leakcheck.py:27`)
   is part of the same defence — dropping it lets response size fingerprint the prefix. **Nothing
   tests either**: the retry tests stub `requests.get` with a lambda that discards the URL.
7. **Every password write appends a history row inside the same `db.connect` block** — including
   the first, from `add_credential`, sharing one `now` and one `checksum`. Miss it and
   `verify_integrity` false-alarms on every launch, and the credential drops out of the age audit.
8. **Never let an error distinguish "wrong key" from "tampered ciphertext"** (`crypto.py:136-139`,
   `backup.py:200-203`, `vault.py:138-139`). Length-truncation is the one existing exception.
9. **Backup AAD is the header's raw bytes as read off disk** (`backup.py:159` `_header_bytes` →
   `196-197`), never a re-serialization of the parsed dict — that is not guaranteed byte-identical,
   and every previously written backup becomes unopenable. (It uniquely authenticates
   `mode`/`created_at`/`app`/`v`; salt and kdf_params already feed derivation.)
10. **Keep the PBKDF2 600,000-iteration floor** (`crypto.py:110-114`). Its real value is on paths
    deriving a NEW key from externally-supplied params — today only `backup.derive_key`, reading an
    attacker-writable `.nmpbak` header. Argon2 params there are **not** floored or capped: a known
    hole (see Traps).
11. **On unlock, replay the KDF recorded in `vault_meta`** — never `default_kdf()`, which is for
    vault creation only (2 callers: `vault.py:94`, `vault.py:329`).
12. **All SQL is a static literal with `?` binding, and lives in `db.py`.** Passwords legitimately
    contain `'`, `"`, `;`, `--`. The one statement outside db.py is the static `sqlite_master` probe
    at `vault.py:77-79`. Guarded by `SqlInjectionPolicyTests` (`tests/test_core.py:385`) — but that
    is four regexes scanning `db.py`'s source only. It is a smoke alarm, not a proof.
13. **Outside `db.py`, never open the vault for writes with a bare `sqlite3.connect`.** Only
    `db.connect` sets `PRAGMA foreign_keys = ON`, the sole thing preventing orphaned
    `password_history` rows — and `db.all_history` is an INNER JOIN, so orphaned ciphertext is
    invisible to `verify_integrity` forever. (`db.snapshot_bytes` raw-connects deliberately.)
14. **`allowed_origins` stays a single pinned extension ID** (`browser_bridge.py:126`), equal to
    the ID Chrome derives from `extension/manifest.json`'s `key`. A mismatch reports "✓ Connected"
    while silently refusing every connection. Guarded by
    `tests/test_views.py::test_pinned_extension_id_matches_the_committed_manifest_key`.
    Never commit `extension/.keys/` — the private half lets anyone build an extension carrying the
    ID the user's registered host already authorizes.
15. **Nothing on the `--native-host` path writes to stdout except `_send`**, and `--native-host`
    must dispatch before the Qt-pulling `.app` import in both `NoMorePwn.py` and
    `nomorepwn_app/__main__.py`. Stray stdout corrupts the 4-byte-length frame stream; the only
    symptom is a dropped browser connection.

## Traps

**Crypto / vault**
- `lock()` does not disable the object. It rebinds `self._key = b""` (Python bytes are immutable —
  nothing is wiped). `list_credentials`, `password_history`, `_row_to_public` all still work. Crypto
  paths raise a bare `builtins.ValueError: AESGCM key must be 128, 192, or 256 bits` — not
  `VaultError`, not `CryptoError` — because `crypto.decrypt` has no key-length guard. Every UI
  reveal site wraps in `except Exception`, so the symptom is a **silently blank password field**.
  Gate on `self.vault is not None`; drop the object to actually revoke access.
- `create_vault` can silently re-key a populated vault. `vault_exists` is False whenever the
  `verifier` meta row is missing (tamper, or interrupted creation); `init_schema` is
  `CREATE TABLE IF NOT EXISTS` and `set_meta` upserts, so rows survive while kdf_salt/verifier are
  overwritten. Every secret becomes permanently undecryptable, reported as "authentication failed".
- `update_credential` is a **PUT, not a PATCH**. `notes=""` and `mfa_enabled=False` defaults erase
  notes and clear MFA, with no error and no history row. Read current values first.
- Editor + failed notes decryption = **permanent data loss**: `editor.py:153-157` swallows the
  exception into `notes=""`, then Save writes NULL over the ciphertext.
- `merge_from`'s `skipped` counter renders as "already present" but also absorbs decrypt and
  validation failures (`vault.py:398-400`). A partially corrupt import reports losses as duplicates.
- Duplicate detection is case-**sensitive** while the list sorts case-**insensitively**.
  `view_vault.py:218-232` then re-finds the saved item by lowercased service+username instead of
  `_cred_id` — it can select the wrong row.
- `verify_integrity` covers `password_enc` only. Notes have no checksum and no GCM probe — notes
  tampering returns a clean bill of health. History rows are checksum-only, never GCM-verified.
- `validate_*` **returns** the cleaned value — reassign it. Identifiers are `.strip()`ed before the
  length check; passwords and notes deliberately are not. Adding `.strip()` to `validate_password`
  is a security bug. Allowlists are ASCII-only (`café.com`, `日本.com`, `_alice` all rejected).
- `SCHEMA_VERSION` is write-only; `init_schema` only runs inside `create_vault`. Bumping it
  migrates nothing. `delete_credential` is the one mutator with no existence check.

**Backups**
- Any path replacing `vault.db` under a live `Vault` must call `backups.discard_pending()` **and**
  `lock(flush=False)` (`controller.py:249-254`) — `backup_material()` re-reads kdf metadata from the
  *new* file while `self._key` is the *old* one. Conversely, never lock before flushing
  (`controller.py:135-142`).
- `flush_sync()` is not a guaranteed write: it stops the debounce timer *before* bailing on
  `self._running`, leaving `_dirty` set with nothing to restart it. A failed backup is never retried,
  and `rotate()` renames the primary away *before* the write — a failure leaves no backup at all.
- "Back up now" is a silent no-op when auto-backup is off, while toasting "Backing up…".
- `read_header`'s V1 branch lacks V2's guards; corrupt blobs raise `struct.error`/`JSONDecodeError`
  past every `except BackupError`. A crafted header with a gigabyte `memory_cost` wedges the app the
  moment Restore is clicked — no upper bound on Argon2 params, no cancel path.
- `db.snapshot_bytes` writes a full **unencrypted** vault copy to the system temp dir on every
  backup (4s debounce after any edit).

**Builds, updates, and running the packaged app**
- **A running instance silently swallows new launches.** `app.py:48` `_already_running_then_show()`
  connects to a per-user `QLocalServer`, tells the existing instance to show itself, and returns 0.
  Launching a freshly built .exe while any NoMorePwn is running exits immediately with **no error
  and no output** — it looks exactly like a crash. Check `Get-Process NoMorePwn` before concluding
  a build is broken.
- **The version is baked at build time** into `nomorepwn_app/_build_info.py` by the spec, and that
  file is gitignored. Never reintroduce `os.environ.get("NOMOREPWN_VERSION")` at module scope: it
  evaluates on the *user's* machine where the variable is unset, which is why every release
  reported `1.0.0`. A source checkout reports `0.0.0-dev`, which `updater.parse_version` refuses
  outright so a checkout is never offered an installer.
- **Every push to main publishes a PRE-RELEASE.** `/releases/latest` skips those, so users only
  move when you promote a release. Drop `prerelease: true` from `release.yml` and every push
  auto-updates every install — with tests running *after* merge.
- **Lock the vault before launching the installer** (`controller.apply_update`). It replaces the
  running .exe and restarts it. Guarded by `tests/test_views.py::UpdateApplyOrderingTests`.
- The installer's SHA-256 ships in the same release, so it catches corruption and a swapped asset —
  **not** a compromised account, which could publish a matching checksum. Do not describe updates
  as tamper-proof. Builds are unsigned; SmartScreen will warn.

**App / UI**
- `run_async(fn, on_done, on_error, *args)` — positional args come *after* the callbacks. Bind with
  a lambda or `partial`; never use the `*args` tail.
- The launch-time integrity sweep passes `lambda e: None` as its error handler. A silent sweep is
  **not** evidence of an untampered vault. There is no logger anywhere in the package.
- `_on_change()` must stay the last statement in `SettingsView._save` — it can destroy the view
  whose slot is running.
- Lock does **not** clear the clipboard (only `quit()` does); `clipboard_clear_seconds = 0` means
  never. Dead settings: `lock_on_minimize`, `ctx.mark_activity`, and
  `startup.is_launch_at_startup()` all have zero readers/callers — the startup checkbox reflects
  settings.json, never the registry.
- Theme colours are baked in at widget construction (`theme._ACTIVE` defaults to DARK at import).
  Any new cached top-level screen must be added to `MainWindow.reset_cached_views()`.
- `icons._pixmap` falls back to the "info" glyph for a mistyped name — no error, and the wrong
  glyph is lru-cached.
- `strength.StrengthResult.crack_time_display` is polymorphic by import: a duration under zxcvbn
  (`strength.py:56`), but `f"~{bits:.0f} bits of entropy"` in the fallback (`strength.py:91`). All
  three callers render it as `f"cracks in {…}"` — **this is a live bug**: without zxcvbn the UI reads
  "Strong · cracks in ~90 bits of entropy".
- `generate_password` silently discards options: `length` is clamped to `[4,128]` with no error, and
  the empty-pool fallback does `opts = PasswordOptions(length=length)`, re-enabling symbols against
  a `LOWER+UPPER+DIGITS` pool — so the result can contain a symbol **outside its own pool**
  (reproduced). `required[:length]` also drops class guarantees at short lengths.

**Extension** (`cd extension; npm test` — nothing else will catch you)
- `pending-store.detach()` does **not** wipe; the caller owns `entry.holder` and must
  `.finally(() => entry.holder.wipe())`. Prefer `discard()` unless you must await.
- Detach synchronously *before* awaiting `subtle.decrypt`. The `if (!entry) return` after detach is
  the exactly-once guard against a trailing 401 or the deadline double-resolving.
- Register every `chrome.*` listener at module top level in `service-worker.js` — never in a
  callback or after an `await`, or the worker misses the events that would have woken it.
- `SecureCredentialHolder` is built via `create()` because construction is async
  (`crypto.subtle.generateKey` is awaited). **`Object.create()` bypasses the constructor entirely,
  so the `INTERNAL` token check never fires and you get an object with uninitialized `#key`/`#iv`/
  `#ciphertext`.** Private fields are installed *only* by a real constructor call. This has already
  happened once here.
- SPAs do not get the 10s `WINDOW_MS` advertises — `VERIFICATION_WINDOW_MS = 5000` in the background
  store hard-caps it, and late verdicts are dropped with no log.
- `verifier.js` `LOGIN_ROUTE` is an unanchored substring regex (`/author/ofek` matches "auth").
  `scoreResponse` never compares origins: third-party traffic in the tab contributes points, and a
  401 from any subframe rejects the capture outright.
- `capture.js` hardcodes its own copy of the message-type strings (content scripts are classic
  scripts and cannot import) and has **zero** test coverage. Renaming a type in
  `shared/messages.js` leaves all 52 checks green and the capture path dead.
- The `content_scripts` `js` array is load-ordered: `spa-observer.js` must stay first.
- The extension is bundled **into** the .exe and materialised to
  `%APPDATA%\NoMorePwn\extension` at startup, version-stamped in `.version`. It is not beside the
  .exe (onefile has no such folder) and not `_MEIPASS` (a temp dir that changes every launch, which
  would break the loaded extension on restart). `build/NoMorePwn.spec` **allowlists** what ships —
  `manifest.json` plus `.js/.json/.css/.html` under `src/` — so `extension/.keys/` is unreachable
  by construction rather than by an exclude list someone has to maintain.

## How to verify a change here

- **`nomorepwn/`** — `python -m unittest discover tests -v`. Vault/backup tests build a real
  Argon2id SQLite vault in a tempdir; never mock crypto or the DB. Tamper tests deliberately reach
  past `db.py` with a bare `sqlite3.connect` to model an out-of-app attacker. Add to the matching
  class in `tests/test_core.py`: stdlib `unittest` only, no pytest, no `unittest.mock` —
  save/reassign/restore module attributes by hand.
- **`nomorepwn_app/` views** — `python -m unittest tests.test_views -v`. Qt runs under
  `QT_QPA_PLATFORM=offscreen` (set at import in that file, before `QApplication`), so views are
  constructible and assertable headlessly. Isolate by patching `config.DB_PATH`. For anything
  visual, actually run `python NoMorePwn.py` — but see the live-vault warning above.
- **`extension/`** — `cd extension; npm test`. Sections share mutable globals and are strictly
  order-dependent (the fake `chrome` must exist before `service-worker.js` is imported; ESM caches
  it, so exactly one import per run). ~22s of that is real sleeps.
- **Native host** — `NativeHostTests` covers `_read`/`_send`/`_handle`/`_vault_present` against
  `io.BytesIO`. To exercise the real process, spawn it and speak the protocol: 4-byte LE length +
  JSON on stdin, same on stdout.

## What to believe

Three rules, each earned by a bug in this repo rather than borrowed from general advice:

- **A failed check is not a passed check.** A bulk breach scan swallowed every network error with
  `except Exception: continue` and reported "No breached passwords found" — a false all-clear in a
  security tool. `leakcheck.ScanOutcome` now keeps `counts`, `failed`, and `complete` separate, and
  `LeakCheckError` exists so callers cannot confuse "didn't run" with "clean".
- **Assert both directions of a boolean.** `native_host._vault_present()` returned False forever —
  `config.VAULT_PATH` doesn't exist (it's `DB_PATH`) and `AttributeError` was swallowed by a broad
  `except`. The test asserted only the False case against an empty sandbox, so it **passed for the
  wrong reason**. Narrow your excepts; assert the True case too.
- **Put security decisions where they can be tested.** The false all-clear was unreachable because
  the logic lived in a Qt callback closure. Decision logic belongs in `nomorepwn/` as a pure
  function over explicit inputs; the view should only render its result.

Enforcement is thin and unevenly distributed: several invariants above have **no test at all**, and
`npm test` is outside CI. Do not infer from a green suite that an invariant is protected — check
whether a test actually covers what you changed.
