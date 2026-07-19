"""Vault orchestration: the API the UI and scripts talk to.

Responsibilities:
* create / unlock the vault (KDF + verifier handshake)
* encrypt-before-write and decrypt-on-demand for every secret field
* append-only password history with SHA-256 checksums
* launch-time integrity sweep (tamper evidence)

The master key is held only in memory on this object. Callers decide
its lifetime (the desktop app holds it until Lock, auto-lock, or exit).
"""

from __future__ import annotations

import secrets
import uuid as uuid_mod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import backup, crypto, db, recovery, validation

# Meta keys for the optional separate backup passphrase.
_BK_NAME = "backup_kdf_name"
_BK_PARAMS = "backup_kdf_params"
_BK_SALT = "backup_kdf_salt"
_BK_WRAPPED = "backup_key_wrapped"
_BACKUP_KEY_AAD = "vault:backup-key"


class VaultError(Exception):
    """Base class for vault-level failures. Messages are UI-safe."""


class VaultNotInitializedError(VaultError):
    pass


class VaultAlreadyExistsError(VaultError):
    pass


class InvalidMasterPasswordError(VaultError):
    pass


class DuplicateCredentialError(VaultError):
    pass


@dataclass(frozen=True)
class IntegrityIssue:
    """One tamper-evidence finding from the launch sweep."""

    credential_id: int
    service_name: str
    username: str
    detail: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _password_aad(cred_uuid: str) -> str:
    return f"cred:{cred_uuid}:password"


def _notes_aad(cred_uuid: str) -> str:
    return f"cred:{cred_uuid}:notes"


def vault_exists(db_path: str | Path) -> bool:
    path = Path(db_path)
    if not path.exists():
        return False
    with db.connect(path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'"
        ).fetchone()
        if row is None:
            return False
        return db.get_meta(conn, "verifier") is not None


def create_vault(db_path: str | Path, master_password: str) -> None:
    """Initialize schema, KDF metadata, and the master-key verifier."""
    if vault_exists(db_path):
        raise VaultAlreadyExistsError(f"A vault already exists at {db_path}.")
    if len(master_password) < 10:
        raise VaultError("Master password must be at least 10 characters.")

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    salt = crypto.generate_salt()
    kdf_name, kdf_params = crypto.default_kdf()
    key = crypto.derive_key(master_password, salt, kdf_name, kdf_params)

    with db.connect(db_path) as conn:
        db.init_schema(conn)
        db.set_meta(conn, "schema_version", str(db.SCHEMA_VERSION))
        db.set_meta(conn, "kdf_name", kdf_name)
        db.set_meta(conn, "kdf_params", crypto.kdf_params_to_json(kdf_params))
        db.set_meta(conn, "kdf_salt", salt.hex())
        db.set_meta(conn, "verifier", crypto.make_verifier(key).hex())
        db.set_meta(conn, "created_at", _now_iso())
        # A random, non-secret vault id. It binds a Recovery Kit to this vault
        # (a kit can only recover the vault it was made for) and never reveals
        # anything — it is not derived from the key or the password.
        db.set_meta(conn, "vault_id", secrets.token_hex(16))


def pre_migration_backup_path(db_path: str | Path, from_version: int) -> Path:
    """Where the untouched copy is parked before a schema upgrade."""
    path = Path(db_path)
    return path.with_name(f"{path.name}.v{from_version}-premigration")


def pre_rekey_backup_path(db_path: str | Path) -> Path:
    """Where the untouched copy is parked before a rekey (recovery / change
    password). Sibling of :func:`pre_migration_backup_path`: a rekey rewrites
    every secret in the file, so an untouched byte-for-byte copy of the vault
    as it was immediately before is written first and never deleted by the
    app (only overwritten by the next rekey)."""
    path = Path(db_path)
    return path.with_name(f"{path.name}.pre-rekey")


def migrate_schema(db_path: str | Path) -> tuple[int, int]:
    """Bring a vault's schema up to date, keeping a copy of the old file.

    Returns ``(from_version, to_version)``; equal values mean nothing ran.

    The backup is the whole point. A migration failing halfway through on a
    password vault is unrecoverable — a rekey needs a working vault to start
    from, and the user's only other copy may be an encrypted `.nmpbak` they need
    this same app to open. So an untouched byte-for-byte copy is written *first*,
    via SQLite's online-backup API rather than a file copy, and left in place.
    `Vault.rekey` writes its own `<vault>.pre-rekey` copy the same way.
    """
    path = Path(db_path)
    with db.connect(path) as conn:
        current = db.read_schema_version(conn)
    if current >= db.SCHEMA_VERSION:
        return current, current

    backup_path = pre_migration_backup_path(path, current)
    try:
        if not backup_path.exists():
            backup_path.write_bytes(db.snapshot_bytes(path))
    except OSError as exc:
        raise VaultError(
            f"Could not write the pre-migration backup at {backup_path}: {exc}. "
            "The vault was left untouched."
        ) from exc

    # db.connect rolls back on any exception, so a failure here leaves the
    # schema exactly as it was — and the backup covers the rest.
    with db.connect(path) as conn:
        return db.migrate(conn)


class Vault:
    """An unlocked vault. Construct via :meth:`Vault.unlock`."""

    def __init__(self, db_path: str | Path, key: bytes):
        self.db_path = Path(db_path)
        self._key = key

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def unlock(cls, db_path: str | Path, master_password: str) -> "Vault":
        if not vault_exists(db_path):
            raise VaultNotInitializedError(
                f"No vault found at {db_path}. Create one first."
            )
        with db.connect(db_path) as conn:
            kdf_name = db.get_meta(conn, "kdf_name")
            kdf_params_raw = db.get_meta(conn, "kdf_params")
            salt_hex = db.get_meta(conn, "kdf_salt")
            verifier_hex = db.get_meta(conn, "verifier")
        if not all((kdf_name, kdf_params_raw, salt_hex, verifier_hex)):
            raise VaultError("Vault metadata is incomplete or corrupted.")

        key = crypto.derive_key(
            master_password,
            bytes.fromhex(salt_hex),
            kdf_name,
            crypto.kdf_params_from_json(kdf_params_raw),
        )
        if not crypto.check_verifier(key, bytes.fromhex(verifier_hex)):
            raise InvalidMasterPasswordError("Master password is incorrect.")
        # Only migrate a vault the caller has proved they can open, and only
        # after the verifier passes — never on a wrong-password attempt.
        migrate_schema(db_path)
        return cls(db_path, key)

    @classmethod
    def unlock_with_recovery(
        cls,
        db_path: str | Path,
        kit_bytes: bytes,
        recovery_code: str,
        totp_secret: str | None = None,
    ) -> "Vault":
        """Open a vault using a Recovery Kit instead of the master password.

        Reconstructs the master key from the kit + recovery code (+ authenticator
        seed, for a ``kit+totp`` kit), proves it against the vault's verifier,
        and returns an unlocked vault. The caller **must** then set a new master
        password via :meth:`rekey` — recovery grants access, not a password.

        Nothing about the kit or its secrets is read from or written to
        ``vault.db``: the only vault data consulted is the non-secret
        ``vault_id`` (to confirm the kit belongs here) and the ``verifier``.
        """
        if not vault_exists(db_path):
            raise VaultNotInitializedError(
                f"No vault found at {db_path}. Create one first."
            )
        header = recovery.read_kit_header(kit_bytes)
        with db.connect(db_path) as conn:
            vault_id = db.get_meta(conn, "vault_id")
            verifier_hex = db.get_meta(conn, "verifier")
        if not vault_id:
            raise recovery.RecoveryError(
                "This vault has no recovery id, so no kit can be matched to it."
            )
        if header.get("vault_id") != vault_id:
            raise recovery.RecoveryError(
                "This recovery kit was made for a different vault."
            )
        key = recovery.open_kit(kit_bytes, recovery_code, totp_secret)
        try:
            verified = bool(verifier_hex) and crypto.check_verifier(
                key, bytes.fromhex(verifier_hex))
        except ValueError:
            # A tampered/malformed verifier is treated as a failed recovery,
            # not an uncaught error — fail closed.
            verified = False
        if not verified:
            # The kit opened but its key is not this vault's key (e.g. the vault
            # was re-created after the kit was made). Indistinguishable, safe.
            raise recovery.RecoveryError(
                "Recovery failed: the kit did not reconstruct this vault's key."
            )
        return cls(db_path, key)

    def lock(self) -> None:
        """Drop the in-memory key. The object is unusable afterwards."""
        self._key = b""

    @property
    def session_key(self) -> bytes:
        """The in-memory master key, for callers that own its lifetime
        (the desktop app holds it until the vault is locked)."""
        return self._key

    # ------------------------------------------------------------------
    # Master-key recovery & rekey
    # ------------------------------------------------------------------

    def _ensure_vault_id(self) -> str:
        """The vault's non-secret id, generated on demand for vaults created
        before recovery existed."""
        with db.connect(self.db_path) as conn:
            vault_id = db.get_meta(conn, "vault_id")
            if vault_id is None:
                vault_id = secrets.token_hex(16)
                db.set_meta(conn, "vault_id", vault_id)
        return vault_id

    def create_recovery_kit(
        self, mode: str = recovery.MODE_KIT, account_label: str = "NoMorePwn vault"
    ) -> dict:
        """Mint a Recovery Kit for this (unlocked) vault.

        Returns the material to show the user **once** and the ``.nmpkit`` bytes
        for them to save out of band. Crucially, **none** of it is written to
        the vault: only the non-secret ``vault_id`` is persisted here. The
        recovery code, the escrow blob, and (for ``kit+totp``) the authenticator
        seed exist only in the returned dict and wherever the user stores them.
        """
        if mode not in recovery._MODES:
            raise VaultError(f"Unknown recovery mode: {mode!r}.")
        vault_id = self._ensure_vault_id()
        recovery_key = recovery.generate_recovery_key()
        totp_secret = (
            recovery.generate_totp_secret() if mode == recovery.MODE_KIT_TOTP else None
        )
        kit_bytes = recovery.build_kit(
            self._key, recovery_key, vault_id, mode, totp_secret
        )
        result = {
            "mode": mode,
            "vault_id": vault_id,
            "kit_bytes": kit_bytes,
            "recovery_code": recovery.encode_recovery_code(recovery_key),
        }
        if totp_secret is not None:
            result["totp_secret"] = totp_secret
            result["totp_uri"] = recovery.totp_provisioning_uri(totp_secret, account_label)
        return result

    def rekey(self, new_master_password: str) -> None:
        """Re-encrypt every secret under a key derived from a new password.

        This is the repo's one rekey path — used by recovery (to give a new
        password after opening with a kit) and by change-master-password. Each
        secret is decrypted under the current key and re-encrypted under the new
        one with its **own uuid-bound AAD unchanged** (invariant 1: the AAD
        format never changes; only the key does). A byte-for-byte snapshot is
        written to ``<vault>.pre-rekey`` first (sibling of invariant 17) — the
        only recovery path if a rekey is interrupted — and the whole rewrite
        runs in a single transaction, so a failure rolls back untouched.
        """
        if len(new_master_password) < 10:
            raise VaultError("Master password must be at least 10 characters.")

        # Snapshot the untouched vault before rewriting a single ciphertext.
        snap_path = pre_rekey_backup_path(self.db_path)
        try:
            snap_path.write_bytes(db.snapshot_bytes(self.db_path))
        except OSError as exc:
            raise VaultError(
                f"Could not write the pre-rekey backup at {snap_path}: {exc}. "
                "The vault was left untouched."
            ) from exc

        old_key = self._key
        new_salt = crypto.generate_salt()
        kdf_name, kdf_params = crypto.default_kdf()
        new_key = crypto.derive_key(new_master_password, new_salt, kdf_name, kdf_params)

        with db.connect(self.db_path) as conn:
            for cred in db.list_credentials(conn):
                uuid = cred["uuid"]
                old_sum = cred["password_sha256"]
                pw_aad = _password_aad(uuid)
                plaintext = crypto.decrypt(old_key, cred["password_enc"], pw_aad)
                new_blob = crypto.encrypt(new_key, plaintext, pw_aad)
                new_sum = crypto.sha256_hex(new_blob)

                new_notes = None
                if cred["notes_enc"] is not None:
                    notes_aad = _notes_aad(uuid)
                    notes_pt = crypto.decrypt(old_key, cred["notes_enc"], notes_aad)
                    new_notes = crypto.encrypt(new_key, notes_pt, notes_aad)

                db.rekey_credential(conn, cred["id"], new_blob, new_sum, new_notes)

                # Keep the history row that mirrors the current password
                # byte-identical to it (invariant 7 / verify_integrity layer 2);
                # re-encrypt older versions independently.
                for hist in db.list_history(conn, cred["id"]):
                    if hist["ciphertext_sha256"] == old_sum:
                        db.rekey_history(conn, hist["id"], new_blob, new_sum)
                    else:
                        h_pt = crypto.decrypt(old_key, hist["password_enc"], pw_aad)
                        h_blob = crypto.encrypt(new_key, h_pt, pw_aad)
                        db.rekey_history(conn, hist["id"], h_blob, crypto.sha256_hex(h_blob))

            # Re-wrap the separate backup key, if one is configured.
            wrapped = db.get_meta(conn, _BK_WRAPPED)
            if wrapped:
                backup_key = crypto.decrypt(
                    old_key, bytes.fromhex(wrapped), _BACKUP_KEY_AAD
                )
                db.set_meta(
                    conn, _BK_WRAPPED,
                    crypto.encrypt(new_key, backup_key, _BACKUP_KEY_AAD).hex(),
                )

            db.set_meta(conn, "kdf_name", kdf_name)
            db.set_meta(conn, "kdf_params", crypto.kdf_params_to_json(kdf_params))
            db.set_meta(conn, "kdf_salt", new_salt.hex())
            db.set_meta(conn, "verifier", crypto.make_verifier(new_key).hex())

        self._key = new_key

    # ------------------------------------------------------------------
    # Credential CRUD (encrypt-before-write, decrypt-on-demand)
    # ------------------------------------------------------------------

    def add_credential(
        self,
        service_name: str,
        username: str,
        password: str,
        notes: str = "",
        mfa_enabled: bool = False,
        group_name: str = "",
        alt_login: str = "",
    ) -> int:
        service_name = validation.validate_service_name(service_name)
        username = validation.validate_username(username)
        password = validation.validate_password(password)
        notes = validation.validate_notes(notes)
        group_name = validation.validate_group_name(group_name)
        alt_login = validation.validate_alt_login(alt_login)

        cred_uuid = str(uuid_mod.uuid4())
        blob = crypto.encrypt(self._key, password.encode("utf-8"), _password_aad(cred_uuid))
        checksum = crypto.sha256_hex(blob)
        notes_enc = (
            crypto.encrypt(self._key, notes.encode("utf-8"), _notes_aad(cred_uuid))
            if notes
            else None
        )
        now = _now_iso()

        with db.connect(self.db_path) as conn:
            if db.find_credential(conn, service_name, username) is not None:
                raise DuplicateCredentialError(
                    f"An entry for {service_name} / {username} already exists."
                )
            cred_id = db.insert_credential(
                conn,
                uuid=cred_uuid,
                service_name=service_name,
                username=username,
                password_enc=blob,
                password_sha256=checksum,
                notes_enc=notes_enc,
                mfa_enabled=mfa_enabled,
                now_iso=now,
                group_name=group_name,
                alt_login=alt_login,
            )
            # Every version — including the first — gets a history row,
            # so the age metric and tamper sweep cover the whole lifetime.
            db.insert_history(
                conn,
                credential_id=cred_id,
                password_enc=blob,
                ciphertext_sha256=checksum,
                changed_at_iso=now,
            )
        return cred_id

    def update_password(self, cred_id: int, new_password: str) -> None:
        new_password = validation.validate_password(new_password)
        with db.connect(self.db_path) as conn:
            row = db.get_credential(conn, cred_id)
            if row is None:
                raise VaultError("Credential not found.")
            blob = crypto.encrypt(
                self._key, new_password.encode("utf-8"), _password_aad(row["uuid"])
            )
            checksum = crypto.sha256_hex(blob)
            now = _now_iso()
            db.update_credential_password(conn, cred_id, blob, checksum, now)
            db.insert_history(
                conn,
                credential_id=cred_id,
                password_enc=blob,
                ciphertext_sha256=checksum,
                changed_at_iso=now,
            )

    def update_credential(
        self,
        cred_id: int,
        service_name: str,
        username: str,
        notes: str = "",
        mfa_enabled: bool = False,
        group_name: str | None = None,
        alt_login: str | None = None,
    ) -> None:
        """Edit a credential's metadata and notes (not its password).

        The password keeps its own tamper-evident history, so password
        changes go through :meth:`update_password`; this handles the
        renamable/editable fields. Notes are re-encrypted under the row's
        existing UUID-bound AAD.

        ``group_name=None`` means *leave the group as it is*, deliberately
        unlike the ``notes=""`` default beside it: that default silently
        erases notes on any caller that forgets to pass them, which is a
        known data-loss trap in this codebase. A new field should not repeat
        it. Pass ``""`` explicitly to clear the group.
        """
        service_name = validation.validate_service_name(service_name)
        username = validation.validate_username(username)
        notes = validation.validate_notes(notes)
        with db.connect(self.db_path) as conn:
            row = db.get_credential(conn, cred_id)
            if row is None:
                raise VaultError("Credential not found.")
            if group_name is None:
                group_name = row["group_name"] if "group_name" in row.keys() else ""
            else:
                group_name = validation.validate_group_name(group_name)
            # Same None-means-unchanged contract as group_name, for the same
            # reason: a PUT default must not silently erase a field.
            if alt_login is None:
                alt_login = row["alt_login"] if "alt_login" in row.keys() else ""
            else:
                alt_login = validation.validate_alt_login(alt_login)
            existing = db.find_credential(conn, service_name, username)
            if existing is not None and existing["id"] != cred_id:
                raise DuplicateCredentialError(
                    f"An entry for {service_name} / {username} already exists."
                )
            notes_enc = (
                crypto.encrypt(self._key, notes.encode("utf-8"), _notes_aad(row["uuid"]))
                if notes
                else None
            )
            db.update_credential_meta(
                conn, cred_id, service_name, username, notes_enc, mfa_enabled,
                _now_iso(), group_name, alt_login,
            )

    def list_groups(self) -> list[str]:
        """Group names currently in use, alphabetically. Never includes ""."""
        with db.connect(self.db_path) as conn:
            return db.list_group_names(conn)

    def list_identifiers(self) -> list[str]:
        """Login identifiers already in use, most-reused first (autocomplete)."""
        with db.connect(self.db_path) as conn:
            return db.list_identifiers(conn)

    def set_group(self, cred_id: int, group_name: str) -> str:
        """Move one credential into a group ("" removes it from any group).

        Returns the validated name actually stored, so callers can reflect
        the trimmed value back into the UI.
        """
        group_name = validation.validate_group_name(group_name)
        with db.connect(self.db_path) as conn:
            if db.get_credential(conn, cred_id) is None:
                raise VaultError("Credential not found.")
            db.set_group_name(conn, cred_id, group_name, _now_iso())
        return group_name

    def set_mfa(self, cred_id: int, enabled: bool) -> None:
        with db.connect(self.db_path) as conn:
            if db.get_credential(conn, cred_id) is None:
                raise VaultError("Credential not found.")
            db.set_mfa_enabled(conn, cred_id, enabled, _now_iso())

    def delete_credential(self, cred_id: int) -> None:
        with db.connect(self.db_path) as conn:
            db.delete_credential(conn, cred_id)

    def list_credentials(self) -> list[dict]:
        """Metadata for all credentials. Secrets stay encrypted."""
        with db.connect(self.db_path) as conn:
            rows = db.list_credentials(conn)
        return [self._row_to_public(row) for row in rows]

    def reveal_password(self, cred_id: int) -> str:
        """Decrypt one password on demand."""
        with db.connect(self.db_path) as conn:
            row = db.get_credential(conn, cred_id)
        if row is None:
            raise VaultError("Credential not found.")
        plaintext = crypto.decrypt(
            self._key, row["password_enc"], _password_aad(row["uuid"])
        )
        return plaintext.decode("utf-8")

    def reveal_notes(self, cred_id: int) -> str:
        with db.connect(self.db_path) as conn:
            row = db.get_credential(conn, cred_id)
        if row is None:
            raise VaultError("Credential not found.")
        if row["notes_enc"] is None:
            return ""
        return crypto.decrypt(
            self._key, row["notes_enc"], _notes_aad(row["uuid"])
        ).decode("utf-8")

    def password_history(self, cred_id: int) -> list[dict]:
        """History metadata (timestamps + checksums), newest first."""
        with db.connect(self.db_path) as conn:
            rows = db.list_history(conn, cred_id)
        return [
            {
                "id": row["id"],
                "changed_at": row["changed_at"],
                "ciphertext_sha256": row["ciphertext_sha256"],
                "checksum_ok": crypto.sha256_hex(row["password_enc"])
                == row["ciphertext_sha256"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Encrypted backups
    # ------------------------------------------------------------------

    def set_backup_passphrase(self, passphrase: str) -> None:
        """Protect backups with a secret *other than* the master password.

        The derived backup key is stored wrapped under the master key, so
        automatic backups keep working without prompting — while the
        backup FILE still needs this passphrase to open.
        """
        if len(passphrase) < 8:
            raise VaultError("Backup passphrase must be at least 8 characters.")
        salt = crypto.generate_salt()
        kdf_name, kdf_params = crypto.default_kdf()
        backup_key = crypto.derive_key(passphrase, salt, kdf_name, kdf_params)
        wrapped = crypto.encrypt(self._key, backup_key, _BACKUP_KEY_AAD)
        with db.connect(self.db_path) as conn:
            db.set_meta(conn, _BK_NAME, kdf_name)
            db.set_meta(conn, _BK_PARAMS, crypto.kdf_params_to_json(kdf_params))
            db.set_meta(conn, _BK_SALT, salt.hex())
            db.set_meta(conn, _BK_WRAPPED, wrapped.hex())

    def clear_backup_passphrase(self) -> None:
        """Fall back to protecting backups with the master password."""
        with db.connect(self.db_path) as conn:
            for key in (_BK_NAME, _BK_PARAMS, _BK_SALT, _BK_WRAPPED):
                db.delete_meta(conn, key)

    def has_backup_passphrase(self) -> bool:
        with db.connect(self.db_path) as conn:
            return db.get_meta(conn, _BK_WRAPPED) is not None

    def backup_material(self) -> dict:
        """Key + KDF metadata used to seal (and later re-open) a backup."""
        with db.connect(self.db_path) as conn:
            wrapped = db.get_meta(conn, _BK_WRAPPED)
            if wrapped:
                try:
                    key = crypto.decrypt(
                        self._key, bytes.fromhex(wrapped), _BACKUP_KEY_AAD
                    )
                except crypto.DecryptionError as exc:
                    raise VaultError("Stored backup key is corrupted.") from exc
                return {
                    "key": key,
                    "mode": backup.MODE_PASSPHRASE,
                    "kdf_name": db.get_meta(conn, _BK_NAME),
                    "kdf_params": crypto.kdf_params_from_json(db.get_meta(conn, _BK_PARAMS)),
                    "salt_hex": db.get_meta(conn, _BK_SALT),
                }
            # Default: seal under the vault's own master key, and record the
            # vault's KDF metadata so a restore re-derives it from the
            # master password alone.
            return {
                "key": self._key,
                "mode": backup.MODE_MASTER,
                "kdf_name": db.get_meta(conn, "kdf_name"),
                "kdf_params": crypto.kdf_params_from_json(db.get_meta(conn, "kdf_params")),
                "salt_hex": db.get_meta(conn, "kdf_salt"),
            }

    def write_backup(self, dest_path) -> "Path":
        """Write an encrypted backup of this vault to ``dest_path``."""
        material = self.backup_material()
        return backup.write_backup(
            self.db_path, dest_path, material["key"],
            mode=material["mode"], kdf_name=material["kdf_name"],
            kdf_params=material["kdf_params"], salt_hex=material["salt_hex"],
        )

    def merge_from(self, other: "Vault") -> tuple[int, int]:
        """Copy credentials from ``other`` that this vault doesn't have.

        Matching is by (service_name, username). Returns
        ``(imported, skipped)``. Existing entries are never overwritten,
        so importing is always additive and safe.
        """
        imported = skipped = 0
        for cred in other.list_credentials():
            try:
                password = other.reveal_password(cred["id"])
                notes = other.reveal_notes(cred["id"])
            except Exception:
                skipped += 1
                continue
            try:
                self.add_credential(
                    cred["service_name"], cred["username"], password,
                    notes, bool(cred["mfa_enabled"]),
                )
            except (DuplicateCredentialError, validation.ValidationError, VaultError):
                skipped += 1
            else:
                imported += 1
        return imported, skipped

    # ------------------------------------------------------------------
    # Tamper-evidence sweep + age metric
    # ------------------------------------------------------------------

    def verify_integrity(self) -> list[IntegrityIssue]:
        """Launch-time sweep. An empty list means everything checks out.

        Three layers, cheapest first:
        1. SHA-256 of every history blob matches its stored checksum.
        2. The current ciphertext's stored checksum matches a recompute
           AND matches the newest history row (detects out-of-band swaps).
        3. Every current blob actually decrypts under this vault's key
           with its row-bound AAD — the cryptographic proof (AES-GCM tag),
           which an attacker cannot forge without the master key.
        """
        issues: list[IntegrityIssue] = []
        with db.connect(self.db_path) as conn:
            creds = db.list_credentials(conn)
            for cred in creds:
                ident = (cred["id"], cred["service_name"], cred["username"])

                if crypto.sha256_hex(cred["password_enc"]) != cred["password_sha256"]:
                    issues.append(IntegrityIssue(
                        *ident,
                        detail="Current ciphertext does not match its stored SHA-256 checksum.",
                    ))

                latest = db.latest_history_entry(conn, cred["id"])
                if latest is None:
                    issues.append(IntegrityIssue(
                        *ident, detail="No history rows exist (history was deleted)."
                    ))
                elif latest["ciphertext_sha256"] != cred["password_sha256"]:
                    issues.append(IntegrityIssue(
                        *ident,
                        detail="Current password does not match the newest history entry.",
                    ))

                try:
                    crypto.decrypt(
                        self._key, cred["password_enc"], _password_aad(cred["uuid"])
                    )
                except crypto.DecryptionError:
                    issues.append(IntegrityIssue(
                        *ident,
                        detail="AES-GCM authentication failed: ciphertext was modified or swapped.",
                    ))

            for hist in db.all_history(conn):
                if crypto.sha256_hex(hist["password_enc"]) != hist["ciphertext_sha256"]:
                    issues.append(IntegrityIssue(
                        credential_id=hist["credential_id"],
                        service_name=hist["service_name"],
                        username=hist["username"],
                        detail=(
                            f"History entry from {hist['changed_at']} fails its "
                            "SHA-256 checksum."
                        ),
                    ))
        return issues

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row_to_public(self, row) -> dict:
        last_changed = self._last_changed(row["id"])
        return {
            "id": row["id"],
            "service_name": row["service_name"],
            "username": row["username"],
            # Defensive: a row read through a connection opened before the
            # migration ran has no such column.
            "group_name": (row["group_name"] if "group_name" in row.keys() else ""),
            "alt_login": (row["alt_login"] if "alt_login" in row.keys() else ""),
            "mfa_enabled": bool(row["mfa_enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_changed": last_changed,
            "age_days": self._age_days(last_changed),
        }

    def _last_changed(self, cred_id: int) -> str | None:
        with db.connect(self.db_path) as conn:
            latest = db.latest_history_entry(conn, cred_id)
        return latest["changed_at"] if latest else None

    @staticmethod
    def _age_days(changed_at_iso: str | None) -> int | None:
        """Days the password has remained unchanged — the UI's age metric."""
        if changed_at_iso is None:
            return None
        changed = datetime.fromisoformat(changed_at_iso)
        if changed.tzinfo is None:
            changed = changed.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - changed).days)
