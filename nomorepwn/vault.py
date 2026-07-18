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

import uuid as uuid_mod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import backup, crypto, db, validation

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
    # Credential CRUD (encrypt-before-write, decrypt-on-demand)
    # ------------------------------------------------------------------

    def add_credential(
        self,
        service_name: str,
        username: str,
        password: str,
        notes: str = "",
        mfa_enabled: bool = False,
    ) -> int:
        service_name = validation.validate_service_name(service_name)
        username = validation.validate_username(username)
        password = validation.validate_password(password)
        notes = validation.validate_notes(notes)

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
    ) -> None:
        """Edit a credential's metadata and notes (not its password).

        The password keeps its own tamper-evident history, so password
        changes go through :meth:`update_password`; this handles the
        renamable/editable fields. Notes are re-encrypted under the row's
        existing UUID-bound AAD.
        """
        service_name = validation.validate_service_name(service_name)
        username = validation.validate_username(username)
        notes = validation.validate_notes(notes)
        with db.connect(self.db_path) as conn:
            row = db.get_credential(conn, cred_id)
            if row is None:
                raise VaultError("Credential not found.")
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
                conn, cred_id, service_name, username, notes_enc, mfa_enabled, _now_iso()
            )

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
