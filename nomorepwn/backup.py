"""Zero-knowledge encrypted backups — safe to drop in any cloud folder.

A backup seals a consistent snapshot of the ENTIRE vault database (which
already holds only ciphertext for secret fields) inside one more layer of
AES-256-GCM. The resulting ``.nmpbak`` blob leaks nothing: no schema, no
service names, no row counts — only the KDF parameters needed to re-derive
the key, which are useless without your secret.

Two protection modes
--------------------
``master``      The blob is sealed under the vault's own master key. The
                header carries the vault's KDF name/params/salt, so a
                restore re-derives the same key straight from your master
                password. Zero configuration — this is the default.

``passphrase``  The blob is sealed under a key derived from a *separate*
                backup passphrase. The header carries that passphrase's
                salt. So the backup can be stored somewhere you wouldn't
                trust with your master password, and knowing one secret
                does not reveal the other.

                To keep automatic backups friction-free, the derived
                backup key is also stored *inside the vault*, wrapped
                under the master key. That costs nothing: the vault is
                itself encrypted, and the backup FILE still cannot be
                opened without the passphrase.

Blob layout::

    magic "NMPBAK2\\n" | 4-byte BE header length | header JSON
                       | nonce (12) | ciphertext+tag

The header JSON is used verbatim as the GCM additional authenticated
data, so its parameters cannot be altered without failing decryption.

Version 1 blobs (written by older builds) are still readable.
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from . import crypto, db

MAGIC_V2 = b"NMPBAK2\n"
MAGIC_V1 = b"NMPBAK1\n"
V1_AAD = "nomorepwn:backup:v1"

MODE_MASTER = "master"
MODE_PASSPHRASE = "passphrase"

BACKUP_EXTENSION = ".nmpbak"


class BackupError(Exception):
    """Base class for backup failures. Messages are UI-safe."""


class BackupFormatError(BackupError):
    """Not a NoMorePwn backup, or the file is truncated."""


class BackupPasswordError(BackupError):
    """Wrong password/passphrase, or the blob was tampered with."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

def build_blob(vault_bytes: bytes, key: bytes, *, mode: str, kdf_name: str,
               kdf_params: dict, salt_hex: str) -> bytes:
    """Seal ``vault_bytes`` into a self-describing backup blob."""
    header = {
        "v": 2,
        "app": "NoMorePwn",
        "mode": mode,
        "kdf_name": kdf_name,
        "kdf_params": kdf_params,
        "salt": salt_hex,
        "created_at": _now_iso(),
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    # The header doubles as AAD: its KDF parameters are authenticated.
    sealed = crypto.encrypt(key, vault_bytes, header_bytes.decode("utf-8"))
    return MAGIC_V2 + struct.pack(">I", len(header_bytes)) + header_bytes + sealed


def write_backup(db_path: str | Path, dest_path: str | Path, key: bytes, *,
                 mode: str, kdf_name: str, kdf_params: dict, salt_hex: str) -> Path:
    """Snapshot the vault and write an encrypted backup atomically."""
    payload = db.snapshot_bytes(db_path)
    blob = build_blob(payload, key, mode=mode, kdf_name=kdf_name,
                      kdf_params=kdf_params, salt_hex=salt_hex)
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(blob)
    tmp.replace(dest)  # atomic on the same volume
    return dest


def rotate(dest: Path, keep: int) -> None:
    """Keep ``keep`` generations: backup.nmpbak, .1, .2 … (oldest dropped).

    Called BEFORE writing a new primary file, so the current primary
    becomes ``.1``. Guards against a corrupted or truncated latest backup
    taking the only copy with it.
    """
    keep = max(1, int(keep))
    if not dest.exists():
        return
    oldest = dest.with_suffix(dest.suffix + f".{keep - 1}")
    if oldest.exists():
        try:
            oldest.unlink()
        except OSError:
            pass
    for index in range(keep - 2, 0, -1):
        src = dest.with_suffix(dest.suffix + f".{index}")
        if src.exists():
            try:
                src.replace(dest.with_suffix(dest.suffix + f".{index + 1}"))
            except OSError:
                pass
    if keep > 1:
        try:
            dest.replace(dest.with_suffix(dest.suffix + ".1"))
        except OSError:
            pass


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

def read_header(blob: bytes) -> dict:
    """Parse the (non-secret) header without decrypting anything."""
    if blob.startswith(MAGIC_V2):
        offset = len(MAGIC_V2)
        if len(blob) < offset + 4:
            raise BackupFormatError("Backup file is truncated.")
        (header_len,) = struct.unpack(">I", blob[offset:offset + 4])
        offset += 4
        raw = blob[offset:offset + header_len]
        if len(raw) != header_len:
            raise BackupFormatError("Backup file is truncated.")
        try:
            header = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise BackupFormatError("Backup header is corrupted.") from exc
        header["_header_bytes"] = raw
        header["_payload_offset"] = offset + header_len
        return header

    if blob.startswith(MAGIC_V1):
        offset = len(MAGIC_V1)
        (header_len,) = struct.unpack(">I", blob[offset:offset + 4])
        offset += 4
        header = json.loads(blob[offset:offset + header_len].decode("utf-8"))
        header.update({"v": 1, "mode": MODE_MASTER,
                       "_header_bytes": None,
                       "_payload_offset": offset + header_len})
        return header

    raise BackupFormatError("Not a NoMorePwn backup file (bad magic bytes).")


def derive_key(header: dict, secret: str) -> bytes:
    """Re-derive the blob's key from the user's secret using its header."""
    return crypto.derive_key(
        secret,
        bytes.fromhex(header["salt"]),
        header["kdf_name"],
        header["kdf_params"],
    )


def open_blob(blob: bytes, secret: str) -> bytes:
    """Return the decrypted vault database bytes.

    Raises :class:`BackupPasswordError` if the secret is wrong or the blob
    has been tampered with — GCM cannot tell those apart, and neither
    should we.
    """
    header = read_header(blob)
    key = derive_key(header, secret)
    sealed = blob[header["_payload_offset"]:]
    aad = (header["_header_bytes"].decode("utf-8")
           if header.get("_header_bytes") is not None else V1_AAD)
    try:
        return crypto.decrypt(key, sealed, aad)
    except crypto.DecryptionError as exc:
        raise BackupPasswordError(
            "Could not open the backup: wrong password or the file was modified."
        ) from exc


def restore_to_path(blob: bytes, secret: str, dest_path: str | Path) -> Path:
    """Decrypt a backup and write it over ``dest_path`` atomically."""
    vault_bytes = open_blob(blob, secret)
    if not vault_bytes.startswith(b"SQLite format 3\x00"):
        raise BackupError("Decrypted data is not a valid vault database.")
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".restore-tmp")
    tmp.write_bytes(vault_bytes)
    tmp.replace(dest)
    return dest


def describe(header: dict) -> str:
    """One-line, human-readable summary for the restore dialog."""
    when = str(header.get("created_at", "")).replace("T", " ").replace("+00:00", " UTC")
    mode = header.get("mode", MODE_MASTER)
    protection = ("separate backup passphrase" if mode == MODE_PASSPHRASE
                  else "master password")
    return f"Created {when or 'unknown'} · protected by your {protection}"
