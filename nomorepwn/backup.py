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

# A real header is ~200 bytes; anything past this is either hostile or corrupt.
_MAX_HEADER_BYTES = 64 * 1024

# Upper bounds on KDF parameters read from an (attacker-writable) header. A
# .nmpbak we wrote only ever carries crypto.DEFAULT_* parameters, so anything
# beyond these bounds is either hostile or unopenable here — and deriving with
# it would wedge the app (a gigabyte Argon2 memory_cost has no cancel path).
# We *reject* rather than clamp: clamping would change the derived key and
# permanently brick a legitimate backup, since GCM cannot open under a
# different key. Parameters inside the bounds pass through unchanged, so a real
# backup still re-derives the identical key.
_ARGON2_BOUNDS = {
    "time_cost": (1, 20),
    "memory_cost": (8, 1_048_576),   # KiB: 8 KiB .. 1 GiB
    "parallelism": (1, 16),
}
# Ceiling only — the 600,000-iteration *floor* stays in crypto.derive_key
# (invariant 10). This just stops a header claiming 10^12 iterations from
# spinning the KDF forever.
_PBKDF2_MAX_ITERATIONS = 100_000_000
_KNOWN_KDFS = ("argon2id", "pbkdf2_sha256")


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

def _read_framed_header(blob: bytes, magic: bytes) -> tuple[dict, bytes, int]:
    """Parse the length-framed JSON header that follows ``magic``.

    Returns ``(header_dict, raw_header_bytes, payload_offset)``. Every malformed
    input — a truncated length field, an implausible length, non-UTF-8 or
    non-JSON bytes — raises :class:`BackupFormatError`, never a raw
    ``struct.error`` / ``JSONDecodeError`` that would sail past a caller's
    ``except BackupError``. Shared by V1 and V2 so both get the same guards;
    the V1 branch used to have none.
    """
    offset = len(magic)
    if len(blob) < offset + 4:
        raise BackupFormatError("Backup file is truncated.")
    (header_len,) = struct.unpack(">I", blob[offset:offset + 4])
    offset += 4
    if header_len == 0 or header_len > _MAX_HEADER_BYTES:
        raise BackupFormatError("Backup header length is implausible.")
    raw = blob[offset:offset + header_len]
    if len(raw) != header_len:
        raise BackupFormatError("Backup file is truncated.")
    try:
        header = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupFormatError("Backup header is corrupted.") from exc
    if not isinstance(header, dict):
        raise BackupFormatError("Backup header is corrupted.")
    return header, raw, offset + header_len


def read_header(blob: bytes) -> dict:
    """Parse the (non-secret) header without decrypting anything."""
    if blob.startswith(MAGIC_V2):
        header, raw, payload_offset = _read_framed_header(blob, MAGIC_V2)
        header["_header_bytes"] = raw
        header["_payload_offset"] = payload_offset
        return header

    if blob.startswith(MAGIC_V1):
        header, _raw, payload_offset = _read_framed_header(blob, MAGIC_V1)
        # V1 predates the header-as-AAD scheme: its AAD is the fixed V1_AAD
        # constant, so the raw header bytes are deliberately NOT used as AAD
        # (invariant 9 applies only to V2). Hence _header_bytes stays None.
        header.update({"v": 1, "mode": MODE_MASTER,
                       "_header_bytes": None,
                       "_payload_offset": payload_offset})
        return header

    raise BackupFormatError("Not a NoMorePwn backup file (bad magic bytes).")


def _validate_kdf(kdf_name, kdf_params) -> None:
    """Reject KDF metadata we will not derive with.

    The header is attacker-writable, so an unknown algorithm, a wrong type, or a
    parameter outside safe bounds is refused *before* a single byte reaches the
    KDF. This is what stops a crafted header (e.g. a gigabyte Argon2
    ``memory_cost``) from wedging the app the moment Restore is clicked.
    """
    if kdf_name not in _KNOWN_KDFS:
        raise BackupFormatError(f"Unsupported backup KDF: {kdf_name!r}.")
    if not isinstance(kdf_params, dict):
        raise BackupFormatError("Backup KDF parameters are malformed.")

    def _as_int(name: str) -> int:
        if name not in kdf_params:
            raise BackupFormatError(f"Backup KDF parameter {name!r} is missing.")
        value = kdf_params[name]
        # bool is an int subclass; a JSON true/false is not a valid parameter.
        if isinstance(value, bool) or not isinstance(value, int):
            raise BackupFormatError(f"Backup KDF parameter {name!r} must be an integer.")
        return value

    if kdf_name == "argon2id":
        for name, (low, high) in _ARGON2_BOUNDS.items():
            value = _as_int(name)
            if not (low <= value <= high):
                raise BackupFormatError(
                    f"Backup Argon2 parameter {name}={value} is outside the "
                    f"supported range [{low}, {high}]."
                )
    else:  # pbkdf2_sha256
        iterations = _as_int("iterations")
        if iterations > _PBKDF2_MAX_ITERATIONS:
            raise BackupFormatError(
                f"Backup PBKDF2 iterations={iterations} exceeds the supported "
                f"maximum of {_PBKDF2_MAX_ITERATIONS}."
            )
        # The 600,000-iteration floor stays in crypto.derive_key (invariant 10).


def derive_key(header: dict, secret: str) -> bytes:
    """Re-derive the blob's key from the user's secret using its header.

    The header is attacker-writable, so its KDF metadata is validated and
    bounded (:func:`_validate_kdf`) before it reaches the KDF, and any residual
    :class:`crypto.CryptoError` (e.g. a below-floor PBKDF2 config, a bad salt
    length) is surfaced as a UI-safe :class:`BackupFormatError` rather than
    leaking past the callers' ``except BackupError``.
    """
    kdf_name = header.get("kdf_name")
    kdf_params = header.get("kdf_params")
    salt_hex = header.get("salt")
    _validate_kdf(kdf_name, kdf_params)
    if not isinstance(salt_hex, str):
        raise BackupFormatError("Backup salt is missing or malformed.")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise BackupFormatError("Backup salt is not valid hex.") from exc
    try:
        return crypto.derive_key(secret, salt, kdf_name, kdf_params)
    except crypto.CryptoError as exc:
        raise BackupFormatError(str(exc)) from exc


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
