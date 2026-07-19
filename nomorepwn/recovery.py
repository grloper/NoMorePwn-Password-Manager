"""Master-key recovery: an out-of-band Recovery Kit that escrows the vault key.

The master key ``K`` is normally derived from the master password and never
stored. This module lets a user, *at their own choice*, escrow ``K`` so a lost
password is recoverable — without ever weakening the password KDF and without
writing a single byte of recovery material into ``vault.db`` or a ``.nmpbak``
(the threat model assumes an attacker can read and write both).

How it works
------------
A **recovery key** ``R`` is 256 bits of CSPRNG output, shown once as a base32
**recovery code** the user records. Because ``R`` is full-entropy it is used
directly (via HKDF) as a key-encryption key — never run through Argon2id/PBKDF2,
which exist to stretch *low*-entropy passwords.

The **Recovery Kit** (a small ``.nmpkit`` file the user stores themselves) holds
only the vault's master key sealed under a key-encryption key derived from the
recovery secrets, plus the non-secret ``vault_id`` and mode. It does **not**
contain ``R`` or the TOTP seed, so the kit file *alone* opens nothing.

Two modes
---------
``kit``       Recovery needs the kit file **and** the recovery code ``R``.
              KEK = HKDF(R, salt=vault_id, info="…kit").

``kit+totp``  Recovery needs the kit file, the recovery code ``R``, **and** an
              authenticator seed ``S``. KEK = HKDF(R‖S, salt=vault_id,
              info="…kit+totp"). ``S`` is shown once (as an ``otpauth://`` QR
              for an authenticator app *and* as text to store apart from the
              kit) and is never persisted by the app. This is a genuine second
              factor precisely because ``S`` lives nowhere the kit or the vault
              file can reach — see docs/design/vault-key-recovery.md for the
              honesty caveat (the rotating 6-digit codes are not what protects
              you; the seed, stored apart, is).

Nothing here reaches the network; ``pyotp`` is offline.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import struct
from datetime import datetime, timezone

import pyotp

from . import crypto

MAGIC = b"NMPKIT1\n"

MODE_KIT = "kit"
MODE_KIT_TOTP = "kit+totp"
_MODES = (MODE_KIT, MODE_KIT_TOTP)

KIT_EXTENSION = ".nmpkit"

RECOVERY_KEY_LEN = 32          # 256-bit recovery key R
_MAX_HEADER_BYTES = 64 * 1024  # a real kit header is ~120 bytes


class RecoveryError(Exception):
    """Recovery could not proceed. Messages are UI-safe (never leak secrets)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Recovery key <-> human recovery code
# --------------------------------------------------------------------------

def generate_recovery_key() -> bytes:
    """A fresh 256-bit recovery key from the CSPRNG (invariant 5: `secrets`)."""
    return secrets.token_bytes(RECOVERY_KEY_LEN)


def encode_recovery_code(recovery_key: bytes) -> str:
    """Render ``R`` as a grouped, transcribable base32 code."""
    if len(recovery_key) != RECOVERY_KEY_LEN:
        raise RecoveryError("Recovery key has the wrong length.")
    body = base64.b32encode(recovery_key).decode("ascii").rstrip("=")
    return "-".join(body[i:i + 5] for i in range(0, len(body), 5))


def decode_recovery_code(code: str) -> bytes:
    """Parse a recovery code back into ``R``. Tolerant of spaces/dashes/case."""
    cleaned = "".join(code.split()).replace("-", "").upper()
    if not cleaned:
        raise RecoveryError("Recovery code is empty.")
    pad = (-len(cleaned)) % 8
    try:
        raw = base64.b32decode(cleaned + "=" * pad, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise RecoveryError("Recovery code is malformed.") from exc
    if len(raw) != RECOVERY_KEY_LEN:
        raise RecoveryError("Recovery code has the wrong length.")
    return raw


# --------------------------------------------------------------------------
# TOTP second factor (offline; seed, not rotating code, is the recovery input)
# --------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """A fresh base32 TOTP seed for an authenticator app (RFC 6238)."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account: str, issuer: str = "NoMorePwn") -> str:
    """``otpauth://`` URI to render as a QR for the user's authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """True iff ``code`` is a currently-valid 6-digit code for ``secret``.

    Not used on the recovery path (recovery consumes the seed itself), but
    useful for confirming at setup that the user successfully added the seed to
    their authenticator before they rely on it.
    """
    try:
        return bool(pyotp.TOTP(secret).verify(str(code).strip(), valid_window=valid_window))
    except Exception:
        return False


def _totp_seed_bytes(secret: str) -> bytes:
    cleaned = "".join(str(secret).split()).replace("-", "").upper()
    pad = (-len(cleaned)) % 8
    try:
        raw = base64.b32decode(cleaned + "=" * pad, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise RecoveryError("Authenticator seed is malformed.") from exc
    if not raw:
        raise RecoveryError("Authenticator seed is empty.")
    return raw


# --------------------------------------------------------------------------
# Key-encryption key
# --------------------------------------------------------------------------

def _kek(recovery_key: bytes, totp_secret: str | None, vault_id: str, mode: str) -> bytes:
    """Derive the AES-256 key that seals/opens the escrowed master key.

    ``mode`` selects both the ingredients and the HKDF ``info`` string, so a
    ``kit+totp`` kit cannot be opened as a ``kit`` even with the right ``R``.
    """
    try:
        salt = bytes.fromhex(vault_id)
    except (TypeError, ValueError) as exc:
        raise RecoveryError("Recovery kit has an invalid vault id.") from exc
    if mode == MODE_KIT_TOTP:
        if not totp_secret:
            raise RecoveryError("This kit also needs its authenticator seed.")
        ikm = recovery_key + _totp_seed_bytes(totp_secret)
        info = b"nmp:recovery:v1:kit+totp"
    elif mode == MODE_KIT:
        ikm = recovery_key
        info = b"nmp:recovery:v1:kit"
    else:
        raise RecoveryError(f"Unknown recovery kit mode: {mode!r}.")
    return crypto.hkdf_sha256(ikm, salt, info)


# --------------------------------------------------------------------------
# Kit build / read / open
# --------------------------------------------------------------------------

def build_kit(master_key: bytes, recovery_key: bytes, vault_id: str, mode: str,
              totp_secret: str | None = None) -> bytes:
    """Seal ``master_key`` into a Recovery Kit blob.

    The header (mode, vault_id, timestamp) doubles as the GCM additional
    authenticated data, so the mode cannot be downgraded and the kit cannot be
    retargeted to another vault without failing to open.
    """
    if mode not in _MODES:
        raise RecoveryError(f"Unknown recovery kit mode: {mode!r}.")
    if len(master_key) != crypto.KEY_LEN:
        raise RecoveryError("Master key has the wrong length.")
    header = {
        "v": 1,
        "app": "NoMorePwn",
        "mode": mode,
        "vault_id": vault_id,
        "created_at": _now_iso(),
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    kek = _kek(recovery_key, totp_secret, vault_id, mode)
    sealed = crypto.encrypt(kek, master_key, header_bytes.decode("utf-8"))
    return MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + sealed


def _read_framed_header(blob: bytes) -> tuple[dict, bytes, int]:
    """Parse the kit's length-framed JSON header with the same guards as the
    backup reader: every malformed input raises :class:`RecoveryError`, never a
    raw ``struct.error`` / ``JSONDecodeError``."""
    if not blob.startswith(MAGIC):
        raise RecoveryError("Not a NoMorePwn recovery kit (bad magic bytes).")
    offset = len(MAGIC)
    if len(blob) < offset + 4:
        raise RecoveryError("Recovery kit is truncated.")
    (header_len,) = struct.unpack(">I", blob[offset:offset + 4])
    offset += 4
    if header_len == 0 or header_len > _MAX_HEADER_BYTES:
        raise RecoveryError("Recovery kit header length is implausible.")
    raw = blob[offset:offset + header_len]
    if len(raw) != header_len:
        raise RecoveryError("Recovery kit is truncated.")
    try:
        header = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RecoveryError("Recovery kit header is corrupted.") from exc
    if not isinstance(header, dict):
        raise RecoveryError("Recovery kit header is corrupted.")
    return header, raw, offset + header_len


def read_kit_header(blob: bytes) -> dict:
    """Parse the (non-secret) kit header — mode, vault_id, timestamp."""
    header, _raw, _offset = _read_framed_header(blob)
    if header.get("mode") not in _MODES:
        raise RecoveryError("Recovery kit has an unknown mode.")
    if not isinstance(header.get("vault_id"), str):
        raise RecoveryError("Recovery kit is missing its vault id.")
    return header


def open_kit(blob: bytes, recovery_code: str, totp_secret: str | None = None) -> bytes:
    """Return the escrowed master key from a kit, given the recovery secrets.

    Raises :class:`RecoveryError` if the recovery code, the second factor, or
    the kit itself is wrong or modified — GCM cannot tell those apart, and
    neither should we.
    """
    header, raw, payload_offset = _read_framed_header(blob)
    mode = header.get("mode")
    vault_id = header.get("vault_id")
    if mode not in _MODES:
        raise RecoveryError("Recovery kit has an unknown mode.")
    if not isinstance(vault_id, str):
        raise RecoveryError("Recovery kit is missing its vault id.")

    recovery_key = decode_recovery_code(recovery_code)
    kek = _kek(recovery_key, totp_secret, vault_id, mode)
    sealed = blob[payload_offset:]
    try:
        master_key = crypto.decrypt(kek, sealed, raw.decode("utf-8"))
    except crypto.DecryptionError as exc:
        raise RecoveryError(
            "Recovery failed: wrong recovery code or second factor, "
            "or the kit was modified."
        ) from exc
    if len(master_key) != crypto.KEY_LEN:
        raise RecoveryError("Recovery kit did not yield a valid key.")
    return master_key
