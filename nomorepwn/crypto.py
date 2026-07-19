"""Cryptographic core: key derivation, authenticated encryption, checksums.

Design
------
* A single Master Password + a random 16-byte salt is stretched into a
  256-bit key with Argon2id (preferred) or PBKDF2-HMAC-SHA256 with
  600,000 iterations (fallback when argon2-cffi is unavailable). The
  KDF name and parameters are persisted alongside the salt so a vault
  is always self-describing and old vaults keep unlocking after
  defaults change.

* Sensitive fields are sealed with AES-256-GCM. Every encryption uses a
  fresh random 96-bit nonce, stored as the first 12 bytes of the blob:
  ``blob = nonce || ciphertext+tag``. GCM's authentication tag makes
  every blob cryptographically tamper-evident: any bit-flip, truncation
  or swap causes decryption to fail loudly instead of returning garbage.

* Each blob is bound to its database row via Additional Authenticated
  Data (AAD, e.g. ``cred:<uuid>:password``). An attacker who copies a
  valid ciphertext from one row into another cannot get it to decrypt,
  because the AAD no longer matches.

* SHA-256 checksums of ciphertext blobs are stored in the history table
  and re-verified on every launch. This is the fast, key-independent
  integrity sweep; AES-GCM remains the cryptographic guarantee.

The master key only ever lives in process memory while the vault is
unlocked. It is never written to disk in any form.
"""

from __future__ import annotations

import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_raw

    HAS_ARGON2 = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_ARGON2 = False

KEY_LEN = 32          # 256-bit AES key
SALT_LEN = 16         # 128-bit random salt
NONCE_LEN = 12        # 96-bit GCM nonce (NIST-recommended size)
PBKDF2_MIN_ITERATIONS = 600_000

# Argon2id parameters follow current OWASP guidance (64 MiB, t=3, p=4).
DEFAULT_ARGON2_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
DEFAULT_PBKDF2_PARAMS = {"iterations": PBKDF2_MIN_ITERATIONS}

_VERIFIER_PLAINTEXT = b"nomorepwn-master-key-verifier-v1"
_VERIFIER_AAD = "vault:verifier"


class CryptoError(Exception):
    """Base class for cryptographic failures."""


class DecryptionError(CryptoError):
    """Wrong key, wrong AAD, or tampered ciphertext."""


def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def default_kdf() -> tuple[str, dict]:
    """Return the strongest KDF available in this environment."""
    if HAS_ARGON2:
        return "argon2id", dict(DEFAULT_ARGON2_PARAMS)
    return "pbkdf2_sha256", dict(DEFAULT_PBKDF2_PARAMS)


def derive_key(master_password: str, salt: bytes, kdf_name: str, kdf_params: dict) -> bytes:
    """Stretch the master password into a 256-bit key.

    The caller supplies the KDF name/params recorded at vault creation,
    so unlocking always replays the exact derivation used originally.
    """
    if not master_password:
        raise CryptoError("Master password must not be empty.")
    if len(salt) != SALT_LEN:
        raise CryptoError("Invalid salt length.")

    secret = master_password.encode("utf-8")

    if kdf_name == "argon2id":
        if not HAS_ARGON2:
            raise CryptoError(
                "Vault was created with Argon2id but argon2-cffi is not installed. "
                "Run: pip install argon2-cffi"
            )
        return _argon2_raw(
            secret=secret,
            salt=salt,
            time_cost=int(kdf_params["time_cost"]),
            memory_cost=int(kdf_params["memory_cost"]),
            parallelism=int(kdf_params["parallelism"]),
            hash_len=KEY_LEN,
            type=_Argon2Type.ID,
        )

    if kdf_name == "pbkdf2_sha256":
        iterations = int(kdf_params["iterations"])
        if iterations < PBKDF2_MIN_ITERATIONS:
            raise CryptoError(
                f"Refusing weak PBKDF2 configuration: {iterations} < {PBKDF2_MIN_ITERATIONS} iterations."
            )
        return hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, dklen=KEY_LEN)

    raise CryptoError(f"Unknown KDF: {kdf_name!r}")


def encrypt(key: bytes, plaintext: bytes, aad: str) -> bytes:
    """AES-256-GCM seal. Returns nonce || ciphertext+tag."""
    if len(key) != KEY_LEN:
        raise CryptoError("Encryption key must be 32 bytes.")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, aad: str) -> bytes:
    """AES-256-GCM open. Raises DecryptionError on any tampering/key mismatch."""
    if len(blob) < NONCE_LEN + 16:  # nonce + minimum tag size
        raise DecryptionError("Ciphertext blob is truncated.")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad.encode("utf-8"))
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong master password or tampered data."
        ) from exc


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """Derive a subkey from *high-entropy* input keying material (HKDF-SHA256).

    Used to fold recovery secrets — a full-entropy recovery key, optionally
    combined with a TOTP seed — into an AES-256 key-encryption key, bound to a
    vault via ``salt`` and domain-separated by ``info``.

    This is **not** a password KDF and must never be handed a human password:
    HKDF does no stretching, so it is only safe over material that already has
    full entropy. Passwords stay on Argon2id/PBKDF2 (``derive_key``); the
    600,000-iteration floor and the memory-hard defaults are unaffected by this.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def sha256_hex(blob: bytes) -> str:
    """Checksum used by the tamper-evident history sweep."""
    return hashlib.sha256(blob).hexdigest()


def make_verifier(key: bytes) -> bytes:
    """Sealed sentinel stored at vault creation to validate unlock attempts."""
    return encrypt(key, _VERIFIER_PLAINTEXT, _VERIFIER_AAD)


def check_verifier(key: bytes, verifier_blob: bytes) -> bool:
    """True iff `key` is the vault's real master key."""
    try:
        return decrypt(key, verifier_blob, _VERIFIER_AAD) == _VERIFIER_PLAINTEXT
    except DecryptionError:
        return False


def kdf_params_to_json(params: dict) -> str:
    return json.dumps(params, sort_keys=True)


def kdf_params_from_json(raw: str) -> dict:
    return json.loads(raw)
