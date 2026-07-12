#!/usr/bin/env python3
"""Zero-knowledge encrypted backup — safe to drop in any cloud bucket.

`export` seals the ENTIRE vault file (which already contains only
ciphertext for secret fields) inside one more AES-256-GCM layer, keyed
from your master password with a FRESH salt. The resulting `.nmpbak`
blob leaks nothing: no schema, no service names, no row counts. Upload
it to Google Drive, Supabase Storage, S3, email it to yourself —
the provider only ever holds random-looking bytes.

`restore` reverses the process on any machine with this repo.

Blob layout:
    magic "NMPBAK1\\n" | 4-byte big-endian header length | header JSON
    (kdf name/params + salt hex, all non-secret) | nonce || ciphertext+tag

Usage:
    python scripts/backup_tool.py export  --out  vault-2026-07-12.nmpbak
    python scripts/backup_tool.py restore vault-2026-07-12.nmpbak --db data/vault.db
"""

from __future__ import annotations

import argparse
import getpass
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import config, crypto, vault

MAGIC = b"NMPBAK1\n"
BACKUP_AAD = "nomorepwn:backup:v1"


def export_backup(db_path: str, out_path: str, master_password: str) -> None:
    # Verify the master password against the vault BEFORE exporting, so a
    # typo can't produce a backup you can never open.
    vault.Vault.unlock(db_path, master_password).lock()

    salt = crypto.generate_salt()  # fresh salt: backup key != vault key
    kdf_name, kdf_params = crypto.default_kdf()
    key = crypto.derive_key(master_password, salt, kdf_name, kdf_params)

    header = json.dumps(
        {"kdf_name": kdf_name, "kdf_params": kdf_params, "salt": salt.hex()}
    ).encode("utf-8")
    sealed = crypto.encrypt(key, Path(db_path).read_bytes(), BACKUP_AAD)

    out = Path(out_path)
    out.write_bytes(MAGIC + struct.pack(">I", len(header)) + header + sealed)
    print(f"Encrypted backup written: {out} ({out.stat().st_size:,} bytes)")
    print("This blob is safe to store anywhere — it is AES-256-GCM ciphertext only.")


def restore_backup(backup_path: str, db_path: str, master_password: str, force: bool) -> None:
    raw = Path(backup_path).read_bytes()
    if not raw.startswith(MAGIC):
        raise SystemExit("ERROR: Not a NoMorePwn backup file (bad magic bytes).")

    offset = len(MAGIC)
    (header_len,) = struct.unpack(">I", raw[offset : offset + 4])
    offset += 4
    header = json.loads(raw[offset : offset + header_len].decode("utf-8"))
    sealed = raw[offset + header_len :]

    key = crypto.derive_key(
        master_password,
        bytes.fromhex(header["salt"]),
        header["kdf_name"],
        header["kdf_params"],
    )
    try:
        plaintext_db = crypto.decrypt(key, sealed, BACKUP_AAD)
    except crypto.DecryptionError:
        raise SystemExit(
            "ERROR: Decryption failed — wrong master password or corrupted backup."
        )

    target = Path(db_path)
    if target.exists() and not force:
        raise SystemExit(
            f"ERROR: {target} already exists. Pass --force to overwrite it."
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plaintext_db)
    print(f"Vault restored to: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-knowledge vault backup/restore.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export", help="Create an encrypted backup blob.")
    p_export.add_argument("--db", default=str(config.DB_PATH))
    p_export.add_argument("--out", required=True, help="Output .nmpbak file.")

    p_restore = sub.add_parser("restore", help="Restore a vault from a backup blob.")
    p_restore.add_argument("backup", help="Path to the .nmpbak file.")
    p_restore.add_argument("--db", default=str(config.DB_PATH))
    p_restore.add_argument("--force", action="store_true", help="Overwrite existing vault.")

    args = parser.parse_args()
    master = getpass.getpass("Master password: ")

    try:
        if args.command == "export":
            if not vault.vault_exists(args.db):
                print(f"ERROR: No vault at {args.db}.")
                return 1
            export_backup(args.db, args.out, master)
        else:
            restore_backup(args.backup, args.db, master, args.force)
    except vault.VaultError as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
