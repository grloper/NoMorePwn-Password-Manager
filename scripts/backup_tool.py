#!/usr/bin/env python3
"""Zero-knowledge encrypted backup — safe to drop in any cloud bucket.

The desktop app keeps a backup refreshed automatically (Settings →
Encrypted backups). This script is the command-line equivalent, useful
for scripted/off-box copies and for restoring onto a fresh machine.

`export` seals a consistent snapshot of the ENTIRE vault (already
ciphertext for secret fields) inside one more AES-256-GCM layer. The
resulting `.nmpbak` blob leaks nothing — no schema, no service names, no
row counts.

`restore` reverses it. If the vault was configured with a separate backup
passphrase, that passphrase (not the master password) opens the blob.

Usage:
    python scripts/backup_tool.py export  --out vault-2026-07-18.nmpbak
    python scripts/backup_tool.py restore vault-2026-07-18.nmpbak --force
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import backup, config, vault


def export_backup(db_path: str, out_path: str, master_password: str) -> None:
    # Verify the master password BEFORE exporting, so a typo can't produce
    # a backup you can never open.
    unlocked = vault.Vault.unlock(db_path, master_password)
    try:
        dest = unlocked.write_backup(out_path)
        mode = unlocked.backup_material()["mode"]
    finally:
        unlocked.lock()

    size = Path(dest).stat().st_size
    secret = ("your separate backup passphrase" if mode == backup.MODE_PASSPHRASE
              else "your master password")
    print(f"Encrypted backup written: {dest} ({size:,} bytes)")
    print(f"It can only be opened with {secret}.")


def restore_backup(backup_path: str, db_path: str, secret: str, force: bool) -> None:
    blob = Path(backup_path).read_bytes()
    header = backup.read_header(blob)
    print(backup.describe(header))

    target = Path(db_path)
    if target.exists() and not force:
        raise SystemExit(f"ERROR: {target} already exists. Pass --force to overwrite it.")
    backup.restore_to_path(blob, secret, target)
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

    try:
        if args.command == "export":
            if not vault.vault_exists(args.db):
                print(f"ERROR: No vault at {args.db}.")
                return 1
            export_backup(args.db, args.out, getpass.getpass("Master password: "))
        else:
            secret = getpass.getpass("Password/passphrase for this backup: ")
            restore_backup(args.backup, args.db, secret, args.force)
    except (vault.VaultError, backup.BackupError) as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
