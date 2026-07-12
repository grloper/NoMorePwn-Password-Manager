#!/usr/bin/env python3
"""Create a new encrypted vault interactively.

Usage:
    python scripts/init_db.py [--db path/to/vault.db]

Prompts for a master password (never echoed, never stored — only its
Argon2id/PBKDF2 derivation is used, and only a sealed verifier plus the
salt and KDF parameters are written to disk).
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import config, crypto, vault


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize a new NoMorePwn vault.")
    parser.add_argument(
        "--db",
        default=str(config.DB_PATH),
        help=f"Vault file location (default: {config.DB_PATH})",
    )
    args = parser.parse_args()

    if vault.vault_exists(args.db):
        print(f"ERROR: A vault already exists at {args.db}. Refusing to overwrite.")
        return 1

    kdf_name, _ = crypto.default_kdf()
    print(f"Creating vault at: {args.db}")
    print(f"Key derivation:    {kdf_name}")
    print()
    print("Choose a master password. It is the ONLY key to your vault —")
    print("there is no recovery if you forget it. Use a long passphrase.")
    print()

    password = getpass.getpass("Master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    if password != confirm:
        print("ERROR: Passwords do not match.")
        return 1

    config.ensure_data_dir()
    try:
        vault.create_vault(args.db, password)
    except vault.VaultError as exc:
        print(f"ERROR: {exc}")
        return 1

    print()
    print(f"Vault created: {args.db}")
    print("Next steps:")
    print("  1. Import your notepad file:  python scripts/import_notepad.py <file>")
    print("  2. Launch the dashboard:      streamlit run app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
