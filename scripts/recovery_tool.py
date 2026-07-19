#!/usr/bin/env python3
"""Master-key recovery — mint a Recovery Kit, or recover with one.

The vault's master key is normally derived from your password and never stored,
so a forgotten password means a lost vault. A **Recovery Kit** is an opt-in,
out-of-band escrow of that key: none of it is written into ``vault.db`` (the
threat model assumes an attacker can read and write that file), so the kit only
works together with the recovery secrets you keep yourself.

    # Make a kit (needs the master password now):
    python scripts/recovery_tool.py create-kit --out my.nmpkit
    # Stronger: also require an authenticator seed to recover:
    python scripts/recovery_tool.py create-kit --mode kit+totp --out my.nmpkit

    # Recover a vault whose password you lost, then set a new password:
    python scripts/recovery_tool.py recover my.nmpkit

``kit`` mode recovery needs the kit file + the recovery code. ``kit+totp`` mode
also needs the authenticator seed you saved at setup — the kit file alone (or
kit + code) is deliberately not enough. Recovery **rewrites the whole vault**
under the new password (a ``<vault>.pre-rekey`` copy is saved first).
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import config, recovery, vault


def create_kit(db_path: str, out_path: str, mode: str, master_password: str) -> None:
    unlocked = vault.Vault.unlock(db_path, master_password)
    try:
        kit = unlocked.create_recovery_kit(mode=mode)
    finally:
        unlocked.lock()

    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(kit["kit_bytes"])

    print(f"\nRecovery kit written: {dest} ({dest.stat().st_size:,} bytes)")
    print("\n" + "=" * 66)
    print("  WRITE THESE DOWN NOW — they are shown once and never stored.")
    print("=" * 66)
    print(f"\n  Recovery code:\n    {kit['recovery_code']}")
    if mode == recovery.MODE_KIT_TOTP:
        print("\n  Authenticator second factor — add to your authenticator app")
        print("  AND save the seed somewhere SEPARATE from the kit file:")
        print(f"    seed:    {kit['totp_secret']}")
        print(f"    otpauth: {kit['totp_uri']}")
        print("\n  To recover you will need: the kit file + the recovery code")
        print("  + this seed. Any two of the three are not enough.")
    else:
        print("\n  To recover you will need: the kit file + the recovery code.")
        print("  Keep the code somewhere separate from the kit file.")
    print()


def recover(kit_path: str, db_path: str) -> None:
    kit_bytes = Path(kit_path).read_bytes()
    header = recovery.read_kit_header(kit_bytes)
    mode = header.get("mode")

    code = getpass.getpass("Recovery code: ")
    totp_seed = None
    if mode == recovery.MODE_KIT_TOTP:
        totp_seed = getpass.getpass("Authenticator seed: ")

    unlocked = vault.Vault.unlock_with_recovery(db_path, kit_bytes, code, totp_seed)
    print("Recovery secrets accepted — this kit opens this vault.")

    new1 = getpass.getpass("New master password (min 10 chars): ")
    new2 = getpass.getpass("Confirm new master password: ")
    if new1 != new2:
        raise SystemExit("ERROR: the two passwords do not match.")

    unlocked.rekey(new1)
    unlocked.lock()
    snap = vault.pre_rekey_backup_path(db_path)
    print(f"Vault re-encrypted under the new password. Unlock with it from now on.")
    print(f"A pre-rekey copy (opens with the OLD state) was saved at: {snap}")


def main() -> int:
    parser = argparse.ArgumentParser(description="NoMorePwn master-key recovery.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create-kit", help="Mint a Recovery Kit for a vault.")
    p_create.add_argument("--db", default=str(config.DB_PATH))
    p_create.add_argument("--out", required=True, help="Output .nmpkit file.")
    p_create.add_argument(
        "--mode", choices=[recovery.MODE_KIT, recovery.MODE_KIT_TOTP],
        default=recovery.MODE_KIT,
        help="kit: file + code. kit+totp: also an authenticator seed.",
    )

    p_recover = sub.add_parser(
        "recover", help="Recover a vault with a kit, then set a new password."
    )
    p_recover.add_argument("kit", help="Path to the .nmpkit file.")
    p_recover.add_argument("--db", default=str(config.DB_PATH))

    args = parser.parse_args()

    try:
        if args.command == "create-kit":
            if not vault.vault_exists(args.db):
                print(f"ERROR: No vault at {args.db}.")
                return 1
            create_kit(args.db, args.out, args.mode, getpass.getpass("Master password: "))
        else:
            recover(args.kit, args.db)
    except (vault.VaultError, recovery.RecoveryError) as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
