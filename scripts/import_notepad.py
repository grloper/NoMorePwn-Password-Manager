#!/usr/bin/env python3
"""Bulk-import a plaintext notepad password file into the encrypted vault.

Expected file format — one credential per line:

    service<DELIM>username<DELIM>password

* DELIM is auto-detected per file (tab, comma, colon, or semicolon) or
  forced with --delimiter.
* The password is everything AFTER the second delimiter, so passwords
  containing the delimiter character import correctly.
* Blank lines and lines starting with '#' are skipped.

Example (comma):
    gmail.com,alice@gmail.com,hunter2!with,commas
    github.com,alice,correct horse battery staple

Every password is validated, encrypted with AES-256-GCM, and written
with parameterized INSERTs. Invalid or duplicate lines are skipped and
reported by line number — passwords are NEVER echoed to the terminal.

Usage:
    python scripts/import_notepad.py passwords.txt
    python scripts/import_notepad.py passwords.txt --delimiter comma --db data/vault.db
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import config, vault
from nomorepwn.validation import ValidationError

DELIMITERS = {"tab": "\t", "comma": ",", "colon": ":", "semicolon": ";"}


def detect_delimiter(lines: list[str]) -> str | None:
    """Pick the delimiter that yields 3+ fields on the most lines.

    Requires a strict majority of lines to parse, so a couple of
    malformed lines don't block the import — they're reported
    individually instead.
    """
    best_name, best_hits = None, 0
    for name in ("tab", "comma", "semicolon", "colon"):
        char = DELIMITERS[name]
        hits = sum(1 for line in lines if line.count(char) >= 2)
        if hits > best_hits:
            best_name, best_hits = name, hits
    return best_name if best_hits > len(lines) / 2 else None


def parse_line(line: str, delim: str, keep_whitespace: bool) -> tuple[str, str, str]:
    """Split into (service, username, password). Password keeps delimiters.

    The password field is stripped by default: notepad formatting like
    "service, user, pass" would otherwise import " pass", which is both
    the wrong password AND hashes differently during breach checks —
    a silent false negative. --keep-whitespace disables stripping for
    passwords that genuinely start/end with spaces.
    """
    parts = line.split(delim, 2)  # maxsplit=2: password may contain the delimiter
    if len(parts) != 3:
        raise ValidationError("Line does not have three delimited fields.")
    password = parts[2] if keep_whitespace else parts[2].strip()
    return parts[0].strip(), parts[1].strip(), password


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import a plaintext password file into the encrypted vault."
    )
    parser.add_argument("file", help="Plaintext file to import.")
    parser.add_argument(
        "--delimiter",
        choices=["auto", *DELIMITERS],
        default="auto",
        help="Field delimiter (default: auto-detect).",
    )
    parser.add_argument("--db", default=str(config.DB_PATH), help="Vault file location.")
    parser.add_argument(
        "--keep-whitespace",
        action="store_true",
        help="Keep leading/trailing whitespace in password fields "
             "(default: stripped, since it's almost always notepad formatting).",
    )
    args = parser.parse_args()

    source = Path(args.file)
    if not source.exists():
        print(f"ERROR: File not found: {source}")
        return 1
    if not vault.vault_exists(args.db):
        print(f"ERROR: No vault at {args.db}. Create one first: python scripts/init_db.py")
        return 1

    raw_lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    data_lines = [
        (num, line)
        for num, line in enumerate(raw_lines, start=1)
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not data_lines:
        print("Nothing to import: the file has no data lines.")
        return 0

    if args.delimiter == "auto":
        detected = detect_delimiter([line for _, line in data_lines])
        if detected is None:
            print(
                "ERROR: Could not auto-detect a delimiter. Every line needs at least "
                "two of the same separator (tab/comma/semicolon/colon). "
                "Retry with --delimiter."
            )
            return 1
        print(f"Auto-detected delimiter: {detected}")
        delim = DELIMITERS[detected]
    else:
        delim = DELIMITERS[args.delimiter]

    master = getpass.getpass("Master password: ")
    try:
        unlocked = vault.Vault.unlock(args.db, master)
    except vault.VaultError as exc:
        print(f"ERROR: {exc}")
        return 1

    imported, skipped = 0, []
    for num, line in data_lines:
        try:
            service, username, password = parse_line(line, delim, args.keep_whitespace)
            unlocked.add_credential(service, username, password)
            imported += 1
        except vault.DuplicateCredentialError:
            skipped.append((num, "duplicate — already in vault"))
        except (ValidationError, vault.VaultError) as exc:
            skipped.append((num, str(exc)))

    unlocked.lock()

    print()
    print(f"Imported:  {imported} credential(s), encrypted with AES-256-GCM.")
    if skipped:
        print(f"Skipped:   {len(skipped)} line(s):")
        for num, reason in skipped:
            print(f"  line {num}: {reason}")
    print()
    print("IMPORTANT: Your plaintext file still exists. Once you've verified the")
    print("import in the dashboard (streamlit run app.py), delete it securely:")
    print(f"  Linux:   shred -u {source}")
    print(f"  macOS:   rm -P {source}   (or use Finder's secure empty trash)")
    print(f"  Windows: use SDelete:  sdelete64.exe {source}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
