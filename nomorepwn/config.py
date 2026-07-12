"""Central configuration: file locations and tunable limits."""

import os
from pathlib import Path

# All vault data lives under a single directory that is .gitignore'd.
# Override with the NOMOREPWN_DATA environment variable if you want the
# vault stored elsewhere (e.g. an encrypted volume).
DATA_DIR = Path(os.environ.get("NOMOREPWN_DATA", Path(__file__).resolve().parent.parent / "data"))

DB_FILENAME = "vault.db"
DB_PATH = DATA_DIR / DB_FILENAME

# Audit thresholds (days). Passwords older than these trigger warnings
# in the UI's security audit.
PASSWORD_AGE_WARN_DAYS = 180
PASSWORD_AGE_CRITICAL_DAYS = 365


def ensure_data_dir() -> Path:
    """Create the data directory with owner-only permissions."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass  # non-POSIX filesystems (e.g. some Windows mounts)
    return DATA_DIR
