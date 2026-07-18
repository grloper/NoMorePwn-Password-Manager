"""Central configuration: file locations and tunable limits.

Data location precedence:

1. ``NOMOREPWN_DATA`` environment variable, if set (used by tests and by
   anyone who wants the vault on an encrypted volume).
2. The per-user application-data directory for the platform — on Windows
   ``%APPDATA%\\NoMorePwn`` — so an installed ``.exe`` keeps its vault in
   the same place whether it was launched from the Start menu, a tray
   icon, or a fresh reboot. This is the production default.

The vault file itself is never bundled with the app; it is created on
first run and lives entirely under the data directory below.
"""

import os
import sys
from pathlib import Path

APP_NAME = "NoMorePwn"


def _default_data_dir() -> Path:
    """Per-user data directory for the current platform."""
    override = os.environ.get("NOMOREPWN_DATA")
    if override:
        return Path(override)

    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    # Linux / other: honour XDG.
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".local" / "share")
    return base / APP_NAME


DATA_DIR = _default_data_dir()

DB_FILENAME = "vault.db"
DB_PATH = DATA_DIR / DB_FILENAME

SETTINGS_FILENAME = "settings.json"
SETTINGS_PATH = DATA_DIR / SETTINGS_FILENAME

# Audit thresholds (days). Passwords older than these trigger warnings
# in the UI's security audit.
PASSWORD_AGE_WARN_DAYS = 180
PASSWORD_AGE_CRITICAL_DAYS = 365

# Auto-lock: how long the vault may stay unlocked without user activity
# before it locks itself, and the default the settings screen shows.
DEFAULT_AUTOLOCK_MINUTES = 5


def ensure_data_dir() -> Path:
    """Create the data directory with owner-only permissions where possible."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass  # non-POSIX filesystems (e.g. some Windows mounts)
    return DATA_DIR
