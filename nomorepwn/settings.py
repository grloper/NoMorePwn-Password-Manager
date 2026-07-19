"""User-facing application settings, persisted as JSON in the data dir.

This holds *non-secret* preferences only (auto-lock timeout, tray
behaviour, theme, clipboard timeout). No key material or credential data
ever lands here — those stay in the encrypted vault. Unknown/legacy keys
are ignored on load so the file is forward-compatible.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from . import config

# Sentinel for "ask me every time I press the X button".
CLOSE_ASK = "ask"
CLOSE_TRAY = "tray"   # lock + keep running in the background
CLOSE_QUIT = "quit"   # lock + exit completely

# Capture actions for browser extension credentials
CAPTURE_SILENT = "silent"     # Save to "Captured Logins" and show a tray notification
CAPTURE_PROMPT = "prompt"     # Bring window to foreground and show the editor
CAPTURE_DISABLED = "disabled" # Ignore captured credentials entirely

@dataclass
class Settings:
    autolock_minutes: int = config.DEFAULT_AUTOLOCK_MINUTES
    lock_on_minimize: bool = True          # lock whenever the window hides to tray
    close_action: str = CLOSE_ASK          # CLOSE_ASK / CLOSE_TRAY / CLOSE_QUIT
    launch_at_startup: bool = False
    start_minimized: bool = False          # launch straight to the tray
    theme: str = "dark"                    # "dark" | "light"
    clipboard_clear_seconds: int = 20      # auto-wipe copied secrets (0 = never)
    show_notifications: bool = True
    warn_unsaved_on_close: bool = True
    capture_action: str = CAPTURE_SILENT   # CAPTURE_SILENT / CAPTURE_PROMPT / CAPTURE_DISABLED

    # -- Automatic encrypted backups ------------------------------------
    backup_enabled: bool = True
    backup_dir: str = ""          # empty -> <data dir>/backups
    backup_keep: int = 5          # generations retained (.nmpbak, .1, .2 …)
    backup_last_at: str = ""      # ISO timestamp of the last successful run
    backup_last_error: str = ""   # last failure, surfaced in Settings

    # -- Automatic updates ----------------------------------------------
    # Checks GitHub Releases, downloads in the background, then asks before
    # installing. Never applies an update without the user clicking.
    updates_enabled: bool = True
    update_last_check: str = ""    # ISO timestamp of the last completed check
    update_skipped_version: str = ""  # a version the user chose to skip

    # -- persistence ----------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or config.SETTINGS_PATH
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(cls)}
        data = {k: v for k, v in raw.items() if k in known}
        try:
            return cls(**data)
        except TypeError:
            return cls()

    def save(self, path: Path | None = None) -> None:
        path = Path(path or config.SETTINGS_PATH)
        config.ensure_data_dir()
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        tmp.replace(path)  # atomic on the same volume

    # -- helpers --------------------------------------------------------

    def autolock_ms(self) -> int:
        """Auto-lock interval in milliseconds (0 disables auto-lock)."""
        return max(0, int(self.autolock_minutes)) * 60 * 1000

    def backup_directory(self) -> Path:
        """Where backups are written (defaults to <data dir>/backups)."""
        if self.backup_dir:
            return Path(self.backup_dir)
        return config.DATA_DIR / "backups"
