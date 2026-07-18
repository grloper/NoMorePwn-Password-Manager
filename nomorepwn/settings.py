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
