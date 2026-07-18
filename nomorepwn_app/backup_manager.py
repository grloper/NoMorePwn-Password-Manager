"""Automatic encrypted backups — fire-and-forget.

Every change to the vault marks it dirty; a short debounce collapses a
burst of edits into a single write, which then runs on a worker thread so
the UI never stutters. Backups are also flushed on lock and on quit, so a
pending change can't be lost by closing the app.

The written blob is useless without the user's secret (see
:mod:`nomorepwn.backup`), which is what makes "just leave it in your
Dropbox folder" a safe default.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from nomorepwn import backup, vault
from nomorepwn.settings import Settings

from . import workers

DEBOUNCE_MS = 4000
PRIMARY_NAME = "vault-backup" + backup.BACKUP_EXTENSION


class BackupManager(QObject):
    completed = Signal(str)   # destination path
    failed = Signal(str)      # user-facing message

    def __init__(self, settings: Settings, get_vault: Callable[[], "vault.Vault | None"],
                 parent=None):
        super().__init__(parent)
        self._settings = settings
        self._get_vault = get_vault
        self._dirty = False
        self._running = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(DEBOUNCE_MS)
        self._timer.timeout.connect(self._run)

    # ------------------------------------------------------------------

    def destination(self) -> Path:
        return self._settings.backup_directory() / PRIMARY_NAME

    def mark_dirty(self) -> None:
        """A vault change happened; schedule a debounced backup."""
        if not self._settings.backup_enabled:
            return
        self._dirty = True
        self._timer.start()

    def flush_sync(self) -> None:
        """Write a pending backup *now*, on this thread.

        Used on lock and on quit: both drop the master key moments later,
        so deferring to a worker would silently lose the backup.
        """
        if not (self._dirty and self._settings.backup_enabled):
            return
        self._timer.stop()
        vlt = self._get_vault()
        if vlt is None or self._running:
            return
        self._dirty = False
        try:
            path = self._perform(vlt)
        except Exception as exc:  # noqa: BLE001 - reported, never fatal on exit
            self._on_error(exc)
        else:
            self._on_done(path)

    def backup_now(self) -> None:
        """Explicit user-triggered backup, regardless of dirty state."""
        self._dirty = True
        self._timer.stop()
        self._run()

    def discard_pending(self) -> None:
        """Drop a queued backup without writing it.

        Used after restoring a different vault over this one: the master
        key in memory belongs to the *old* vault, so writing a backup now
        would seal the new database under a key its header doesn't describe.
        """
        self._dirty = False
        self._timer.stop()

    def ensure_initial(self) -> None:
        """Make sure a backup exists shortly after unlocking."""
        if not self._settings.backup_enabled:
            return
        if not self.destination().exists():
            self.mark_dirty()

    # ------------------------------------------------------------------

    def _perform(self, vlt: "vault.Vault") -> str:
        """Snapshot, rotate, and write the encrypted backup. Blocking."""
        material = vlt.backup_material()
        dest = self.destination()
        backup.rotate(dest, self._settings.backup_keep)
        return str(backup.write_backup(
            vlt.db_path, dest, material["key"],
            mode=material["mode"], kdf_name=material["kdf_name"],
            kdf_params=material["kdf_params"], salt_hex=material["salt_hex"],
        ))

    def _run(self) -> None:
        vlt = self._get_vault()
        if vlt is None or self._running or not self._settings.backup_enabled:
            return
        self._running = True
        self._dirty = False
        workers.run_async(lambda: self._perform(vlt), self._on_done, self._on_error)

    def _on_done(self, path: str) -> None:
        self._running = False
        self._settings.backup_last_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._settings.backup_last_error = ""
        try:
            self._settings.save()
        except OSError:
            pass
        self.completed.emit(path)

    def _on_error(self, exc: Exception) -> None:
        self._running = False
        message = str(exc) or exc.__class__.__name__
        self._settings.backup_last_error = message
        try:
            self._settings.save()
        except OSError:
            pass
        self.failed.emit(message)
