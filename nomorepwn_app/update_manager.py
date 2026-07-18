"""Background update checks, and handing the installer to Windows.

Policy (chosen deliberately, do not loosen without saying so in the UI):

  check -> download -> verify -> **ask** -> lock the vault -> run installer

The app never installs on its own. It is a password manager updating itself
from an *unsigned* executable, so a human confirms before anything runs. The
download and verification happen in the background because that part is safe;
the execution is what needs consent.

Two ordering rules that are not negotiable:

1. **The vault is locked before the installer launches.** The installer
   replaces the running .exe and restarts it. An unlocked vault across that
   boundary means the master key is in the RAM of a process being torn down
   while an installer writes to disk.
2. **The installer runs detached, then we quit.** Inno cannot overwrite a
   running executable. We start it with a short wait, then exit so the file is
   unlocked by the time it is replaced.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from nomorepwn import config, updater

from . import GITHUB_OWNER, GITHUB_REPO, __version__, is_packaged_build
from . import workers

# How long after launch before the first check, so startup stays snappy.
STARTUP_DELAY_MS = 20_000

# Re-check roughly daily for a long-running tray session.
RECHECK_INTERVAL_MS = 24 * 60 * 60 * 1000


def download_dir() -> Path:
    return Path(config.DATA_DIR) / "updates"


class UpdateManager(QObject):
    """Checks for updates and prepares them; never installs unprompted."""

    #: A verified installer is ready. (release, path_to_installer)
    update_ready = Signal(object, object)
    #: A check or download failed. (message)
    failed = Signal(str)
    #: Progress while downloading. (bytes_done, bytes_total)
    progress = Signal(int, int)
    #: No update available — only emitted for user-initiated checks.
    up_to_date = Signal()

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self._busy = False
        self._ready: tuple[object, Path] | None = None

        self._timer = QTimer(self)
        self._timer.setInterval(RECHECK_INTERVAL_MS)
        self._timer.timeout.connect(lambda: self.check(user_initiated=False))

    # -- lifecycle ------------------------------------------------------

    def start(self) -> None:
        """Begin periodic checks, if enabled and this is a real install."""
        if not self._settings.updates_enabled or not is_packaged_build():
            return
        QTimer.singleShot(STARTUP_DELAY_MS, lambda: self.check(user_initiated=False))
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    @property
    def ready(self) -> tuple[object, Path] | None:
        return self._ready

    # -- checking -------------------------------------------------------

    def check(self, user_initiated: bool = True) -> None:
        """Look for a newer stable release; download and verify it if found."""
        if self._busy:
            return
        if not user_initiated and not self._settings.updates_enabled:
            return

        # A source checkout has no version to compare and no installer to
        # replace — updating it would leave two copies side by side.
        if not is_packaged_build():
            if user_initiated:
                self.failed.emit(
                    "This is a development build; updates apply to installed copies only.")
            return

        self._busy = True

        def work():
            release = updater.check(GITHUB_OWNER, GITHUB_REPO, __version__)
            if release is None:
                return None
            if (not user_initiated
                    and release.version == self._settings.update_skipped_version):
                return None
            path = updater.download(
                release, download_dir(),
                on_progress=lambda done, total: self.progress.emit(done, total))
            return release, path

        def done(result):
            self._busy = False
            self._settings.update_last_check = datetime.now(timezone.utc).isoformat()
            self._settings.save()
            if result is None:
                if user_initiated:
                    self.up_to_date.emit()
                return
            release, path = result
            self._ready = (release, path)
            self.update_ready.emit(release, path)

        def err(exc):
            self._busy = False
            # A failed check is not evidence of being up to date — say so
            # rather than silently implying everything is current.
            if user_initiated:
                self.failed.emit(str(exc))

        workers.run_async(work, done, err)

    def skip(self, version: str) -> None:
        self._settings.update_skipped_version = version
        self._settings.save()
        self._ready = None

    # -- applying -------------------------------------------------------

    def apply(self, installer: Path, lock_vault) -> bool:
        """Lock the vault, launch the installer detached, and signal quit.

        `lock_vault` is called first and must fully lock. Returns True if the
        installer started, in which case the caller must quit the app
        immediately — Inno cannot replace a running executable.
        """
        installer = Path(installer)
        if not installer.exists():
            return False

        # Order matters: never hand the machine to an installer that will
        # restart us while the master key is still in memory.
        lock_vault()

        try:
            # /SILENT shows a progress bar but asks nothing. The AppId in
            # installer.iss matches, so this upgrades in place and leaves
            # %APPDATA%\NoMorePwn (vault + backups) untouched.
            subprocess.Popen(
                [str(installer), "/SILENT", "/NOCANCEL", "/NORESTART",
                 f'/LOG={installer.parent / "install.log"}'],
                creationflags=(
                    subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                    if sys.platform == "win32" else 0),
                close_fds=True,
            )
        except OSError:
            return False
        return True

    def cleanup_old_downloads(self, keep: Path | None = None) -> None:
        """Remove previously downloaded installers.

        Downloaded installers are executables sitting in the data directory;
        do not leave a pile of them around after an update lands.
        """
        directory = download_dir()
        if not directory.exists():
            return
        for path in directory.glob("*.exe"):
            if keep is not None and path == Path(keep):
                continue
            try:
                path.unlink()
            except OSError:
                pass
