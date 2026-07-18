"""Application controller: wires the window, tray, timers, and lifecycle.

State machine
-------------
* No vault on disk        -> Create screen (window shown)
* Vault exists, locked    -> Unlock screen (or hidden in tray)
* Vault unlocked          -> the app shell

Background behaviour
--------------------
* Closing the window (X) never kills the process by default: it locks the
  vault and either hides to the tray or quits, per the user's choice.
* An idle timer auto-locks after N minutes of no input.
* The tray icon is the always-on home; quitting from it locks first.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QTimer
from PySide6.QtWidgets import QApplication

from nomorepwn import config, vault
from nomorepwn.settings import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings

from . import startup, theme, workers
from .context import AppContext
from .dialogs import CloseChoiceDialog, confirm
from .main_window import MainWindow
from .tray import TrayIcon
from .util import ClipboardManager


_ACTIVITY_EVENTS = {
    QEvent.MouseMove, QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.Wheel,
    QEvent.TouchBegin,
}


class AppController(QObject):
    def __init__(self, app: QApplication):
        super().__init__()
        self.app = app
        self.settings = Settings.load()
        self._theme_name = self.settings.theme
        self.db_path = str(config.DB_PATH)
        self.vault: vault.Vault | None = None
        self._quitting = False
        self._tray_hint_shown = False

        # Theme (palette first — it covers widgets the stylesheet can't reach)
        theme.set_active(theme.get_palette(self.settings.theme))
        app.setPalette(theme.build_palette(theme.active()))
        app.setStyleSheet(theme.build_stylesheet(theme.active()))

        # Core objects
        self.clipboard = ClipboardManager()
        self.window = MainWindow(self.db_path)
        self.ctx = AppContext(
            settings=self.settings,
            toast=self.window.toast,
            clipboard=self.clipboard,
            notify=self._notify,
            mark_activity=self._reset_autolock,
        )
        self.window.set_context(self.ctx)
        self.tray = TrayIcon(self)

        # Auto-lock timer
        self.autolock = QTimer(self)
        self.autolock.setSingleShot(True)
        self.autolock.timeout.connect(self._auto_lock)

        # Signals
        self.window.vault_opened.connect(self._on_vault_opened)
        self.window.lock_requested.connect(lambda: self.lock(manual=True))
        self.window.close_requested.connect(self._on_close_requested)
        self.window.settings_changed.connect(self._on_settings_changed)
        self.tray.show_requested.connect(self.show_window)
        self.tray.lock_requested.connect(lambda: self.lock(manual=True))
        self.tray.quit_requested.connect(self.quit)

        app.installEventFilter(self)

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def start(self, start_hidden: bool = False) -> None:
        self.tray.show()
        self.tray.set_state(locked=True)
        if not vault.vault_exists(self.db_path):
            self.window.show_create()
            self._present_window()
            return
        self.window.show_unlock()
        if start_hidden or self.settings.start_minimized:
            if not self._tray_hint_shown:
                self._notify("NoMorePwn is running",
                             "Locked and waiting in the tray. Click the icon to unlock.")
                self._tray_hint_shown = True
        else:
            self._present_window()

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------

    def _on_vault_opened(self, vlt: "vault.Vault") -> None:
        self.vault = vlt
        self.window.show_shell(vlt)
        self.tray.set_state(locked=False)
        self._present_window()
        self._reset_autolock()
        self._run_integrity_sweep(vlt)

    def _run_integrity_sweep(self, vlt: "vault.Vault") -> None:
        def done(issues):
            if issues:
                self.ctx.toast.show(
                    f"⚠ Tamper check found {len(issues)} issue(s) — your vault file was modified outside the app.",
                    "error", 7000)
                self._notify("Tamper warning",
                             f"{len(issues)} integrity issue(s) detected in your vault.")
        workers.run_async(vlt.verify_integrity, done, lambda e: None)

    def lock(self, manual: bool = False, notify: bool = False) -> None:
        if self.vault is not None:
            self.vault.lock()
            self.vault = None
        self.autolock.stop()
        self.window.teardown_shell()
        if vault.vault_exists(self.db_path):
            self.window.show_unlock()
        self.tray.set_state(locked=True)
        if notify:
            self._notify("Vault locked", "NoMorePwn locked your vault after inactivity.")

    def _auto_lock(self) -> None:
        if self.vault is not None:
            self.lock(notify=True)

    def _reset_autolock(self) -> None:
        if self.vault is None:
            self.autolock.stop()
            return
        ms = self.settings.autolock_ms()
        if ms > 0:
            self.autolock.start(ms)
        else:
            self.autolock.stop()

    # ------------------------------------------------------------------
    # Window presentation
    # ------------------------------------------------------------------

    def show_window(self) -> None:
        if not vault.vault_exists(self.db_path):
            self.window.show_create()
        elif self.vault is None:
            self.window.show_unlock()
        self._present_window()

    def _present_window(self) -> None:
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    # ------------------------------------------------------------------
    # Close (X) handling
    # ------------------------------------------------------------------

    def _on_close_requested(self) -> None:
        if (self.settings.warn_unsaved_on_close and self.window.has_unsaved()):
            if not confirm(self.window, "Discard unsaved changes?",
                           "You're editing an item. Closing now will lose those changes.",
                           confirm_text="Discard & close", danger=True):
                return

        action = self.settings.close_action
        if action == CLOSE_ASK:
            dlg = CloseChoiceDialog(self.window)
            if dlg.exec() != dlg.Accepted or dlg.choice is None:
                return
            action = dlg.choice
            if dlg.remembered():
                self.settings.close_action = action
                self.settings.save()

        # Both paths lock the vault first.
        self.lock()
        if action == CLOSE_QUIT:
            self.quit()
        else:  # CLOSE_TRAY
            self.window.hide()
            if not self._tray_hint_shown:
                self._notify("Still running",
                             "NoMorePwn is locked and running in the tray. "
                             "Click the tray icon to reopen.")
                self._tray_hint_shown = True

    def quit(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        if self.vault is not None:
            self.vault.lock()
            self.vault = None
        self.clipboard._wipe()
        self.tray.hide()
        self.app.quit()

    # ------------------------------------------------------------------
    # Settings changes
    # ------------------------------------------------------------------

    def _on_settings_changed(self) -> None:
        startup.set_launch_at_startup(self.settings.launch_at_startup)
        self._reset_autolock()
        if self.settings.theme != self._theme_name:
            self._apply_theme()

    def _apply_theme(self) -> None:
        """Switch palettes without leaving stale colours behind.

        Many widgets bake palette colours into inline stylesheets when
        they're built, so a stylesheet swap alone leaves light surfaces
        stranded in dark mode. We clear and reapply the global sheet (to
        force a full re-polish) and rebuild every cached screen.
        """
        self._theme_name = self.settings.theme
        theme.set_active(theme.get_palette(self.settings.theme))
        self.app.setPalette(theme.build_palette(theme.active()))
        self.app.setStyleSheet("")  # force Qt to drop the old sheet entirely
        self.app.setStyleSheet(theme.build_stylesheet(theme.active()))

        self.window.reset_cached_views()
        if self.vault is not None:
            # Rebuild the unlocked shell and return to the Settings page.
            self.window.show_shell(self.vault)
            self.window._shell.goto_page(3)
        elif vault.vault_exists(self.db_path):
            self.window.show_unlock()
        else:
            self.window.show_create()

    # ------------------------------------------------------------------

    def _notify(self, title: str, message: str) -> None:
        if self.settings.show_notifications:
            self.tray.notify(title, message)

    def eventFilter(self, obj, event) -> bool:
        if event.type() in _ACTIVITY_EVENTS and self.vault is not None:
            self._reset_autolock()
        return super().eventFilter(obj, event)
