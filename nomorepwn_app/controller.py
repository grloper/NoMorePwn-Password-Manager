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
from PySide6.QtWidgets import QApplication, QDialog

from nomorepwn import config, vault
from nomorepwn.settings import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings

from . import browser_bridge, startup, theme, workers
from .backup_manager import BackupManager
from .update_manager import UpdateManager
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
        self._pending_captures: list[dict] = []

        # Theme (palette first — it covers widgets the stylesheet can't reach)
        theme.set_active(theme.get_palette(self.settings.theme))
        app.setPalette(theme.build_palette(theme.active()))
        app.setStyleSheet(theme.build_stylesheet(theme.active()))

        # Core objects
        self.clipboard = ClipboardManager()
        self.window = MainWindow(self.db_path)
        self.backups = BackupManager(self.settings, lambda: self.vault, self)
        self.updates = UpdateManager(self.settings, self)
        self.ctx = AppContext(
            settings=self.settings,
            toast=self.window.toast,
            clipboard=self.clipboard,
            notify=self._notify,
            mark_activity=self._reset_autolock,
            request_backup=self.backups.mark_dirty,
            backup_now=self.backups.backup_now,
            open_restore=self.open_restore,
            get_vault=lambda: self.vault,
            updates=self.updates,
            apply_update=self.apply_update,
        )
        self.window.set_context(self.ctx)
        self.tray = TrayIcon(self)

        # Auto-lock timer
        self.autolock = QTimer(self)
        self.autolock.setSingleShot(True)
        self.autolock.timeout.connect(self._auto_lock)

        # Signals
        self.window.vault_opened.connect(self._on_vault_opened)
        self.window.vault_created.connect(self._on_vault_created)
        self.window.lock_requested.connect(lambda: self.lock(manual=True))
        self.window.close_requested.connect(self._on_close_requested)
        self.window.settings_changed.connect(self._on_settings_changed)
        self.tray.show_requested.connect(self.show_window)
        self.tray.lock_requested.connect(lambda: self.lock(manual=True))
        self.tray.quit_requested.connect(self.quit)
        self.backups.failed.connect(
            lambda msg: self.ctx.toast.show(f"Backup failed: {msg}", "error", 5000))
        self.updates.update_ready.connect(self._on_update_ready)
        self.updates.start()

        # Unpack the bundled browser extension to its stable directory. Cheap
        # and version-stamped, so it is a no-op after the first launch on a
        # given build — but it means the folder always exists when the user
        # goes looking for it, and it refreshes itself after an update.
        browser_bridge.ensure_extension_files()

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
        self.backups.ensure_initial()
        
        # Flush pending captures
        if self._pending_captures:
            for msg in self._pending_captures:
                # Re-invoke the IPC handler for each pending message
                import json
                self.handle_ipc_message(json.dumps(msg).encode("utf-8"))
            self._pending_captures.clear()

    def _on_vault_created(self, vlt: "vault.Vault") -> None:
        """A vault was just created (first run). Offer to set up recovery so a
        forgotten master password isn't fatal — the shell is already showing."""
        from .recovery_dialog import offer_recovery_setup
        offer_recovery_setup(self.window, self.ctx)

    def _run_integrity_sweep(self, vlt: "vault.Vault") -> None:
        def done(issues):
            if issues:
                self.ctx.toast.show(
                    f"⚠ Tamper check found {len(issues)} issue(s) — your vault file was modified outside the app.",
                    "error", 7000)
                self._notify("Tamper warning",
                             f"{len(issues)} integrity issue(s) detected in your vault.")
        workers.run_async(vlt.verify_integrity, done, lambda e: None)

    def lock(self, manual: bool = False, notify: bool = False, flush: bool = True) -> None:
        # Flush first: locking drops the master key, and a pending backup
        # can't be written without it.
        if flush:
            self.backups.flush_sync()
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

    def handle_ipc_message(self, data: bytes) -> bytes | None:
        if data == b"show":
            self.show_window()
            return b"ok"
        try:
            import json
            msg = json.loads(data.decode("utf-8"))
            if msg.get("type") == "save-credential":
                from nomorepwn.settings import CAPTURE_SILENT, CAPTURE_PROMPT, CAPTURE_DISABLED
                
                if self.settings.capture_action == CAPTURE_DISABLED:
                    return json.dumps({"type": "ok"}).encode("utf-8")
                    
                if self.vault is None:
                    # Queue the capture and ask user to unlock
                    self._pending_captures.append(msg)
                    self.window.show_unlock()
                    self._present_window()
                    return json.dumps({"type": "ok"}).encode("utf-8")
                
                target_url = msg.get("targetUrl", "")
                username = msg.get("username", "")
                password = msg.get("password", "")
                
                if self.settings.capture_action == CAPTURE_PROMPT:
                    if self.window.has_unsaved():
                        return json.dumps({"type": "error", "code": "editor-busy", "message": "Please finish or discard your current edits first."}).encode("utf-8")
                    
                    self.show_window()
                    if self.window._shell:
                        self.window._shell.goto_page(0) # Items
                        self.window._shell.vault_view._add()
                        
                        editor = self.window._shell.vault_view.editor
                        editor.service.setText(target_url)
                        editor.username.setText(username)
                        editor.password.setText(password)
                        editor.group.setText("Captured Logins")
                        editor._update_strength()
                        editor._suggest_group_for_service()
                        
                    return json.dumps({"type": "ok"}).encode("utf-8")
                
                # CAPTURE_SILENT behavior
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(target_url)
                    service_name = parsed.netloc or target_url
                except Exception:
                    service_name = target_url

                self.vault.add_credential(
                    service_name=service_name,
                    username=username,
                    password=password,
                    group_name="Captured Logins",
                    notes=f"Captured from {target_url}"
                )
                self.vault.save()
                
                from PySide6.QtWidgets import QSystemTrayIcon
                self.tray.tray.showMessage(
                    "Credential Captured", 
                    f"Saved {username} for {service_name} to Captured Logins.", 
                    QSystemTrayIcon.Information, 
                    5000
                )
                
                if self.window._shell and hasattr(self.window._shell, "vault_view"):
                    self.window._shell.vault_view.refresh()
                    
                return json.dumps({"type": "ok"}).encode("utf-8")
        except Exception as e:
            import json
            return json.dumps({"type": "error", "code": "ipc-error", "message": str(e)}).encode("utf-8")
        return None

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
            # QDialog.DialogCode.Accepted, never `dlg.Accepted`: PySide6 does
            # not expose the enum on the *instance* (6.11 raises AttributeError),
            # and an exception here is swallowed by the slot — so the X button
            # silently did nothing at all, for both choices.
            if dlg.exec() != QDialog.DialogCode.Accepted or dlg.choice is None:
                return
            action = dlg.choice
            if dlg.remembered():
                self.settings.close_action = action
                self.settings.save()

        if action == CLOSE_QUIT:
            # quit() locks, hides, and exits — going through lock() first
            # would rebuild the unlock screen and leave it on screen while
            # the process tears down.
            self.quit()
        else:  # CLOSE_TRAY
            self.lock()
            self.window.hide()
            if not self._tray_hint_shown:
                self._notify("Still running",
                             "NoMorePwn is locked and running in the tray. "
                             "Click the tray icon to reopen.")
                self._tray_hint_shown = True

    def quit(self) -> None:
        """Lock, tear the UI down, and exit.

        The window and tray icon are hidden *before* the event loop stops
        so the app visually disappears the instant you choose Quit, rather
        than lingering on screen while the process tears down.
        """
        if self._quitting:
            return
        self._quitting = True
        self.autolock.stop()
        self.backups.flush_sync()      # write any pending backup while we still hold the key
        if self.vault is not None:
            self.vault.lock()
            self.vault = None
        self.clipboard._wipe()
        self.window.teardown_shell()
        self.window.hide()
        self.tray.hide()
        self.app.quit()

    # ------------------------------------------------------------------
    # Updates
    # ------------------------------------------------------------------

    def _on_update_ready(self, release, installer) -> None:
        """A verified installer is waiting. Tell the user; never auto-install."""
        self._notify(
            f"NoMorePwn {release.version} is ready",
            "Open Settings → Updates to install it.")
        self.ctx.toast.show(
            f"Update {release.version} downloaded — install it from Settings.",
            "info", 6000)

    def apply_update(self, installer) -> None:
        """Lock, flush, launch the installer, and quit.

        Ordering is the security-relevant part and mirrors `quit()`:
        flush the backup *while we still hold the key*, then lock, then hand
        off. The installer replaces this executable and restarts it, so the
        master key must be gone before it runs, and the process must exit or
        Inno cannot overwrite the file it is running from.
        """
        if self._quitting:
            return

        def lock_everything() -> None:
            self.autolock.stop()
            self.backups.flush_sync()
            if self.vault is not None:
                self.vault.lock()
                self.vault = None
            self.clipboard._wipe()

        if not self.updates.apply(installer, lock_everything):
            self.ctx.toast.show("Could not start the installer.", "error", 5000)
            return

        # The vault is already locked; go straight to teardown rather than
        # through quit(), which would try to flush a backup without a key.
        self._quitting = True
        self.window.teardown_shell()
        self.window.hide()
        self.tray.hide()
        self.app.quit()

    # ------------------------------------------------------------------
    # Backup / restore
    # ------------------------------------------------------------------

    def open_restore(self) -> None:
        from PySide6.QtWidgets import QDialog

        from .restore_dialog import RestoreDialog

        dlg = RestoreDialog(self.window, self.db_path, lambda: self.vault, self.ctx)
        if dlg.exec() != QDialog.Accepted:
            return
        if dlg.outcome == "replaced":
            # The database on disk is a different vault now, so the key we
            # hold no longer describes it: drop any queued backup and force
            # a fresh unlock rather than flushing stale key material.
            self.backups.discard_pending()
            self.lock(flush=False)
            self.ctx.toast.show(dlg.summary, "success", 7000)
        else:
            if self.window._shell is not None:
                self.window._shell.set_vault(self.vault)
            self.ctx.toast.show(dlg.summary, "success", 5000)

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
