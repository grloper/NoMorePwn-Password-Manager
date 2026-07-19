"""Settings page: security, startup, appearance, and about."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QScrollArea,
    QVBoxLayout, QWidget,
)

from nomorepwn import config, vault
from nomorepwn.settings import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings

from . import __version__, browser_bridge, components, is_packaged_build, theme
from .components import Card
from .context import AppContext
from .dialogs import ask_new_passphrase, confirm


class _Setting(QWidget):
    """One labelled setting row: title + description on the left, control right."""

    def __init__(self, title: str, description: str, control: QWidget):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 6)
        lay.setSpacing(16)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet(f"color:{theme.active().text}; font-weight:600;")
        col.addWidget(t)
        d = QLabel(description)
        d.setObjectName("Faint")
        d.setWordWrap(True)
        col.addWidget(d)
        lay.addLayout(col, 1)
        lay.addWidget(control, 0, Qt.AlignRight | Qt.AlignVCenter)


class SettingsView(QWidget):
    def __init__(self, ctx: AppContext, on_change: Callable[[], None], parent=None):
        super().__init__(parent)
        self._ctx = ctx
        self._settings = ctx.settings
        self._on_change = on_change
        self._loading = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 26, 28, 26)
        lay.setSpacing(18)
        scroll.setWidget(body)
        root.addWidget(scroll)

        lay.addWidget(components.heading("Settings", "H1"))

        # -- Security --------------------------------------------------
        sec = Card()
        sec.add(components.heading("Security", "H3"))
        self.autolock = QComboBox()
        for label, val in [("After 1 minute", 1), ("After 5 minutes", 5),
                           ("After 15 minutes", 15), ("After 30 minutes", 30), ("Never", 0)]:
            self.autolock.addItem(label, val)
        sec.add(_Setting("Auto-lock", "Lock the vault after this much inactivity.", self.autolock))

        self.lock_min = QCheckBox()
        sec.add(_Setting("Lock when hidden to tray",
                         "Always lock the vault the moment the window is hidden.", self.lock_min))

        self.clip = QComboBox()
        for label, val in [("After 10 seconds", 10), ("After 20 seconds", 20),
                           ("After 30 seconds", 30), ("After 60 seconds", 60), ("Never", 0)]:
            self.clip.addItem(label, val)
        sec.add(_Setting("Clear clipboard", "Wipe copied passwords from the clipboard automatically.", self.clip))
        lay.addWidget(sec)

        # -- On close --------------------------------------------------
        close_card = Card()
        close_card.add(components.heading("When I press the X button", "H3"))
        self.close_action = QComboBox()
        self.close_action.addItem("Ask me every time", CLOSE_ASK)
        self.close_action.addItem("Lock & keep running in tray", CLOSE_TRAY)
        self.close_action.addItem("Lock & quit completely", CLOSE_QUIT)
        close_card.add(_Setting("Close behaviour",
                                "The vault is always locked first, either way.", self.close_action))
        self.warn_unsaved = QCheckBox()
        close_card.add(_Setting("Warn about unsaved changes",
                                "Ask before closing while you're editing an item.", self.warn_unsaved))
        lay.addWidget(close_card)

        # -- Startup ---------------------------------------------------
        start_card = Card()
        start_card.add(components.heading("Startup", "H3"))
        self.launch = QCheckBox()
        start_card.add(_Setting("Launch at Windows startup",
                                "Start NoMorePwn (locked, in the tray) when you sign in.", self.launch))
        self.start_min = QCheckBox()
        start_card.add(_Setting("Start minimised to tray",
                                "Open straight to the tray instead of showing the window.", self.start_min))
        lay.addWidget(start_card)

        # -- Backups ---------------------------------------------------
        backup_card = Card()
        backup_card.add(components.heading("Encrypted backups", "H3"))
        backup_card.add(components.muted(
            "A sealed copy of your vault is refreshed automatically after every "
            "change. The file is useless to anyone without your password — so it's "
            "safe to point this at Dropbox, OneDrive, or a USB stick."))

        self.backup_enabled = QCheckBox()
        backup_card.add(_Setting("Back up automatically",
                                 "Refresh the encrypted backup whenever the vault changes.",
                                 self.backup_enabled))

        self.backup_keep = QComboBox()
        for label, val in [("Keep 3", 3), ("Keep 5", 5), ("Keep 10", 10)]:
            self.backup_keep.addItem(label, val)
        backup_card.add(_Setting("Generations kept",
                                 "Older copies are retained as .1, .2 … in case the newest is lost.",
                                 self.backup_keep))

        loc_btn = components.button("Change…", "external")
        loc_btn.clicked.connect(self._pick_backup_dir)
        backup_card.add(_Setting("Location", "Where backup files are written.", loc_btn))
        self.backup_path = QLabel("")
        self.backup_path.setObjectName("Faint")
        self.backup_path.setWordWrap(True)
        self.backup_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        backup_card.add(self.backup_path)

        self.pass_btn = components.button("Use a separate passphrase…", "key")
        self.pass_btn.clicked.connect(self._set_backup_passphrase)
        backup_card.add(_Setting(
            "Protection",
            "By default backups open with your master password. You can require a "
            "different passphrase instead.",
            self.pass_btn))
        self.protection_lbl = QLabel("")
        self.protection_lbl.setObjectName("Faint")
        self.protection_lbl.setWordWrap(True)
        backup_card.add(self.protection_lbl)

        self.backup_status = QLabel("")
        self.backup_status.setObjectName("Faint")
        self.backup_status.setWordWrap(True)
        backup_card.add(self.backup_status)

        actions = QHBoxLayout()
        now_btn = components.button("Back up now", "download")
        now_btn.clicked.connect(self._backup_now)
        restore_btn = components.button("Restore or import…", "history")
        restore_btn.clicked.connect(lambda: self._ctx.open_restore())
        actions.addWidget(now_btn)
        actions.addWidget(restore_btn)
        actions.addStretch(1)
        backup_card.body.addLayout(actions)
        lay.addWidget(backup_card)

        # -- Recovery kit ----------------------------------------------
        rec_card = Card()
        rec_card.add(components.heading("Recovery kit", "H3"))
        rec_card.add(components.muted(
            "Forget your master password and there is no reset — unless you make a "
            "recovery kit first. It escrows your key into a file you store yourself; "
            "nothing about it is written into your vault or backups. The optional "
            "authenticator mode also requires a seed, so the kit file alone opens "
            "nothing. Keep the kit as safe as your password."))
        self.recovery_btn = components.button("Create recovery kit…", "key")
        self.recovery_btn.clicked.connect(self._create_recovery_kit)
        rec_card.add(_Setting(
            "Recovery kit",
            "Make one now so a forgotten password is recoverable later.",
            self.recovery_btn))
        lay.addWidget(rec_card)

        # -- Updates ---------------------------------------------------
        upd_card = Card()
        upd_card.add(components.heading("Updates", "H3"))
        upd_card.add(components.muted(
            "NoMorePwn checks GitHub for new stable releases, downloads them in "
            "the background, and verifies the download before asking you to "
            "install. It never installs on its own, and your vault is locked "
            "first. Your vault and backups are untouched by an update."))

        self.updates_enabled = QCheckBox()
        upd_card.add(_Setting("Check for updates automatically",
                              "On launch and once a day while running.",
                              self.updates_enabled))

        self.update_status = QLabel("")
        self.update_status.setWordWrap(True)
        upd_card.add(self.update_status)

        upd_actions = QHBoxLayout()
        self.update_check_btn = components.button("Check now", "refresh")
        self.update_check_btn.clicked.connect(self._check_updates)
        self.update_install_btn = components.button("Restart & update", "download")
        self.update_install_btn.clicked.connect(self._install_update)
        self.update_install_btn.setVisible(False)
        upd_actions.addWidget(self.update_check_btn)
        upd_actions.addWidget(self.update_install_btn)
        upd_actions.addStretch(1)
        upd_card.body.addLayout(upd_actions)
        lay.addWidget(upd_card)

        # -- Browser extension -----------------------------------------
        ext_card = Card()
        ext_card.add(components.heading("Browser extension", "H3"))
        ext_card.add(components.muted(
            "Save logins straight from your browser. The extension only offers to "
            "save a password once it has confirmed the login actually worked, so "
            "you don't end up storing the typo you just fixed. It talks to this app "
            "directly on your machine — nothing is sent anywhere."))

        self.ext_status = QLabel("")
        self.ext_status.setWordWrap(True)
        ext_card.add(self.ext_status)
        
        from nomorepwn.settings import CAPTURE_SILENT, CAPTURE_PROMPT, CAPTURE_DISABLED
        self.capture_action = QComboBox()
        self.capture_action.addItem("Save silently to Captured Logins", CAPTURE_SILENT)
        self.capture_action.addItem("Prompt me to review in the app", CAPTURE_PROMPT)
        self.capture_action.addItem("Ignore completely", CAPTURE_DISABLED)
        ext_card.add(_Setting(
            "When a login is captured",
            "How NoMorePwn handles credentials sent from your browser.",
            self.capture_action))

        self.ext_setup_btn = components.button("Set up browser extension…", "globe")
        self.ext_setup_btn.clicked.connect(self._setup_extension)
        ext_card.add(_Setting(
            "Connection",
            "Registers NoMorePwn with Chrome, Edge, and Brave so the extension can reach it.",
            self.ext_setup_btn))

        self.ext_steps = QLabel("")
        self.ext_steps.setObjectName("Faint")
        self.ext_steps.setWordWrap(True)
        self.ext_steps.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ext_card.add(self.ext_steps)

        ext_actions = QHBoxLayout()
        self.ext_folder_btn = components.button("Open extension folder", "external")
        self.ext_folder_btn.clicked.connect(self._open_extension_folder)
        self.ext_copy_btn = components.button("Copy folder path", "copy")
        self.ext_copy_btn.clicked.connect(self._copy_extension_path)
        self.ext_remove_btn = components.button("Disconnect", "x")
        self.ext_remove_btn.clicked.connect(self._remove_extension)
        ext_actions.addWidget(self.ext_folder_btn)
        ext_actions.addWidget(self.ext_copy_btn)
        ext_actions.addWidget(self.ext_remove_btn)
        ext_actions.addStretch(1)
        ext_card.body.addLayout(ext_actions)
        lay.addWidget(ext_card)

        # -- Appearance ------------------------------------------------
        appear = Card()
        appear.add(components.heading("Appearance", "H3"))
        self.theme_sel = QComboBox()
        self.theme_sel.addItem("Dark", "dark")
        self.theme_sel.addItem("Light", "light")
        appear.add(_Setting("Theme", "Switch between the dark and light look.", self.theme_sel))
        lay.addWidget(appear)

        # -- About -----------------------------------------------------
        about = Card()
        about.add(components.heading("About", "H3"))
        about.add(components.muted(f"NoMorePwn {__version__}"))
        about.add(components.muted(
            "Local-first, zero-knowledge password manager. Your master password "
            "never leaves this device; secrets are sealed with AES-256-GCM."))
        loc = QLabel(f"Vault location: {config.DATA_DIR}")
        loc.setObjectName("Faint")
        loc.setWordWrap(True)
        loc.setTextInteractionFlags(Qt.TextSelectableByMouse)
        about.add(loc)
        lay.addWidget(about)
        lay.addStretch(1)

        self._load()
        # Wire after loading so we don't fire on programmatic set.
        self.autolock.currentIndexChanged.connect(self._save)
        self.lock_min.toggled.connect(self._save)
        self.clip.currentIndexChanged.connect(self._save)
        self.close_action.currentIndexChanged.connect(self._save)
        self.warn_unsaved.toggled.connect(self._save)
        self.launch.toggled.connect(self._save)
        self.start_min.toggled.connect(self._save)
        self.theme_sel.currentIndexChanged.connect(self._save)
        self.backup_enabled.toggled.connect(self._save)
        self.backup_keep.currentIndexChanged.connect(self._save)
        self.updates_enabled.toggled.connect(self._save)
        self.capture_action.currentIndexChanged.connect(self._save)

    def _load(self) -> None:
        self._loading = True
        s = self._settings
        self.autolock.setCurrentIndex(max(0, self.autolock.findData(s.autolock_minutes)))
        self.lock_min.setChecked(s.lock_on_minimize)
        self.clip.setCurrentIndex(max(0, self.clip.findData(s.clipboard_clear_seconds)))
        self.close_action.setCurrentIndex(max(0, self.close_action.findData(s.close_action)))
        self.warn_unsaved.setChecked(s.warn_unsaved_on_close)
        self.launch.setChecked(s.launch_at_startup)
        self.start_min.setChecked(s.start_minimized)
        self.theme_sel.setCurrentIndex(max(0, self.theme_sel.findData(s.theme)))
        self.backup_enabled.setChecked(s.backup_enabled)
        self.backup_keep.setCurrentIndex(max(0, self.backup_keep.findData(s.backup_keep)))
        self.updates_enabled.setChecked(s.updates_enabled)
        self.capture_action.setCurrentIndex(max(0, self.capture_action.findData(s.capture_action)))
        self._loading = False
        self._refresh_backup_info()
        self._refresh_extension_info()
        self._refresh_update_info()

    # -- backups --------------------------------------------------------

    def _refresh_backup_info(self) -> None:
        s = self._settings
        p = theme.active()
        self.backup_path.setText(str(s.backup_directory()))

        vlt = self._ctx.get_vault()
        has_phrase = False
        try:
            has_phrase = bool(vlt and vlt.has_backup_passphrase())
        except Exception:
            pass
        if has_phrase:
            self.protection_lbl.setText("Backups require your separate backup passphrase.")
            self.pass_btn.setText("Change or remove…")
        else:
            self.protection_lbl.setText("Backups open with your master password.")
            self.pass_btn.setText("Use a separate passphrase…")

        if s.backup_last_error:
            self.backup_status.setText(f"⚠  Last backup failed: {s.backup_last_error}")
            self.backup_status.setStyleSheet(f"color:{p.danger};")
        elif s.backup_last_at:
            when = s.backup_last_at.replace("T", " ").replace("+00:00", " UTC")
            self.backup_status.setText(f"✓  Last backup: {when}")
            self.backup_status.setStyleSheet(f"color:{p.success};")
        else:
            self.backup_status.setText("No backup written yet.")
            self.backup_status.setStyleSheet(f"color:{p.text_muted};")

    def _pick_backup_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose a backup folder", str(self._settings.backup_directory()))
        if chosen:
            self._settings.backup_dir = chosen
            self._settings.save()
            self._refresh_backup_info()
            self._ctx.toast.show("Backup location updated", "success")
            self._ctx.backup_now()

    def _backup_now(self) -> None:
        if self._ctx.get_vault() is None:
            self._ctx.toast.show("Unlock the vault first.", "error")
            return
        self._ctx.backup_now()
        self._ctx.toast.show("Backing up…", "info")
        # The write is async; refresh the status shortly after.
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1200, self._refresh_backup_info)

    def _set_backup_passphrase(self) -> None:
        vlt = self._ctx.get_vault()
        if vlt is None:
            self._ctx.toast.show("Unlock the vault first.", "error")
            return
        if vlt.has_backup_passphrase():
            if confirm(self, "Go back to your master password?",
                       "New backups will be protected by your master password again. "
                       "Backups already written with the passphrase still need it.",
                       confirm_text="Remove passphrase", danger=True):
                vlt.clear_backup_passphrase()
                self._ctx.toast.show("Backup passphrase removed", "success")
                self._refresh_backup_info()
                self._ctx.backup_now()
            return
        phrase = ask_new_passphrase(
            self, "Backup passphrase",
            "Backups will be sealed with this instead of your master password. "
            "Useful if you store them somewhere you'd rather not tie to your master password.")
        if not phrase:
            return
        try:
            vlt.set_backup_passphrase(phrase)
        except vault.VaultError as exc:
            self._ctx.toast.show(str(exc), "error")
            return
        self._ctx.toast.show("Backup passphrase set", "success")
        self._refresh_backup_info()
        self._ctx.backup_now()

    # -- updates ----------------------------------------------------------

    def _update_manager(self):
        return getattr(self._ctx, "updates", None)

    def _refresh_update_info(self, message: str = "", kind: str = "") -> None:
        p = theme.active()
        colour = {"error": p.danger, "success": p.success}.get(kind, p.text_muted)
        weight = "600" if kind else "400"

        mgr = self._update_manager()
        ready = mgr.ready if mgr else None
        self.update_install_btn.setVisible(bool(ready))

        if message:
            text = message
        elif ready:
            text = f"Version {ready[0].version} is downloaded and verified."
            colour, weight = p.success, "600"
        elif not is_packaged_build():
            text = (f"Running {__version__} from source — updates apply to "
                    "installed copies only.")
            self.update_check_btn.setEnabled(False)
        else:
            when = self._settings.update_last_check
            text = f"You're on {__version__}."
            if when:
                text += f" Last checked {when.replace('T', ' ')[:16]}."

        self.update_status.setText(text)
        self.update_status.setStyleSheet(f"color:{colour}; font-weight:{weight};")

    def _check_updates(self) -> None:
        mgr = self._update_manager()
        if mgr is None:
            self._refresh_update_info("Update checks are unavailable.", "error")
            return
        self._refresh_update_info("Checking…")
        mgr.check(user_initiated=True)

    def _install_update(self) -> None:
        mgr = self._update_manager()
        if mgr is None or not mgr.ready:
            return
        release, installer = mgr.ready
        if not confirm(
                self, f"Update to {release.version}?",
                "NoMorePwn will lock your vault, close, and install the update. "
                "Your vault and backups are not affected.",
                confirm_text="Restart & update"):
            return
        self._ctx.apply_update(installer)

    # -- recovery kit ---------------------------------------------------

    def _create_recovery_kit(self) -> None:
        if self._ctx.get_vault() is None:
            self._ctx.toast.show("Unlock the vault first.", "error")
            return
        from .recovery_dialog import RecoveryKitDialog
        RecoveryKitDialog(self, self._ctx.get_vault, self._ctx).exec()

    # -- browser extension ----------------------------------------------

    def _refresh_extension_info(self) -> None:
        p = theme.active()
        st = browser_bridge.status()

        if not st.supported:
            self.ext_status.setText(st.detail)
            self.ext_status.setStyleSheet(f"color:{p.text_muted};")
            for b in (self.ext_setup_btn, self.ext_folder_btn,
                      self.ext_copy_btn, self.ext_remove_btn):
                b.setEnabled(False)
            self.ext_steps.setText("")
            return

        missing = not st.extension_dir.exists()
        self.ext_setup_btn.setEnabled(not missing)
        self.ext_folder_btn.setEnabled(not missing)
        self.ext_copy_btn.setEnabled(not missing)
        self.ext_remove_btn.setEnabled(st.is_registered)

        if missing:
            self.ext_status.setText(f"⚠  {st.detail}")
            self.ext_status.setStyleSheet(f"color:{p.danger};")
        elif st.is_registered:
            self.ext_status.setText(f"✓  Connected to {', '.join(st.registered)}")
            self.ext_status.setStyleSheet(f"color:{p.success}; font-weight:600;")
            self.ext_setup_btn.setText("Re-run setup")
        else:
            self.ext_status.setText("Not set up yet.")
            self.ext_status.setStyleSheet(f"color:{p.text_muted};")
            self.ext_setup_btn.setText("Set up browser extension…")

        # Loading unpacked is a browser-side action we can't perform for the
        # user, so spell it out rather than leaving them guessing.
        self.ext_steps.setText(
            "Then, in your browser: open chrome://extensions, turn on "
            "Developer mode, click “Load unpacked”, and choose:\n"
            f"{st.extension_dir}")

    def _setup_extension(self) -> None:
        done = browser_bridge.register()
        self._refresh_extension_info()
        if done:
            self._ctx.toast.show(f"Registered with {', '.join(done)}", "success", 3200)
        else:
            self._ctx.toast.show(
                "Couldn't register the bridge — no supported browser found.", "error", 4000)

    def _remove_extension(self) -> None:
        if not confirm(self, "Disconnect the browser extension?",
                       "The extension will no longer be able to reach your vault. "
                       "It stays installed in your browser until you remove it there.",
                       confirm_text="Disconnect", danger=True):
            return
        browser_bridge.unregister()
        self._refresh_extension_info()
        self._ctx.toast.show("Browser extension disconnected", "success")

    def _open_extension_folder(self) -> None:
        path = browser_bridge.extension_dir()
        if not path.exists():
            self._ctx.toast.show("Extension folder is missing.", "error")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _copy_extension_path(self) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(str(browser_bridge.extension_dir()))
        self._ctx.toast.show("Folder path copied", "success")

    def _save(self) -> None:
        if self._loading:
            return
        s = self._settings
        s.autolock_minutes = self.autolock.currentData()
        s.lock_on_minimize = self.lock_min.isChecked()
        s.clipboard_clear_seconds = self.clip.currentData()
        s.close_action = self.close_action.currentData()
        s.warn_unsaved_on_close = self.warn_unsaved.isChecked()
        s.launch_at_startup = self.launch.isChecked()
        s.start_minimized = self.start_min.isChecked()
        s.theme = self.theme_sel.currentData()
        s.backup_enabled = self.backup_enabled.isChecked()
        s.backup_keep = self.backup_keep.currentData()
        s.updates_enabled = self.updates_enabled.isChecked()
        s.capture_action = self.capture_action.currentData()
        s.save()
        self._on_change()
