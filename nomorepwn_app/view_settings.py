"""Settings page.

A category sidebar on the left switches between focused panels on the right —
Security, General, Backups, Recovery, Browser extension, Updates, About — so
each screen shows only the handful of controls it owns instead of one long,
undifferentiated scroll.
"""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QSize, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QScrollArea, QStackedWidget, QVBoxLayout,
    QWidget,
)

from nomorepwn import config, vault
from nomorepwn.settings import (
    CAPTURE_DISABLED, CAPTURE_PROMPT, CAPTURE_SILENT,
    CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY,
)

from . import __version__, browser_bridge, components, icons, is_packaged_build, theme
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

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- Category rail ---------------------------------------------
        self.nav = QListWidget()
        self.nav.setObjectName("SettingsNav")
        self.nav.setFixedWidth(198)
        self.nav.setIconSize(QSize(18, 18))
        self.nav.setFocusPolicy(Qt.NoFocus)
        root.addWidget(self.nav)

        # -- Content stack ---------------------------------------------
        self.pages = QStackedWidget()
        root.addWidget(self.pages, 1)

        p = theme.active()
        categories = [
            ("shield", "Security", self._build_security_page),
            ("settings", "General", self._build_general_page),
            ("download", "Backups", self._build_backups_page),
            ("key", "Recovery", self._build_recovery_page),
            ("globe", "Browser extension", self._build_extension_page),
            ("refresh", "Updates", self._build_updates_page),
            ("info", "About", self._build_about_page),
        ]
        for icon_name, title, builder in categories:
            item = QListWidgetItem(icons.icon(icon_name, p.text_muted, 18), f"  {title}")
            self.nav.addItem(item)
            self.pages.addWidget(self._scroll(builder()))
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)

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
        # The browser picker only changes what folder/steps we show — never a
        # persisted setting, so it refreshes the panel instead of saving.
        self.ext_browser.currentIndexChanged.connect(self._refresh_extension_info)

    # -- page scaffolding ----------------------------------------------

    def _page(self, title: str, subtitle: str = "") -> tuple[QWidget, QVBoxLayout]:
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(30, 26, 30, 26)
        lay.setSpacing(16)
        lay.addWidget(components.heading(title, "H1"))
        if subtitle:
            lay.addWidget(components.muted(subtitle))
        return body, lay

    def _scroll(self, body: QWidget) -> QScrollArea:
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setFrameShape(QScrollArea.NoFrame)
        sc.setWidget(body)
        return sc

    # -- Security ------------------------------------------------------

    def _build_security_page(self) -> QWidget:
        body, lay = self._page(
            "Security",
            "When the vault locks itself, and how long copied secrets linger.")
        card = Card()
        self.autolock = QComboBox()
        for label, val in [("After 1 minute", 1), ("After 5 minutes", 5),
                           ("After 15 minutes", 15), ("After 30 minutes", 30), ("Never", 0)]:
            self.autolock.addItem(label, val)
        card.add(_Setting("Auto-lock", "Lock the vault after this much inactivity.", self.autolock))

        self.lock_min = QCheckBox()
        card.add(_Setting("Lock when hidden to tray",
                          "Always lock the vault the moment the window is hidden.", self.lock_min))

        self.clip = QComboBox()
        for label, val in [("After 10 seconds", 10), ("After 20 seconds", 20),
                           ("After 30 seconds", 30), ("After 60 seconds", 60), ("Never", 0)]:
            self.clip.addItem(label, val)
        card.add(_Setting("Clear clipboard",
                          "Wipe copied passwords from the clipboard automatically.", self.clip))
        lay.addWidget(card)
        lay.addStretch(1)
        return body

    # -- General -------------------------------------------------------

    def _build_general_page(self) -> QWidget:
        body, lay = self._page("General", "Window behaviour, startup, and appearance.")

        close_card = Card()
        close_card.add(components.heading("When you press the X button", "H3"))
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

        start_card = Card()
        start_card.add(components.heading("Startup", "H3"))
        self.launch = QCheckBox()
        start_card.add(_Setting("Launch at Windows startup",
                                "Start NoMorePwn (locked, in the tray) when you sign in.", self.launch))
        self.start_min = QCheckBox()
        start_card.add(_Setting("Start minimised to tray",
                                "Open straight to the tray instead of showing the window.", self.start_min))
        lay.addWidget(start_card)

        appear_card = Card()
        appear_card.add(components.heading("Appearance", "H3"))
        self.theme_sel = QComboBox()
        self.theme_sel.addItem("Dark", "dark")
        self.theme_sel.addItem("Light", "light")
        appear_card.add(_Setting("Theme", "Switch between the dark and light look.", self.theme_sel))
        lay.addWidget(appear_card)
        lay.addStretch(1)
        return body

    # -- Backups -------------------------------------------------------

    def _build_backups_page(self) -> QWidget:
        body, lay = self._page(
            "Encrypted backups",
            "A sealed copy of your vault is refreshed automatically after every "
            "change. The file is useless to anyone without your password — so it's "
            "safe to point this at Dropbox, OneDrive, or a USB stick.")

        card = Card()
        self.backup_enabled = QCheckBox()
        card.add(_Setting("Back up automatically",
                          "Refresh the encrypted backup whenever the vault changes.",
                          self.backup_enabled))

        self.backup_keep = QComboBox()
        for label, val in [("Keep 3", 3), ("Keep 5", 5), ("Keep 10", 10)]:
            self.backup_keep.addItem(label, val)
        card.add(_Setting("Generations kept",
                          "Older copies are retained as .1, .2 … in case the newest is lost.",
                          self.backup_keep))

        loc_btn = components.button("Change…", "external")
        loc_btn.clicked.connect(self._pick_backup_dir)
        card.add(_Setting("Location", "Where backup files are written.", loc_btn))
        self.backup_path = QLabel("")
        self.backup_path.setObjectName("Faint")
        self.backup_path.setWordWrap(True)
        self.backup_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.add(self.backup_path)

        self.pass_btn = components.button("Use a separate passphrase…", "key")
        self.pass_btn.clicked.connect(self._set_backup_passphrase)
        card.add(_Setting(
            "Protection",
            "By default backups open with your master password. You can require a "
            "different passphrase instead.",
            self.pass_btn))
        self.protection_lbl = QLabel("")
        self.protection_lbl.setObjectName("Faint")
        self.protection_lbl.setWordWrap(True)
        card.add(self.protection_lbl)

        self.backup_status = QLabel("")
        self.backup_status.setObjectName("Faint")
        self.backup_status.setWordWrap(True)
        card.add(self.backup_status)

        actions = QHBoxLayout()
        now_btn = components.button("Back up now", "download")
        now_btn.clicked.connect(self._backup_now)
        restore_btn = components.button("Restore or import…", "history")
        restore_btn.clicked.connect(lambda: self._ctx.open_restore())
        actions.addWidget(now_btn)
        actions.addWidget(restore_btn)
        actions.addStretch(1)
        card.body.addLayout(actions)
        lay.addWidget(card)
        lay.addStretch(1)
        return body

    # -- Recovery ------------------------------------------------------

    def _build_recovery_page(self) -> QWidget:
        body, lay = self._page(
            "Recovery kit",
            "Forget your master password and there is no reset — unless you make a "
            "recovery kit first. It escrows your key into a file you store yourself; "
            "nothing about it is written into your vault or backups. The optional "
            "authenticator mode also requires a seed, so the kit file alone opens "
            "nothing. Keep the kit as safe as your password.")
        card = Card()
        self.recovery_btn = components.button("Create recovery kit…", "key")
        self.recovery_btn.clicked.connect(self._create_recovery_kit)
        card.add(_Setting(
            "Recovery kit",
            "Make one now so a forgotten password is recoverable later.",
            self.recovery_btn))
        lay.addWidget(card)
        lay.addStretch(1)
        return body

    # -- Browser extension ---------------------------------------------

    def _build_extension_page(self) -> QWidget:
        body, lay = self._page(
            "Browser extension",
            "Save logins straight from your browser. NoMorePwn only offers to save "
            "a password once it has confirmed the login actually worked, so you "
            "never store the typo you just fixed. It talks to this app directly on "
            "your machine — nothing is sent anywhere.")

        status_card = Card()
        self.ext_status = QLabel("")
        self.ext_status.setWordWrap(True)
        status_card.add(self.ext_status)
        lay.addWidget(status_card)

        cap_card = Card()
        cap_card.add(components.heading("Capture behaviour", "H3"))
        self.capture_action = QComboBox()
        self.capture_action.addItem("Save silently to Captured Logins", CAPTURE_SILENT)
        self.capture_action.addItem("Prompt me to review in the app", CAPTURE_PROMPT)
        self.capture_action.addItem("Ignore completely", CAPTURE_DISABLED)
        cap_card.add(_Setting(
            "When a login is captured",
            "How NoMorePwn handles credentials sent from your browser.",
            self.capture_action))
        lay.addWidget(cap_card)

        inst_card = Card()
        inst_card.add(components.heading("Install in your browser", "H3"))
        inst_card.add(components.muted(
            "Choose a browser and NoMorePwn will register the local connection, "
            "open that browser's extensions page, and open the folder to load. The "
            "final “Load unpacked” click is yours — browsers don't let an app "
            "install an unpacked extension silently."))

        self.ext_browser = QComboBox()
        self._populate_browser_choices()
        inst_card.add(_Setting(
            "Browser",
            "Chrome, Edge and Brave share one build; Firefox uses its own.",
            self.ext_browser))

        self.ext_setup_btn = components.primary_button("Auto-install on browser", "download")
        self.ext_setup_btn.clicked.connect(self._auto_install_extension)
        setup_row = QHBoxLayout()
        setup_row.addWidget(self.ext_setup_btn)
        setup_row.addStretch(1)
        inst_card.body.addLayout(setup_row)

        self.ext_steps = QLabel("")
        self.ext_steps.setObjectName("Faint")
        self.ext_steps.setWordWrap(True)
        self.ext_steps.setTextInteractionFlags(Qt.TextSelectableByMouse)
        inst_card.add(self.ext_steps)

        ext_actions = QHBoxLayout()
        self.ext_folder_btn = components.button("Open folder", "external")
        self.ext_folder_btn.clicked.connect(self._open_extension_folder)
        self.ext_copy_btn = components.button("Copy path", "copy")
        self.ext_copy_btn.clicked.connect(self._copy_extension_path)
        self.ext_remove_btn = components.button("Disconnect", "x")
        self.ext_remove_btn.clicked.connect(self._remove_extension)
        ext_actions.addWidget(self.ext_folder_btn)
        ext_actions.addWidget(self.ext_copy_btn)
        ext_actions.addWidget(self.ext_remove_btn)
        ext_actions.addStretch(1)
        inst_card.body.addLayout(ext_actions)
        lay.addWidget(inst_card)
        lay.addStretch(1)
        return body

    # -- Updates -------------------------------------------------------

    def _build_updates_page(self) -> QWidget:
        body, lay = self._page(
            "Updates",
            "NoMorePwn checks GitHub for new stable releases, downloads them in "
            "the background, and verifies the download before asking you to "
            "install. It never installs on its own, and your vault is locked "
            "first. Your vault and backups are untouched by an update.")
        card = Card()
        self.updates_enabled = QCheckBox()
        card.add(_Setting("Check for updates automatically",
                          "On launch and once a day while running.",
                          self.updates_enabled))
        self.update_status = QLabel("")
        self.update_status.setWordWrap(True)
        card.add(self.update_status)
        upd_actions = QHBoxLayout()
        self.update_check_btn = components.button("Check now", "refresh")
        self.update_check_btn.clicked.connect(self._check_updates)
        self.update_install_btn = components.button("Restart & update", "download")
        self.update_install_btn.clicked.connect(self._install_update)
        self.update_install_btn.setVisible(False)
        upd_actions.addWidget(self.update_check_btn)
        upd_actions.addWidget(self.update_install_btn)
        upd_actions.addStretch(1)
        card.body.addLayout(upd_actions)
        lay.addWidget(card)
        lay.addStretch(1)
        return body

    # -- About ---------------------------------------------------------

    def _build_about_page(self) -> QWidget:
        body, lay = self._page("About")
        card = Card()
        card.add(components.heading(f"NoMorePwn {__version__}", "H3"))
        card.add(components.muted(
            "Local-first, zero-knowledge password manager. Your master password "
            "never leaves this device; secrets are sealed with AES-256-GCM."))
        loc = QLabel(f"Vault location: {config.DATA_DIR}")
        loc.setObjectName("Faint")
        loc.setWordWrap(True)
        loc.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.add(loc)
        lay.addWidget(card)
        lay.addStretch(1)
        return body

    # -- load / save ---------------------------------------------------

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
        # Must stay last: _on_change() can rebuild/destroy this very view.
        self._on_change()

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

    def _populate_browser_choices(self) -> None:
        """Fill the browser picker: detected browsers first, else all supported.

        The user's default browser is preselected and labelled, so the common
        "just set it up" path is one click with nothing to choose.
        """
        self.ext_browser.blockSignals(True)
        self.ext_browser.clear()
        installed = browser_bridge.installed_browsers()
        default = browser_bridge.default_browser()
        names = installed or list(browser_bridge.BROWSERS)
        for name in names:
            suffix = ""
            if name == default:
                suffix = "  (default)"
            elif name in installed:
                suffix = "  (installed)"
            self.ext_browser.addItem(name + suffix, name)
        if default:
            idx = self.ext_browser.findData(default)
            if idx >= 0:
                self.ext_browser.setCurrentIndex(idx)
        self.ext_browser.blockSignals(False)

    def _selected_browser(self) -> str:
        return self.ext_browser.currentData() or "Chrome"

    def _refresh_extension_info(self) -> None:
        p = theme.active()
        st = browser_bridge.status()
        browser = self._selected_browser()
        folder = st.folder_for(browser)
        missing = st.files_missing

        if missing:
            self.ext_status.setText("⚠  The browser extension is missing from this install.")
            self.ext_status.setStyleSheet(f"color:{p.danger};")
        elif st.is_registered:
            self.ext_status.setText(f"✓  Connected to {', '.join(st.registered)}")
            self.ext_status.setStyleSheet(f"color:{p.success}; font-weight:600;")
        elif not st.supported:
            self.ext_status.setText(
                "Ready to load. Automatic registration is Windows-only for now — "
                "the folder and steps below still apply.")
            self.ext_status.setStyleSheet(f"color:{p.text_muted};")
        else:
            self.ext_status.setText("Not connected yet — use “Auto-install on browser” below.")
            self.ext_status.setStyleSheet(f"color:{p.text_muted};")

        self.ext_setup_btn.setEnabled(not missing)
        self.ext_browser.setEnabled(not missing)
        self.ext_folder_btn.setEnabled(not missing and folder.exists())
        self.ext_copy_btn.setEnabled(not missing)
        self.ext_remove_btn.setEnabled(st.is_registered)

        # Loading unpacked is a browser-side action we can't perform for the
        # user, so spell it out — naming the exact per-browser folder.
        if missing:
            self.ext_steps.setText("")
            return
        page_url = browser_bridge.extensions_page(browser)
        self.ext_steps.setText(
            f"To finish loading in {browser}:\n"
            f"1.  Open  {page_url}\n"
            f"2.  Turn on Developer mode\n"
            f"3.  Click “Load unpacked” and choose this folder:\n"
            f"      {folder}")

    def _auto_install_extension(self) -> None:
        browser = self._selected_browser()
        outcome = browser_bridge.auto_install(browser)

        # Opening the folder + copying its path is cross-platform and makes the
        # one remaining manual step trivial.
        if outcome.folder.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(outcome.folder)))
            QApplication.clipboard().setText(str(outcome.folder))

        self._refresh_extension_info()

        page_url = browser_bridge.extensions_page(browser)
        if not outcome.files_ready:
            self._ctx.toast.show(
                "The bundled extension files are missing from this install.", "error", 4000)
            return
        if not outcome.supported:
            self._ctx.toast.show(
                f"Opened the {browser} folder and copied its path. Automatic "
                f"registration is Windows-only; load it from {page_url}.", "info", 5000)
            return
        if not outcome.registered:
            # Registration is the part we own on this platform — don't hide a
            # failure behind a cheerful "opened the folder" message.
            self._ctx.toast.show(
                f"Opened the {browser} folder and copied its path, but couldn't "
                f"register the connection. Load it from {page_url} and try "
                f"Auto-install again.", "error", 6000)
            return

        steps = ["registered the connection"]
        if outcome.page_opened:
            steps.append(f"opened {browser}")
        steps.append("opened the folder & copied its path")
        self._ctx.toast.show(
            f"NoMorePwn {', '.join(steps)}. Click “Load unpacked” to finish.",
            "success", 5000)

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
        path = browser_bridge.extension_dir(self._selected_browser())
        if not path.exists():
            self._ctx.toast.show("Extension folder is missing.", "error")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _copy_extension_path(self) -> None:
        QApplication.clipboard().setText(
            str(browser_bridge.extension_dir(self._selected_browser())))
        self._ctx.toast.show("Folder path copied", "success")
