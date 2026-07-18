"""Settings page: security, startup, appearance, and about."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QScrollArea,
    QVBoxLayout, QWidget,
)

from nomorepwn import config, vault
from nomorepwn.settings import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings

from . import __version__, components, theme
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
        self._loading = False
        self._refresh_backup_info()

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
        s.save()
        self._on_change()
