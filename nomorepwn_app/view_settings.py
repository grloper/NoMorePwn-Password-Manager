"""Settings page: security, startup, appearance, and about."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from nomorepwn import config
from nomorepwn.settings import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings

from . import __version__, components, theme
from .components import Card
from .context import AppContext


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
        self._loading = False

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
        s.save()
        self._on_change()
