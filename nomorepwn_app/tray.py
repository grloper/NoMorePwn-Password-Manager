"""System-tray icon: the app's home while running in the background.

Lives in the Windows notification area (the "show hidden icons" ^ tray).
Left-click / double-click opens the window; right-click shows a menu to
open, lock, or fully quit. The icon and tooltip reflect lock state.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from . import APP_DISPLAY_NAME, icons


class TrayIcon(QObject):
    show_requested = Signal()
    lock_requested = Signal()
    quit_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._locked = True
        self._has_vault = True
        self.tray = QSystemTrayIcon(icons.tray_icon(locked=True), parent)
        self.tray.setToolTip(f"{APP_DISPLAY_NAME} — locked")

        self.menu = QMenu()
        self.act_title = QAction(APP_DISPLAY_NAME, self.menu)
        self.act_title.setEnabled(False)
        self.act_status = QAction("Locked", self.menu)
        self.act_status.setEnabled(False)

        self.act_open = QAction("Open NoMorePwn", self.menu)
        self.act_open.triggered.connect(self.show_requested.emit)
        self.act_lock = QAction("Lock vault", self.menu)
        self.act_lock.triggered.connect(self.lock_requested.emit)
        self.act_quit = QAction("Quit NoMorePwn", self.menu)
        self.act_quit.triggered.connect(self.quit_requested.emit)

        self.menu.addAction(self.act_title)
        self.menu.addAction(self.act_status)
        self.menu.addSeparator()
        self.menu.addAction(self.act_open)
        self.menu.addAction(self.act_lock)
        self.menu.addSeparator()
        self.menu.addAction(self.act_quit)
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._on_activated)

    def _on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_requested.emit()

    def show(self) -> None:
        self.tray.show()

    def hide(self) -> None:
        self.tray.hide()

    def set_state(self, locked: bool, has_vault: bool = True) -> None:
        self._locked = locked
        self._has_vault = has_vault
        self.tray.setIcon(icons.tray_icon(locked=locked))
        state = "locked" if locked else "unlocked"
        self.tray.setToolTip(f"{APP_DISPLAY_NAME} — {state}")
        self.act_status.setText("🔒  Locked" if locked else "🔓  Unlocked")
        self.act_lock.setEnabled(not locked)
        self.act_open.setText("Open NoMorePwn" if locked else "Show window")

    def notify(self, title: str, message: str) -> None:
        self.tray.showMessage(title, message, icons.tray_icon(self._locked), 4000)
