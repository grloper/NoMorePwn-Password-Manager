"""Top-level window: switches between create / unlock / unlocked shell."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QMainWindow, QStackedWidget, QWidget

from nomorepwn import vault

from . import APP_DISPLAY_NAME, icons
from .components import ToastHost
from .context import AppContext
from .shell import AppShell
from .view_create import CreateView
from .view_unlock import UnlockView


class MainWindow(QMainWindow):
    vault_opened = Signal(object)
    lock_requested = Signal()
    close_requested = Signal()
    settings_changed = Signal()

    def __init__(self, db_path: str):
        super().__init__()
        self._db_path = db_path
        self._ctx: AppContext | None = None
        self._create: CreateView | None = None
        self._unlock: UnlockView | None = None
        self._shell: AppShell | None = None

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setWindowIcon(icons.app_icon())
        self.resize(1060, 720)
        self.setMinimumSize(940, 620)

        self.stack = QStackedWidget()
        self.stack.setObjectName("Root")
        self.setCentralWidget(self.stack)
        self.toast = ToastHost(self)

    def set_context(self, ctx: AppContext) -> None:
        self._ctx = ctx

    # -- state screens -------------------------------------------------

    def show_create(self) -> None:
        if self._create is None:
            self._create = CreateView(self._db_path, self.toast)
            self._create.created.connect(self.vault_opened.emit)
            self.stack.addWidget(self._create)
        self.stack.setCurrentWidget(self._create)

    def show_unlock(self) -> None:
        if self._unlock is None:
            self._unlock = UnlockView(self._db_path, self.toast)
            self._unlock.unlocked.connect(self.vault_opened.emit)
            self.stack.addWidget(self._unlock)
        self.stack.setCurrentWidget(self._unlock)
        self._unlock.focus_input()

    def show_shell(self, vlt: "vault.Vault") -> None:
        # Rebuild the shell each unlock so no decrypted data lingers.
        if self._shell is not None:
            self.stack.removeWidget(self._shell)
            self._shell.deleteLater()
            self._shell = None
        self._shell = AppShell(self._ctx)
        self._shell.lock_requested.connect(self.lock_requested.emit)
        self._shell.settings_changed.connect(self.settings_changed.emit)
        self._shell.set_vault(vlt)
        self.stack.addWidget(self._shell)
        self.stack.setCurrentWidget(self._shell)

    def teardown_shell(self) -> None:
        """Drop the unlocked shell (called on lock) to clear plaintext widgets."""
        if self._shell is not None:
            self.stack.removeWidget(self._shell)
            self._shell.deleteLater()
            self._shell = None

    def reset_cached_views(self) -> None:
        """Discard the cached create/unlock screens.

        Those widgets bake palette colours into inline stylesheets at
        construction, so after a theme change they must be rebuilt rather
        than reused — otherwise light-theme surfaces linger in dark mode.
        """
        for attr in ("_create", "_unlock"):
            view = getattr(self, attr)
            if view is not None:
                self.stack.removeWidget(view)
                view.deleteLater()
                setattr(self, attr, None)

    def has_unsaved(self) -> bool:
        return self._shell is not None and self._shell.has_unsaved()

    # -- window chrome -------------------------------------------------

    def closeEvent(self, event) -> None:
        # The controller decides whether to hide to tray or quit.
        event.ignore()
        self.close_requested.emit()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast._current is not None:
            self.toast._reposition(self.toast._current)
