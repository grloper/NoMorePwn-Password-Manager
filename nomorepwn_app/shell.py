"""The unlocked application shell: left nav rail + stacked pages."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QLabel, QStackedWidget, QToolButton, QVBoxLayout, QWidget,
)

from nomorepwn import vault

from . import components, icons, theme
from .context import AppContext
from .view_audit import AuditView
from .view_generator import GeneratorView
from .view_settings import SettingsView
from .view_vault import VaultView


class AppShell(QWidget):
    lock_requested = Signal()
    settings_changed = Signal()

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self._ctx = ctx
        self._vault: vault.Vault | None = None
        p = theme.active()

        from PySide6.QtWidgets import QHBoxLayout
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- Rail ------------------------------------------------------
        rail = QFrame()
        rail.setObjectName("Sidebar")
        rail.setFixedWidth(84)
        rl = QVBoxLayout(rail)
        rl.setContentsMargins(12, 16, 12, 16)
        rl.setSpacing(8)

        logo = QLabel()
        logo.setPixmap(icons.logo_pixmap(38))
        logo.setAlignment(Qt.AlignCenter)
        rl.addWidget(logo)
        rl.addSpacing(14)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self.stack = QStackedWidget()

        self.vault_view = VaultView(ctx)
        self.audit_view = AuditView(ctx)
        self.generator_view = GeneratorView(ctx)
        self.settings_view = SettingsView(ctx, self.settings_changed.emit)

        pages = [
            ("grid", "Items", self.vault_view),
            ("activity", "Security", self.audit_view),
            ("sliders", "Generator", self.generator_view),
            ("settings", "Settings", self.settings_view),
        ]
        for i, (icon_name, label, page) in enumerate(pages):
            btn = self._nav_button(icon_name, label)
            self._group.addButton(btn, i)
            rl.addWidget(btn)
            self.stack.addWidget(page)
            if i == 0:
                btn.setChecked(True)
        self._group.idClicked.connect(self._switch_page)

        rl.addStretch(1)
        self.lock_btn = self._nav_button("lock", "Lock", checkable=False)
        self.lock_btn.setToolTip("Lock the vault")
        self.lock_btn.clicked.connect(self.lock_requested.emit)
        rl.addWidget(self.lock_btn)

        root.addWidget(rail)
        root.addWidget(self.stack, 1)

    def _nav_button(self, icon_name: str, label: str, checkable: bool = True) -> QToolButton:
        btn = QToolButton()
        btn.setObjectName("NavButton")
        btn.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        btn.setIcon(icons.icon(icon_name, theme.active().text_muted, 22))
        btn.setIconSize(QSize(22, 22))
        btn.setText(label)
        btn.setCheckable(checkable)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedSize(60, 56)
        return btn

    def _switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        page = self.stack.widget(index)
        if page is self.audit_view:
            self.audit_view.refresh()
        elif page is self.generator_view:
            self.generator_view.panel.regenerate()

    def set_vault(self, vlt: "vault.Vault | None") -> None:
        self._vault = vlt
        self.vault_view.set_vault(vlt)
        self.audit_view.set_vault(vlt)

    def goto_items(self) -> None:
        self.goto_page(0)

    def goto_page(self, index: int) -> None:
        btn = self._group.button(index)
        if btn is not None:
            btn.setChecked(True)
        self._switch_page(index)

    def has_unsaved(self) -> bool:
        return self.vault_view.has_unsaved_editor()
