"""Standalone password / passphrase generator page."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QScrollArea, QVBoxLayout, QWidget

from . import components
from .components import Card
from .context import AppContext
from .generator_widget import GeneratorPanel


class GeneratorView(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self._ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 26, 28, 26)
        lay.setSpacing(16)
        scroll.setWidget(body)
        root.addWidget(scroll)

        lay.addWidget(components.heading("Password generator", "H1"))
        lay.addWidget(components.muted(
            "Every password is created with a cryptographically secure random "
            "generator — right here on your device."))

        card = Card(padding=24)
        card.setMinimumWidth(560)
        card.setMaximumWidth(760)
        self.panel = GeneratorPanel(show_use_button=False)
        card.add(self.panel)
        lay.addWidget(card)
        lay.addStretch(1)

        self.panel.copy_btn.clicked.connect(
            lambda: self._ctx.copy_secret(self.panel.value(), "Password copied"))
