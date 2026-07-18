"""Modal dialogs styled to the app: confirmations and the close prompt."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from nomorepwn.settings import CLOSE_QUIT, CLOSE_TRAY

from . import components, icons, theme


def confirm(parent, title: str, message: str, confirm_text: str = "Confirm",
            cancel_text: str = "Cancel", danger: bool = False) -> bool:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setMinimumWidth(420)
    p = theme.active()
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(26, 24, 26, 22)
    lay.setSpacing(14)

    head = QHBoxLayout()
    head.setSpacing(12)
    ico = QLabel()
    ico.setPixmap(icons.pixmap("alert-triangle" if danger else "info",
                               p.danger if danger else p.primary, 26))
    ico.setAlignment(Qt.AlignTop)
    head.addWidget(ico)
    tcol = QVBoxLayout()
    tcol.setSpacing(6)
    tcol.addWidget(components.heading(title, "H3"))
    msg = QLabel(message)
    msg.setObjectName("Muted")
    msg.setWordWrap(True)
    tcol.addWidget(msg)
    head.addLayout(tcol, 1)
    lay.addLayout(head)

    btns = QHBoxLayout()
    btns.addStretch(1)
    cancel = components.button(cancel_text, object_name="Ghost")
    cancel.clicked.connect(dlg.reject)
    btns.addWidget(cancel)
    ok = QPushButton(confirm_text)
    ok.setObjectName("Danger" if danger else "Primary")
    ok.setCursor(Qt.PointingHandCursor)
    ok.clicked.connect(dlg.accept)
    btns.addWidget(ok)
    lay.addLayout(btns)

    return dlg.exec() == QDialog.Accepted


class _OptionCard(QFrame):
    """A large, selectable option row (child widgets render reliably here,
    unlike inside a QPushButton)."""

    clicked = Signal()

    def __init__(self, icon_name: str, title: str, subtitle: str, accent: str):
        super().__init__()
        self.setObjectName("OptCard")
        self.setCursor(Qt.PointingHandCursor)
        self._accent = accent
        self._checked = False
        p = theme.active()

        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(14)
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, accent, 26))
        ic.setAlignment(Qt.AlignTop)
        ic.setStyleSheet("background:transparent; border:none;")
        lay.addWidget(ic)
        col = QVBoxLayout()
        col.setSpacing(3)
        t = QLabel(title)
        t.setStyleSheet(f"color:{p.text}; font-size:15px; font-weight:700; background:transparent; border:none;")
        col.addWidget(t)
        s = QLabel(subtitle)
        s.setWordWrap(True)
        s.setStyleSheet(f"color:{p.text_muted}; background:transparent; border:none;")
        col.addWidget(s)
        lay.addLayout(col, 1)
        self._refresh()

    def _refresh(self) -> None:
        p = theme.active()
        border = self._accent if self._checked else p.border
        bg = p.primary_soft if self._checked else p.surface
        self.setStyleSheet(
            f"QFrame#OptCard {{ background:{bg}; border:1.5px solid {border}; border-radius:14px; }}"
        )

    def setChecked(self, value: bool) -> None:
        self._checked = value
        self._refresh()

    def isChecked(self) -> bool:
        return self._checked

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class CloseChoiceDialog(QDialog):
    """The X-button prompt: keep running in tray, or quit — both lock first."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Close NoMorePwn")
        self.setModal(True)
        self.setMinimumWidth(460)
        self.choice: str | None = None
        p = theme.active()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(14)

        lay.addWidget(components.heading("Before you go", "H2"))
        sub = QLabel("Your vault will be locked either way. What should NoMorePwn do next?")
        sub.setObjectName("Muted")
        sub.setWordWrap(True)
        lay.addWidget(sub)

        self.tray_card = _OptionCard(
            "shield-check", "Keep running in the tray",
            "Locks the vault and keeps NoMorePwn in the system tray (bottom-right) for instant access.",
            p.primary,
        )
        self.quit_card = _OptionCard(
            "power", "Quit completely",
            "Locks the vault and shuts NoMorePwn down entirely.",
            p.danger,
        )
        self.tray_card.setChecked(True)
        self.tray_card.clicked.connect(lambda: self._select(self.tray_card))
        self.quit_card.clicked.connect(lambda: self._select(self.quit_card))
        lay.addWidget(self.tray_card)
        lay.addWidget(self.quit_card)

        self.remember = QCheckBox("Remember my choice (change later in Settings)")
        self.remember.setCursor(Qt.PointingHandCursor)
        lay.addWidget(self.remember)

        btns = QHBoxLayout()
        cancel = components.button("Cancel", object_name="Ghost")
        cancel.clicked.connect(self.reject)
        btns.addWidget(cancel)
        btns.addStretch(1)
        cont = components.primary_button("Continue", "check")
        cont.clicked.connect(self._accept)
        btns.addWidget(cont)
        lay.addLayout(btns)

    def _select(self, card: _OptionCard) -> None:
        self.tray_card.setChecked(card is self.tray_card)
        self.quit_card.setChecked(card is self.quit_card)

    def _accept(self) -> None:
        self.choice = CLOSE_QUIT if self.quit_card.isChecked() else CLOSE_TRAY
        self.accept()

    def remembered(self) -> bool:
        return self.remember.isChecked()
