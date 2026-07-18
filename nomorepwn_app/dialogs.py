"""Modal dialogs styled to the app: confirmations and the close prompt."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget,
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


def ask_new_passphrase(parent, title: str, message: str, min_length: int = 8) -> str | None:
    """Prompt for a new passphrase twice. Returns None if cancelled."""
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setMinimumWidth(440)
    p = theme.active()
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(26, 24, 26, 22)
    lay.setSpacing(10)

    lay.addWidget(components.heading(title, "H3"))
    msg = QLabel(message)
    msg.setObjectName("Muted")
    msg.setWordWrap(True)
    lay.addWidget(msg)

    first = QLineEdit()
    first.setPlaceholderText(f"At least {min_length} characters")
    components.add_reveal_action(first)
    lay.addWidget(first)
    second = QLineEdit()
    second.setPlaceholderText("Confirm passphrase")
    components.add_reveal_action(second)
    lay.addWidget(second)

    warn = QLabel("If you lose this passphrase, backups sealed with it cannot be opened — "
                  "not even with your master password.")
    warn.setWordWrap(True)
    warn.setStyleSheet(f"color:{p.warning}; font-size:12px;")
    lay.addWidget(warn)

    error = QLabel("")
    error.setStyleSheet(f"color:{p.danger}; font-size:12px; font-weight:600;")
    lay.addWidget(error)

    btns = QHBoxLayout()
    btns.addStretch(1)
    cancel = components.button("Cancel", object_name="Ghost")
    cancel.clicked.connect(dlg.reject)
    btns.addWidget(cancel)
    ok = components.primary_button("Set passphrase", "check")
    btns.addWidget(ok)
    lay.addLayout(btns)

    def submit():
        if len(first.text()) < min_length:
            error.setText(f"Use at least {min_length} characters.")
            return
        if first.text() != second.text():
            error.setText("The two entries don't match.")
            return
        dlg.accept()

    ok.clicked.connect(submit)
    second.returnPressed.connect(submit)
    return first.text() if dlg.exec() == QDialog.Accepted else None


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
        self._hover = False
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
        active = self._checked or self._hover
        border = self._accent if active else p.border_strong
        bg = p.primary_soft if active else p.surface
        self.setStyleSheet(
            f"QFrame#OptCard {{ background:{bg}; border:1.5px solid {border}; border-radius:14px; }}"
        )

    def setChecked(self, value: bool) -> None:
        self._checked = value
        self._refresh()

    def isChecked(self) -> bool:
        return self._checked

    def enterEvent(self, event) -> None:
        self._hover = True
        self._refresh()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover = False
        self._refresh()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class CloseChoiceDialog(QDialog):
    """The X-button prompt. Each option is a *direct action*: one click
    performs it — no separate confirm step — so there's no way to press
    the X and end up unsure whether the app closed. Both options lock the
    vault first."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Close NoMorePwn")
        self.setModal(True)
        self.setMinimumWidth(470)
        self.choice: str | None = None
        p = theme.active()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(14)

        lay.addWidget(components.heading("Close NoMorePwn", "H2"))
        sub = QLabel("Your vault will be locked first. Pick what happens to the app:")
        sub.setObjectName("Muted")
        sub.setWordWrap(True)
        lay.addWidget(sub)

        self.tray_card = _OptionCard(
            "shield-check", "Keep running in the tray",
            "Locks the vault and keeps NoMorePwn in the system tray (bottom-right ⌃) for instant access.",
            p.primary,
        )
        self.quit_card = _OptionCard(
            "power", "Quit completely",
            "Locks the vault and shuts NoMorePwn down entirely.",
            p.danger,
        )
        self.tray_card.clicked.connect(lambda: self._choose(CLOSE_TRAY))
        self.quit_card.clicked.connect(lambda: self._choose(CLOSE_QUIT))
        lay.addWidget(self.tray_card)
        lay.addWidget(self.quit_card)

        self.remember = QCheckBox("Remember my choice (change later in Settings)")
        self.remember.setCursor(Qt.PointingHandCursor)
        lay.addWidget(self.remember)

        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = components.button("Cancel", object_name="Ghost")
        cancel.clicked.connect(self.reject)
        btns.addWidget(cancel)
        lay.addLayout(btns)

    def _choose(self, action: str) -> None:
        self.choice = action
        self.accept()

    def remembered(self) -> bool:
        return self.remember.isChecked()
