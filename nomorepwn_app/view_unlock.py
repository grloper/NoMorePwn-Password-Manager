"""Lock screen: unlock an existing vault with the master password."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget

from nomorepwn import vault

from . import components, icons, theme, workers


class UnlockView(QWidget):
    unlocked = Signal(object)

    def __init__(self, db_path: str, toast, parent=None):
        super().__init__(parent)
        self._db_path = db_path
        self._toast = toast
        self.setObjectName("Root")
        p = theme.active()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)

        self.col_host = QWidget()
        self.col_host.setFixedWidth(400)
        col = QVBoxLayout(self.col_host)
        col.setSpacing(14)
        col.setContentsMargins(0, 0, 0, 0)

        logo = QLabel()
        logo.setPixmap(icons.logo_pixmap(72))
        logo.setAlignment(Qt.AlignCenter)
        col.addWidget(logo)

        title = components.heading("Welcome back", "H1")
        title.setAlignment(Qt.AlignCenter)
        col.addWidget(title)
        sub = components.muted("Enter your master password to unlock the vault.")
        sub.setAlignment(Qt.AlignCenter)
        # No alignment flag: an aligned layout item is sized to sizeHint() and
        # never asked for heightForWidth(), which starves a word-wrapped label
        # into a one-line box that its text then overflows. setAlignment above
        # already centres the text.
        col.addWidget(sub)

        card = components.Card(padding=22)
        card.add(components.field_label("Master password"))
        self.pw = QLineEdit()
        self.pw.setPlaceholderText("Master password")
        components.add_reveal_action(self.pw)
        card.add(self.pw)

        self.error = QLabel("")
        self.error.setStyleSheet(f"color:{p.danger}; font-size:12px; font-weight:600;")
        self.error.setVisible(False)
        card.add(self.error)

        self.unlock_btn = components.primary_button("Unlock", "unlock")
        card.add(self.unlock_btn)
        col.addWidget(card)

        row.addWidget(self.col_host)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)

        self.pw.returnPressed.connect(self._submit)
        self.unlock_btn.clicked.connect(self._submit)

    def focus_input(self) -> None:
        self.pw.setFocus()
        self.pw.selectAll()

    def _submit(self) -> None:
        password = self.pw.text()
        if not password:
            return
        self.error.setVisible(False)
        self.unlock_btn.setEnabled(False)
        self.unlock_btn.setText("Unlocking…")
        workers.run_async(
            lambda: vault.Vault.unlock(self._db_path, password),
            self._on_done, self._on_error,
        )

    def _on_done(self, unlocked) -> None:
        self.pw.clear()
        self.unlock_btn.setEnabled(True)
        self.unlock_btn.setText("Unlock")
        self.unlocked.emit(unlocked)

    def _on_error(self, exc: Exception) -> None:
        self.unlock_btn.setEnabled(True)
        self.unlock_btn.setText("Unlock")
        if isinstance(exc, vault.InvalidMasterPasswordError):
            self.error.setText("Incorrect master password. Try again.")
        else:
            self.error.setText(str(exc))
        self.error.setVisible(True)
        self.pw.selectAll()
        self._shake()

    def _shake(self) -> None:
        anim = QPropertyAnimation(self.col_host, b"pos", self)
        start = self.col_host.pos()
        anim.setDuration(320)
        anim.setEasingCurve(QEasingCurve.OutElastic)
        anim.setKeyValueAt(0.0, start)
        anim.setKeyValueAt(0.25, start.__class__(start.x() - 10, start.y()))
        anim.setKeyValueAt(0.5, start.__class__(start.x() + 8, start.y()))
        anim.setKeyValueAt(0.75, start.__class__(start.x() - 4, start.y()))
        anim.setKeyValueAt(1.0, start)
        anim.start()
        self._shake_anim = anim
