"""First-run screen: create the encrypted vault with a master password."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget,
)

from nomorepwn import config, strength, vault
from nomorepwn.settings import Settings

from . import components, icons, theme, workers
from .components import StrengthMeter


class CreateView(QWidget):
    """Emits ``created`` with an unlocked :class:`~nomorepwn.vault.Vault`."""

    created = Signal(object)

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
        panel = QWidget()
        panel.setFixedWidth(440)
        col = QVBoxLayout(panel)
        col.setSpacing(14)
        col.setContentsMargins(0, 0, 0, 0)

        logo = QLabel()
        logo.setPixmap(icons.logo_pixmap(64))
        logo.setAlignment(Qt.AlignCenter)
        col.addWidget(logo)

        title = components.heading("Create your vault", "H1")
        title.setAlignment(Qt.AlignCenter)
        col.addWidget(title)
        sub = components.muted(
            "Your master password unlocks everything. It's stretched with "
            "Argon2id into a key that never touches disk — so choose something "
            "strong and memorable."
        )
        sub.setAlignment(Qt.AlignCenter)
        col.addWidget(sub)
        col.addSpacing(4)

        card = components.Card(padding=24)

        card.add(components.field_label("Master password"))
        self.pw1 = QLineEdit()
        self.pw1.setPlaceholderText("At least 10 characters")
        components.add_reveal_action(self.pw1)
        card.add(self.pw1)

        self.meter = StrengthMeter()
        card.add(self.meter)

        card.add(components.field_label("Confirm master password"))
        self.pw2 = QLineEdit()
        self.pw2.setPlaceholderText("Type it again")
        components.add_reveal_action(self.pw2)
        card.add(self.pw2)

        self.hint = QLabel("")
        self.hint.setObjectName("Faint")
        self.hint.setWordWrap(True)
        card.add(self.hint)

        warn = QHBoxLayout()
        warn_icon = QLabel()
        warn_icon.setPixmap(icons.pixmap("alert-triangle", p.warning, 16))
        warn_icon.setAlignment(Qt.AlignTop)
        warn_text = QLabel("If you forget this password there's no reset — but you can set up a "
                           "Recovery Kit right after, so you're not locked out.")
        warn_text.setWordWrap(True)
        warn_text.setStyleSheet(f"color:{p.warning}; font-size:12px;")
        warn.addWidget(warn_icon)
        warn.addWidget(warn_text, 1)
        card.body.addLayout(warn)

        self.create_btn = components.primary_button("Create vault", "shield-check")
        self.create_btn.setEnabled(False)
        card.add(self.create_btn)

        col.addWidget(card)
        row.addWidget(panel)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)

        self.pw1.textChanged.connect(self._validate)
        self.pw2.textChanged.connect(self._validate)
        self.pw1.returnPressed.connect(lambda: self.pw2.setFocus())
        self.pw2.returnPressed.connect(self._submit)
        self.create_btn.clicked.connect(self._submit)

    def _validate(self) -> None:
        pw = self.pw1.text()
        if pw:
            res = strength.evaluate(pw)
            self.meter.set_result(res.score, res.label)
        else:
            self.meter.clear()

        ok = True
        if len(pw) < 10:
            self.hint.setText("Master password must be at least 10 characters.")
            ok = False
        elif self.pw2.text() and self.pw1.text() != self.pw2.text():
            self.hint.setText("Passwords don't match yet.")
            ok = False
        else:
            self.hint.setText("")
        self.create_btn.setEnabled(ok and bool(self.pw2.text()) and pw == self.pw2.text())

    def _submit(self) -> None:
        pw = self.pw1.text()
        if len(pw) < 10 or pw != self.pw2.text():
            self._validate()
            return
        self.create_btn.setEnabled(False)
        self.create_btn.setText("Securing your vault…")

        def work():
            config.ensure_data_dir()
            vault.create_vault(self._db_path, pw)
            return vault.Vault.unlock(self._db_path, pw)

        workers.run_async(work, self._on_done, self._on_error)

    def _on_done(self, unlocked) -> None:
        self.pw1.clear()
        self.pw2.clear()
        self.create_btn.setText("Create vault")
        self.created.emit(unlocked)

    def _on_error(self, exc: Exception) -> None:
        self.create_btn.setEnabled(True)
        self.create_btn.setText("Create vault")
        self._toast.show(str(exc), "error", 4000)
