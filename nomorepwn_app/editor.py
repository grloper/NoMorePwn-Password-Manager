"""Add / edit a credential, with an inline generator and strength meter."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLineEdit, QPlainTextEdit, QScrollArea, QVBoxLayout, QWidget,
)

from nomorepwn import strength, validation, vault

from . import components, theme, workers
from .components import StrengthMeter
from .context import AppContext
from .generator_widget import GeneratorPanel


class CredentialEditor(QWidget):
    saved = Signal()
    cancelled = Signal()

    def __init__(self, get_vault: Callable[[], "vault.Vault"], ctx: AppContext, parent=None):
        super().__init__(parent)
        self._get_vault = get_vault
        self._ctx = ctx
        self._mode = "add"
        self._cred_id: int | None = None
        self._original = {}

        p = theme.active()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QHBoxLayout()
        header.setContentsMargins(28, 24, 28, 12)
        self.title = components.heading("Add item", "H2")
        header.addWidget(self.title)
        header.addStretch(1)
        root.addLayout(header)

        # Scrollable form body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        form = QVBoxLayout(body)
        form.setContentsMargins(28, 8, 28, 20)
        form.setSpacing(6)

        form.addWidget(components.field_label("Service name"))
        self.service = QLineEdit()
        self.service.setPlaceholderText("e.g. GitHub, gmail.com")
        self.service.setMaxLength(validation.MAX_SERVICE_LEN)
        form.addWidget(self.service)
        form.addSpacing(8)

        form.addWidget(components.field_label("Username / email"))
        self.username = QLineEdit()
        self.username.setPlaceholderText("e.g. alice@example.com")
        self.username.setMaxLength(validation.MAX_USERNAME_LEN)
        form.addWidget(self.username)
        form.addSpacing(8)

        pw_label_row = QHBoxLayout()
        pw_label_row.addWidget(components.field_label("Password"))
        pw_label_row.addStretch(1)
        self.gen_toggle = components.button("Generate", "sparkles", "LinkButton")
        pw_label_row.addWidget(self.gen_toggle)
        form.addLayout(pw_label_row)

        pw_row = QHBoxLayout()
        pw_row.setSpacing(8)
        self.password = QLineEdit()
        self.password.setPlaceholderText("Type or generate a password")
        self.password.setMaxLength(validation.MAX_PASSWORD_LEN)
        components.add_reveal_action(self.password)
        pw_row.addWidget(self.password, 1)
        self.copy_pw = components.icon_button("copy", "Copy", 18)
        pw_row.addWidget(self.copy_pw)
        form.addLayout(pw_row)

        self.meter = StrengthMeter()
        form.addWidget(self.meter)

        # Inline generator (collapsed by default)
        self.gen_box = QWidget()
        self.gen_box.setObjectName("Card")
        gb = QVBoxLayout(self.gen_box)
        gb.setContentsMargins(16, 16, 16, 16)
        self.generator = GeneratorPanel(show_use_button=True)
        gb.addWidget(self.generator)
        self.gen_box.setVisible(False)
        form.addSpacing(6)
        form.addWidget(self.gen_box)
        form.addSpacing(8)

        form.addWidget(components.field_label("Notes (encrypted)"))
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Optional. Recovery codes, security questions…")
        self.notes.setFixedHeight(90)
        form.addWidget(self.notes)
        form.addSpacing(10)

        self.mfa = _make_check("Two-factor authentication (MFA) is enabled on this account")
        form.addWidget(self.mfa)
        form.addStretch(1)

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        # Footer actions
        footer = QHBoxLayout()
        footer.setContentsMargins(28, 12, 28, 24)
        self.cancel_btn = components.button("Cancel", object_name="Ghost")
        footer.addWidget(self.cancel_btn)
        footer.addStretch(1)
        self.save_btn = components.primary_button("Save", "check")
        footer.addWidget(self.save_btn)
        root.addLayout(footer)

        # Wiring
        self.password.textChanged.connect(self._update_strength)
        self.gen_toggle.clicked.connect(self._toggle_generator)
        self.generator.use_requested.connect(self._use_generated)
        self.copy_pw.clicked.connect(lambda: self._ctx.copy_secret(self.password.text(), "Password copied"))
        self.cancel_btn.clicked.connect(self.cancelled.emit)
        self.save_btn.clicked.connect(self._save)

    # ------------------------------------------------------------------

    def load_new(self) -> None:
        self._mode = "add"
        self._cred_id = None
        self.title.setText("Add item")
        self.service.clear()
        self.username.clear()
        self.password.clear()
        self.notes.clear()
        self.mfa.setChecked(False)
        self.gen_box.setVisible(False)
        self._original = {"service": "", "username": "", "password": "", "notes": "", "mfa": False}
        self.service.setFocus()

    def load_edit(self, cred: dict) -> None:
        self._mode = "edit"
        self._cred_id = cred["id"]
        self.title.setText("Edit item")
        vlt = self._get_vault()
        try:
            current_pw = vlt.reveal_password(cred["id"]) if vlt else ""
            current_notes = vlt.reveal_notes(cred["id"]) if vlt else ""
        except Exception:
            current_pw, current_notes = "", ""
        self.service.setText(cred["service_name"])
        self.username.setText(cred["username"])
        self.password.setText(current_pw)
        self.notes.setPlainText(current_notes)
        self.mfa.setChecked(bool(cred["mfa_enabled"]))
        self.gen_box.setVisible(False)
        self._original = {
            "service": cred["service_name"], "username": cred["username"],
            "password": current_pw, "notes": current_notes, "mfa": bool(cred["mfa_enabled"]),
        }
        self.service.setFocus()

    def is_dirty(self) -> bool:
        return (
            self.service.text() != self._original.get("service", "")
            or self.username.text() != self._original.get("username", "")
            or self.password.text() != self._original.get("password", "")
            or self.notes.toPlainText() != self._original.get("notes", "")
            or self.mfa.isChecked() != self._original.get("mfa", False)
        )

    # ------------------------------------------------------------------

    def _update_strength(self) -> None:
        pw = self.password.text()
        if pw:
            res = strength.evaluate(pw)
            self.meter.set_result(res.score, f"{res.label} · cracks in {res.crack_time_display}")
        else:
            self.meter.clear()

    def _toggle_generator(self) -> None:
        show = not self.gen_box.isVisible()
        self.gen_box.setVisible(show)
        if show:
            self.generator.regenerate()

    def _use_generated(self, secret: str) -> None:
        self.password.setText(secret)
        self.gen_box.setVisible(False)

    def _save(self) -> None:
        vlt = self._get_vault()
        if vlt is None:
            return
        service = self.service.text().strip()
        username = self.username.text().strip()
        password = self.password.text()
        notes = self.notes.toPlainText()
        mfa = self.mfa.isChecked()

        try:
            if self._mode == "add":
                if not password:
                    self._ctx.toast.show("Enter or generate a password first.", "error")
                    return
                vlt.add_credential(service, username, password, notes, mfa)
            else:
                vlt.update_credential(self._cred_id, service, username, notes, mfa)
                if password != self._original.get("password", ""):
                    if not password:
                        self._ctx.toast.show("Password cannot be empty.", "error")
                        return
                    vlt.update_password(self._cred_id, password)
        except (validation.ValidationError, vault.VaultError) as exc:
            self._ctx.toast.show(str(exc), "error", 4000)
            return

        self._ctx.toast.show(
            "Item saved" if self._mode == "edit" else "Item added to vault", "success"
        )
        self.saved.emit()


def _make_check(text: str):
    from PySide6.QtWidgets import QCheckBox
    cb = QCheckBox(text)
    cb.setCursor(Qt.PointingHandCursor)
    return cb
