"""Add / edit a credential, with an inline generator and strength meter."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, QStringListModel, Signal
from PySide6.QtWidgets import (
    QComboBox, QCompleter, QHBoxLayout, QLineEdit, QPlainTextEdit, QScrollArea,
    QVBoxLayout, QWidget,
)

from nomorepwn import groups, strength, validation, vault

from . import components, dialogs, theme, workers
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

        user_label_row = QHBoxLayout()
        user_label_row.addWidget(components.field_label("Username / email"))
        user_label_row.addStretch(1)
        self.alt_toggle = components.button("Add alternate login", None, "LinkButton")
        user_label_row.addWidget(self.alt_toggle)
        form.addLayout(user_label_row)

        self.username = QLineEdit()
        self.username.setPlaceholderText("e.g. alice@example.com")
        self.username.setMaxLength(validation.MAX_USERNAME_LEN)
        # Suggest identifiers already in the vault — most people reuse a
        # handful of addresses across dozens of sites.
        self._identifier_model = QStringListModel([])
        completer = QCompleter(self._identifier_model, self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setFilterMode(Qt.MatchContains)
        completer.setCompletionMode(QCompleter.PopupCompletion)
        self.username.setCompleter(completer)
        form.addWidget(self.username)

        # Hidden until asked for: most credentials have one identifier, and an
        # always-visible second box makes people wonder which one to fill in.
        self.alt_row = QWidget()
        alt_lay = QVBoxLayout(self.alt_row)
        alt_lay.setContentsMargins(0, 8, 0, 0)
        alt_lay.setSpacing(4)
        alt_lay.addWidget(components.field_label("Alternate login (optional)"))
        self.alt_login = QLineEdit()
        self.alt_login.setPlaceholderText("The other way you sign in — e.g. a username, or an email")
        self.alt_login.setMaxLength(validation.MAX_USERNAME_LEN)
        alt_completer = QCompleter(self._identifier_model, self)
        alt_completer.setCaseSensitivity(Qt.CaseInsensitive)
        alt_completer.setFilterMode(Qt.MatchContains)
        self.alt_login.setCompleter(alt_completer)
        alt_lay.addWidget(self.alt_login)
        self.alt_row.setVisible(False)
        form.addWidget(self.alt_row)
        form.addSpacing(8)

        form.addWidget(components.field_label("Group (optional)"))
        # Editable: the dropdown offers known groups, but any label the user
        # types is equally valid — this is their filing system, not ours.
        self.group = QComboBox()
        self.group.setEditable(True)
        self.group.setInsertPolicy(QComboBox.NoInsert)
        self.group.lineEdit().setPlaceholderText("Ungrouped — pick one or type your own")
        self.group.lineEdit().setMaxLength(validation.MAX_GROUP_LEN)
        form.addWidget(self.group)
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
        self.generator = GeneratorPanel(show_use_button=True, ctx=ctx)
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
        # Suggest a group once they stop typing the service, not per keystroke.
        self.service.editingFinished.connect(self._suggest_group_for_service)
        self.alt_toggle.clicked.connect(self._toggle_alt_login)
        self.gen_toggle.clicked.connect(self._toggle_generator)
        self.generator.use_requested.connect(self._use_generated)
        self.copy_pw.clicked.connect(lambda: self._ctx.copy_secret(self.password.text(), "Password copied"))
        self.cancel_btn.clicked.connect(self.cancelled.emit)
        self.save_btn.clicked.connect(self._save)

    # ------------------------------------------------------------------

    def _refresh_identifiers(self) -> None:
        """Reload the autocomplete list from the vault."""
        vlt = self._get_vault()
        try:
            self._identifier_model.setStringList(vlt.list_identifiers() if vlt else [])
        except Exception:  # noqa: BLE001 - autocomplete must never block editing
            self._identifier_model.setStringList([])

    def _show_alt_login(self, show: bool) -> None:
        self.alt_row.setVisible(show)
        self.alt_toggle.setText("Remove alternate login" if show else "Add alternate login")
        if show:
            self.alt_login.setFocus()

    def _toggle_alt_login(self) -> None:
        # isHidden(), not isVisible(): the latter is False whenever an ancestor
        # is off-screen, which would flip this branch the wrong way.
        if not self.alt_row.isHidden():
            self.alt_login.clear()      # hiding it clears it; save writes ""
            self._show_alt_login(False)
        else:
            self._show_alt_login(True)

    def _refresh_group_choices(self, selected: str = "") -> None:
        """Repopulate the dropdown: known groups first, then the user's own."""
        vlt = self._get_vault()
        try:
            existing = vlt.list_groups() if vlt else []
        except Exception:  # noqa: BLE001 - a locked vault must not break the editor
            existing = []
        self.group.blockSignals(True)
        self.group.clear()
        self.group.addItem("")          # ungrouped
        self.group.addItems(groups.choices(existing))
        self.group.setCurrentText(selected)
        self.group.blockSignals(False)

    def _suggest_group_for_service(self) -> None:
        """Pre-fill the group from a recognised service, e.g. gmail -> Email.

        Only ever fills an *empty* box on a *new* item: never silently
        re-files something the user already grouped.
        """
        if self._mode != "add" or self.group.currentText().strip():
            return
        suggested = groups.suggest_group(self.service.text())
        if suggested:
            self.group.setCurrentText(suggested)

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
        self.alt_login.clear()
        self._show_alt_login(False)
        self._refresh_identifiers()
        self._refresh_group_choices("")
        self._original = {"service": "", "username": "", "password": "", "notes": "",
                          "mfa": False, "group": "", "alt": ""}
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
        current_group = cred.get("group_name", "")
        current_alt = cred.get("alt_login", "")
        self.alt_login.setText(current_alt)
        # Shown only when the item actually has one.
        self._show_alt_login(bool(current_alt))
        self._refresh_identifiers()
        self._refresh_group_choices(current_group)
        self._original = {
            "service": cred["service_name"], "username": cred["username"],
            "password": current_pw, "notes": current_notes, "mfa": bool(cred["mfa_enabled"]),
            "group": current_group, "alt": current_alt,
        }
        self.service.setFocus()

    def is_dirty(self) -> bool:
        return (
            self.service.text() != self._original.get("service", "")
            or self.username.text() != self._original.get("username", "")
            or self.password.text() != self._original.get("password", "")
            or self.notes.toPlainText() != self._original.get("notes", "")
            or self.mfa.isChecked() != self._original.get("mfa", False)
            or self.group.currentText().strip() != self._original.get("group", "")
            or self.alt_login.text().strip() != self._original.get("alt", "")
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
        group_name = self.group.currentText().strip()
        alt_login = self.alt_login.text().strip()
        password = self.password.text()
        notes = self.notes.toPlainText()
        mfa = self.mfa.isChecked()

        # A password that ends in a space is usually a copy-paste slip, and it
        # is saved silently today — the user only finds out when the login
        # fails. Ask; never trim on their behalf, because the space can be
        # real. Only for a new or changed password, so editing an entry whose
        # password legitimately ends in a space doesn't nag on every save.
        if password and password != self._original.get("password", ""):
            finding = validation.inspect_password_whitespace(password)
            if finding.found:
                choice = dialogs.ask_whitespace_fix(self, password, finding)
                if choice is None:
                    return
                if choice == dialogs.WS_REMOVE:
                    password = finding.cleaned
                    self.password.setText(password)

        try:
            if self._mode == "add":
                if not password:
                    self._ctx.toast.show("Enter or generate a password first.", "error")
                    return
                vlt.add_credential(service, username, password, notes, mfa,
                                   group_name=group_name, alt_login=alt_login)
            else:
                vlt.update_credential(self._cred_id, service, username, notes, mfa,
                                      group_name=group_name, alt_login=alt_login)
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
        self._ctx.request_backup()
        self.saved.emit()


def _make_check(text: str):
    from PySide6.QtWidgets import QCheckBox
    cb = QCheckBox(text)
    cb.setCursor(Qt.PointingHandCursor)
    return cb
