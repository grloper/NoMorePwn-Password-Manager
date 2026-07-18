"""Right-hand detail panel for a single credential."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QScrollArea, QVBoxLayout, QWidget,
)

from nomorepwn import config, leakcheck, strength, vault

from . import components, icons, theme, workers
from .components import Avatar, Pill, StrengthMeter
from .context import AppContext
from .util import human_age, initials


class _Field(QFrame):
    """A labelled value row with copy / reveal affordances."""

    def __init__(self, label: str, value: str, ctx: AppContext,
                 secret: bool = False, copy_label: str = "Copied"):
        super().__init__()
        p = theme.active()
        self.setStyleSheet(
            f"QFrame {{ background:{p.field}; border:1px solid {p.border}; border-radius:12px; }}"
        )
        self._ctx = ctx
        self._value = value
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 10, 10)
        lay.setSpacing(8)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        lab = QLabel(label.upper())
        lab.setStyleSheet(f"color:{p.text_faint}; font-size:11px; font-weight:700; background:transparent; border:none;")
        text_col.addWidget(lab)
        self.value_edit = QLineEdit(value)
        self.value_edit.setReadOnly(True)
        self.value_edit.setFrame(False)
        self.value_edit.setCursorPosition(0)
        mono = "font-family:'Cascadia Code','Consolas',monospace;" if secret else ""
        self.value_edit.setStyleSheet(
            f"QLineEdit {{ background:transparent; border:none; padding:0; font-size:14px; {mono} color:{p.text}; }}"
        )
        if secret:
            self.value_edit.setEchoMode(QLineEdit.Password)
        text_col.addWidget(self.value_edit)
        lay.addLayout(text_col, 1)

        if secret:
            self.reveal_btn = components.icon_button("eye", "Reveal", 18)
            self.reveal_btn.setCheckable(True)
            self.reveal_btn.toggled.connect(self._toggle_reveal)
            lay.addWidget(self.reveal_btn)
        self.copy_btn = components.icon_button("copy", "Copy", 18)
        self.copy_btn.clicked.connect(lambda: self._ctx.copy_secret(self._value, copy_label))
        lay.addWidget(self.copy_btn)

    def _toggle_reveal(self, on: bool) -> None:
        self.value_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        self.reveal_btn.setIcon(icons.icon("eye-off" if on else "eye", theme.active().text_muted, 18))


class CredentialDetail(QWidget):
    edit_requested = Signal(dict)
    deleted = Signal()
    changed = Signal()

    def __init__(self, get_vault: Callable[[], "vault.Vault"], ctx: AppContext, parent=None):
        super().__init__(parent)
        self._get_vault = get_vault
        self._ctx = ctx
        self._cred: dict | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        self._body = QWidget()
        self._lay = QVBoxLayout(self._body)
        self._lay.setContentsMargins(28, 26, 28, 26)
        self._lay.setSpacing(16)
        scroll.setWidget(self._body)
        root.addWidget(scroll)

    def _clear(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
            elif item.layout():
                _delete_layout(item.layout())

    def show_credential(self, cred: dict) -> None:
        self._cred = cred
        self._clear()
        p = theme.active()
        vlt = self._get_vault()

        # -- Header --------------------------------------------------
        header = QHBoxLayout()
        header.setSpacing(14)
        av = Avatar(cred["service_name"], initials(cred["service_name"]), 56)
        header.addWidget(av, 0, Qt.AlignTop)
        title_col = QVBoxLayout()
        title_col.setSpacing(3)
        title_col.addWidget(components.heading(cred["service_name"], "H2"))
        uname = QLabel(cred["username"])
        uname.setObjectName("Muted")
        title_col.addWidget(uname)
        pills = QHBoxLayout()
        pills.setSpacing(6)
        if cred["mfa_enabled"]:
            pills.addWidget(Pill("MFA on", "success", "shield-check"))
        else:
            pills.addWidget(Pill("No MFA", "warning", "alert-triangle"))
        age = cred.get("age_days")
        if age is not None:
            kind = "danger" if age >= config.PASSWORD_AGE_WARN_DAYS else "neutral"
            pills.addWidget(Pill(f"Changed {human_age(age)}", kind, "clock"))
        pills.addStretch(1)
        title_col.addLayout(pills)
        header.addLayout(title_col, 1)
        self._lay.addLayout(header)

        # -- Fields --------------------------------------------------
        self._lay.addWidget(_Field("Username", cred["username"], self._ctx, copy_label="Username copied"))

        try:
            pw = vlt.reveal_password(cred["id"]) if vlt else ""
        except Exception:
            pw = ""
        pw_field = _Field("Password", pw, self._ctx, secret=True, copy_label="Password copied")
        self._lay.addWidget(pw_field)

        if pw:
            res = strength.evaluate(pw)
            meter = StrengthMeter()
            self._lay.addWidget(meter)
            meter.set_result(res.score, f"{res.label} · cracks in {res.crack_time_display}")

        try:
            notes = vlt.reveal_notes(cred["id"]) if vlt else ""
        except Exception:
            notes = ""
        if notes:
            self._lay.addWidget(_Field("Notes", notes, self._ctx, copy_label="Notes copied"))

        # -- Breach check --------------------------------------------
        breach_row = QHBoxLayout()
        self.breach_btn = components.button("Check for breaches", "globe")
        self.breach_btn.clicked.connect(self._check_breach)
        breach_row.addWidget(self.breach_btn)
        self.breach_status = QLabel("")
        self.breach_status.setObjectName("Muted")
        breach_row.addWidget(self.breach_status, 1)
        breach_row.addStretch(1)
        self._lay.addLayout(breach_row)

        note = QLabel("Only 5 characters of a hash are ever sent (k-anonymity). Your password never leaves this device.")
        note.setObjectName("Faint")
        note.setWordWrap(True)
        self._lay.addWidget(note)

        self._lay.addWidget(components.divider())

        # -- History (collapsible) -----------------------------------
        history = vlt.password_history(cred["id"]) if vlt else []
        self.hist_toggle = components.button(f"Password history ({len(history)})", "history", "Ghost")
        self.hist_toggle.setCheckable(True)
        self.hist_box = QWidget()
        hb = QVBoxLayout(self.hist_box)
        hb.setContentsMargins(6, 4, 6, 4)
        hb.setSpacing(6)
        for entry in history:
            row = QHBoxLayout()
            ok = entry["checksum_ok"]
            dot = QLabel()
            dot.setPixmap(icons.pixmap("check-circle" if ok else "alert-circle",
                                       p.success if ok else p.danger, 15))
            row.addWidget(dot)
            when = QLabel(entry["changed_at"].replace("T", "  ").replace("+00:00", " UTC"))
            when.setObjectName("Muted")
            row.addWidget(when)
            row.addStretch(1)
            hb.addLayout(row)
        self.hist_box.setVisible(False)
        self.hist_toggle.toggled.connect(self.hist_box.setVisible)
        self._lay.addWidget(self.hist_toggle)
        self._lay.addWidget(self.hist_box)

        self._lay.addStretch(1)

        # -- Actions -------------------------------------------------
        actions = QHBoxLayout()
        actions.setSpacing(10)
        edit_btn = components.button("Edit", "edit")
        edit_btn.clicked.connect(lambda: self.edit_requested.emit(self._cred))
        del_btn = components.button("Delete", "trash", "Danger")
        del_btn.clicked.connect(self._delete)
        actions.addWidget(edit_btn)
        actions.addStretch(1)
        actions.addWidget(del_btn)
        self._lay.addLayout(actions)

    # ------------------------------------------------------------------

    def _check_breach(self) -> None:
        vlt = self._get_vault()
        if not vlt or not self._cred:
            return
        self.breach_btn.setEnabled(False)
        self.breach_status.setText("Checking…")
        p = theme.active()
        cred_id = self._cred["id"]

        def work():
            return leakcheck.check_password(vlt.reveal_password(cred_id))

        def done(count):
            self.breach_btn.setEnabled(True)
            if count:
                self.breach_status.setText(f"⚠  Found in {count:,} breaches — change it now")
                self.breach_status.setStyleSheet(f"color:{p.danger}; font-weight:700;")
            else:
                self.breach_status.setText("✓  Not found in any known breach")
                self.breach_status.setStyleSheet(f"color:{p.success}; font-weight:700;")

        def err(exc):
            self.breach_btn.setEnabled(True)
            self.breach_status.setText("Couldn't reach breach service (offline?)")
            self.breach_status.setStyleSheet(f"color:{p.text_muted};")

        workers.run_async(work, done, err)

    def _delete(self) -> None:
        from .dialogs import confirm
        if not self._cred:
            return
        if confirm(self, "Delete this item?",
                   f"“{self._cred['service_name']}” and its password history will be permanently removed. "
                   "This can't be undone.",
                   confirm_text="Delete", danger=True):
            vlt = self._get_vault()
            if vlt:
                vlt.delete_credential(self._cred["id"])
                self._ctx.toast.show("Item deleted", "success")
                self.deleted.emit()


def _delete_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w:
            w.deleteLater()
        elif item.layout():
            _delete_layout(item.layout())
