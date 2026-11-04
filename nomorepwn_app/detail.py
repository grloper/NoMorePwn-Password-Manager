"""Right-hand detail panel for a single credential."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QScrollArea, QVBoxLayout, QWidget,
)

from nomorepwn import breachcatalog, config, leakcheck, strength, vault

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
    closed = Signal()     # user dismissed the item; show the empty state

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
        # Nothing used to dismiss an item: the pane always showed one, whether
        # or not you wanted it open.
        close_btn = components.icon_button("x", "Close (Esc)", 18)
        close_btn.clicked.connect(self.closed.emit)
        header.addWidget(close_btn, 0, Qt.AlignTop)
        self._lay.addLayout(header)

        # -- Fields --------------------------------------------------
        self._lay.addWidget(_Field("Username", cred["username"], self._ctx, copy_label="Username copied"))

        alt = cred.get("alt_login", "")
        if alt:
            self._lay.addWidget(_Field("Alternate login", alt, self._ctx,
                                       copy_label="Alternate login copied"))

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
            meter.set_result(res.score, f"{res.label} · estimate: {res.crack_time_display}")

        try:
            notes = vlt.reveal_notes(cred["id"]) if vlt else ""
        except Exception:
            notes = ""
        if notes:
            self._lay.addWidget(_Field("Notes", notes, self._ctx, copy_label="Notes copied"))

        # -- Breach check (offline until the user asks) --------------
        breach_row = QHBoxLayout()
        already = cred.get("breach_checked_at") is not None and cred.get("breach_count") is not None
        self.breach_btn = components.button(
            "Re-check for breaches" if already else "Check for breaches", "globe")
        self.breach_btn.clicked.connect(self._check_breach)
        breach_row.addWidget(self.breach_btn)
        self.breach_status = QLabel("")
        self.breach_status.setObjectName("Muted")
        breach_row.addWidget(self.breach_status, 1)
        breach_row.addStretch(1)
        self._lay.addLayout(breach_row)
        self._apply_breach_status(
            cred.get("breach_checked_at"),
            cred.get("breach_count"),
        )

        note = QLabel("Only 5 characters of a hash are ever sent (k-anonymity). Your password never leaves this device. The check runs only when you ask.")
        note.setObjectName("Faint")
        note.setWordWrap(True)
        self._lay.addWidget(note)

        # -- Named service breaches (local catalog match, no network) -
        self._render_service_breaches(cred["service_name"])

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

    def _apply_breach_status(self, checked_at, count) -> None:
        """Render persisted (or just-updated) HIBP status on the detail pane."""
        p = theme.active()
        if checked_at is None or count is None:
            self.breach_status.setText(leakcheck.status_label(None, None))
            self.breach_status.setStyleSheet(f"color:{p.text_muted};")
            self.breach_status.setObjectName("Muted")
        elif count:
            self.breach_status.setText(
                f"⚠  Found in {count:,} breaches — change it now · checked {checked_at[:10]}")
            self.breach_status.setStyleSheet(f"color:{p.danger}; font-weight:700;")
        else:
            self.breach_status.setText(f"✓  Clean · checked {checked_at[:10]}")
            self.breach_status.setStyleSheet(f"color:{p.success}; font-weight:700;")

    def _render_service_breaches(self, service_name: str) -> None:
        """Show named breaches for this service domain from the local catalog.

        Matching is on-device only. A missing catalog is not an error — the
        vault works offline; the user refreshes the catalog from the dashboard.
        """
        p = theme.active()
        catalog = breachcatalog.load_catalog()
        hits = breachcatalog.match_service(service_name, catalog)

        head = QLabel("Service breaches (local catalog)")
        head.setStyleSheet(
            f"color:{p.text_faint}; font-size:11px; font-weight:700;")
        self._lay.addWidget(head)

        if catalog is None:
            empty = QLabel(
                "No breach catalog cached yet. Use “Refresh breach catalog” "
                "on the security dashboard — nothing about this vault is sent.")
            empty.setObjectName("Faint")
            empty.setWordWrap(True)
            self._lay.addWidget(empty)
            return

        domain = breachcatalog.extract_domain(service_name)
        if domain is None:
            empty = QLabel(
                "No domain in this service name, so it can’t be matched "
                "against the breach catalog.")
            empty.setObjectName("Faint")
            empty.setWordWrap(True)
            self._lay.addWidget(empty)
            return

        if not hits:
            empty = QLabel(f"No known breaches for {domain} in the local catalog.")
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            self._lay.addWidget(empty)
            return

        for breach in hits[:12]:
            row = QVBoxLayout()
            row.setSpacing(2)
            title = QLabel(f"{breach.display_name}  ·  {breach.breach_date or 'unknown date'}")
            title.setStyleSheet(f"color:{p.warning}; font-weight:700;")
            row.addWidget(title)
            if breach.data_classes:
                classes = QLabel("Exposed: " + ", ".join(breach.data_classes))
                classes.setObjectName("Muted")
                classes.setWordWrap(True)
                row.addWidget(classes)
            self._lay.addLayout(row)
        if len(hits) > 12:
            more = QLabel(f"+{len(hits) - 12} more in catalog")
            more.setObjectName("Faint")
            self._lay.addWidget(more)
        stale_note = QLabel(breachcatalog.status_label(catalog))
        stale_note.setObjectName("Faint")
        stale_note.setWordWrap(True)
        self._lay.addWidget(stale_note)

    def _check_breach(self) -> None:
        vlt = self._get_vault()
        if not vlt or not self._cred:
            return
        self.breach_btn.setEnabled(False)
        self.breach_status.setText("Checking…")
        p = theme.active()
        cred_id = self._cred["id"]

        def work():
            count = leakcheck.check_password(vlt.reveal_password(cred_id))
            vlt.record_breach_check(cred_id, count)
            # Re-read so the UI shows the same timestamp the vault stored.
            for c in vlt.list_credentials():
                if c["id"] == cred_id:
                    return c
            return {"id": cred_id, "breach_count": count, "breach_checked_at": None}

        def done(cred):
            self.breach_btn.setEnabled(True)
            self.breach_btn.setText("Re-check for breaches")
            if self._cred and self._cred.get("id") == cred_id:
                self._cred["breach_count"] = cred.get("breach_count")
                self._cred["breach_checked_at"] = cred.get("breach_checked_at")
            self._apply_breach_status(
                cred.get("breach_checked_at"), cred.get("breach_count"))
            self.changed.emit()

        def err(exc):
            self.breach_btn.setEnabled(True)
            # Leave any prior persisted status alone — a failed re-check is
            # not a reason to erase a real earlier result.
            if self._cred and self._cred.get("breach_checked_at") is not None:
                self._apply_breach_status(
                    self._cred.get("breach_checked_at"),
                    self._cred.get("breach_count"),
                )
                self.breach_status.setText(
                    self.breach_status.text() + "  ·  re-check failed (offline?)")
            else:
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
                self._ctx.request_backup()
                self.deleted.emit()


def _delete_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w:
            w.deleteLater()
        elif item.layout():
            _delete_layout(item.layout())
