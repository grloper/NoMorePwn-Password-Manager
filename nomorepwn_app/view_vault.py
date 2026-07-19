"""The Items page: searchable list on the left, detail/editor on the right."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QStackedWidget, QVBoxLayout, QWidget,
)

from nomorepwn import groups, vault

from . import components, icons, theme
from .components import Avatar, Pill
from .context import AppContext
from .detail import CredentialDetail
from .editor import CredentialEditor
from .util import initials


class _GroupHeader(QWidget):
    """A clickable divider naming a group, its size, and its collapsed state.

    The list item itself stays non-selectable, so this widget owns the click.
    """

    toggled = Signal()

    def __init__(self, label: str, count: int, collapsed: bool = False):
        super().__init__()
        p = theme.active()
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Expand group" if collapsed else "Collapse group")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 14, 2)
        lay.setSpacing(6)

        self.arrow = QLabel()
        self.arrow.setPixmap(icons.pixmap(
            "chevron-right" if collapsed else "chevron-down", p.text_faint, 14))
        lay.addWidget(self.arrow)

        # Named attributes, not layout positions: callers and tests should not
        # have to know the arrow is child 0.
        self.name_label = QLabel(label.upper())
        self.name_label.setStyleSheet(
            f"color:{p.text_faint}; font-size:11px; font-weight:800;"
            f" letter-spacing:0.8px;"
        )
        lay.addWidget(self.name_label)
        self.count_label = QLabel(str(count))
        self.count_label.setStyleSheet(
            f"color:{p.text_faint}; font-size:11px; font-weight:700;"
            f" background:{p.surface_alt}; border-radius:7px; padding:1px 7px;"
        )
        lay.addWidget(self.count_label)
        lay.addStretch(1)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.toggled.emit()
        super().mouseReleaseEvent(event)


class _ItemRow(QWidget):
    def __init__(self, cred: dict):
        super().__init__()
        p = theme.active()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(12)
        lay.addWidget(Avatar(cred["service_name"], initials(cred["service_name"]), 38))
        col = QVBoxLayout()
        col.setSpacing(1)
        name = QLabel(cred["service_name"])
        name.setStyleSheet(f"color:{p.text}; font-weight:600; background:transparent;")
        col.addWidget(name)
        user = QLabel(cred["username"])
        user.setStyleSheet(f"color:{p.text_muted}; font-size:12px; background:transparent;")
        col.addWidget(user)
        lay.addLayout(col, 1)
        if not cred["mfa_enabled"]:
            warn = QLabel()
            warn.setPixmap(icons.pixmap("alert-triangle", p.warning, 15))
            warn.setToolTip("No MFA on this account")
            lay.addWidget(warn, 0, Qt.AlignVCenter)


class VaultView(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self._ctx = ctx
        self._vault: vault.Vault | None = None
        self._creds: list[dict] = []
        self._selected_id: int | None = None
        # Casefolded labels of groups the user has collapsed this session.
        self._collapsed: set[str] = set()
        p = theme.active()

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- Left: list panel ----------------------------------------
        left = QFrame()
        left.setObjectName("ListPanel")
        left.setFixedWidth(340)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(16, 18, 16, 12)
        ll.setSpacing(12)

        top = QHBoxLayout()
        title = components.heading("All items", "H2")
        top.addWidget(title)
        top.addStretch(1)
        self.count_lbl = QLabel("0")
        self.count_lbl.setObjectName("Faint")
        top.addWidget(self.count_lbl)
        ll.addLayout(top)

        search_wrap = QWidget()
        sw = QHBoxLayout(search_wrap)
        sw.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText("Search items…")
        self.search.addAction(icons.icon("search", p.text_faint, 16), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self._apply_filter)
        sw.addWidget(self.search)
        ll.addWidget(search_wrap)

        self.add_btn = components.primary_button("Add item", "plus")
        self.add_btn.clicked.connect(self._add)
        ll.addWidget(self.add_btn)

        self.list = QListWidget()
        self.list.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        self.list.currentItemChanged.connect(self._on_selection)
        ll.addWidget(self.list, 1)

        self.empty_list_hint = QLabel("Your vault is empty.\nAdd your first item to get started.")
        self.empty_list_hint.setObjectName("Muted")
        self.empty_list_hint.setAlignment(Qt.AlignCenter)
        self.empty_list_hint.setVisible(False)
        ll.addWidget(self.empty_list_hint)

        root.addWidget(left)

        # -- Right: detail / editor stack ----------------------------
        right = QFrame()
        right.setObjectName("DetailPanel")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        rl.addWidget(self.stack)

        self.empty = self._make_empty_state()
        self.detail = CredentialDetail(lambda: self._vault, ctx)
        self.editor = CredentialEditor(lambda: self._vault, ctx)
        self.stack.addWidget(self.empty)     # 0
        self.stack.addWidget(self.detail)    # 1
        self.stack.addWidget(self.editor)    # 2
        root.addWidget(right, 1)

        self.detail.edit_requested.connect(self._edit)
        self.detail.closed.connect(self.close_item)
        self.detail.deleted.connect(self._on_deleted)
        self.detail.changed.connect(lambda: self.refresh(self._selected_id))
        self.editor.saved.connect(self._on_saved)
        self.editor.cancelled.connect(self._on_cancel)

    # ------------------------------------------------------------------

    def _make_empty_state(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(icons.pixmap("shield", theme.active().border_strong, 72, 1.5))
        logo.setAlignment(Qt.AlignCenter)
        lay.addWidget(logo)
        t = components.heading("Select an item", "H3")
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)
        s = components.muted("Choose a credential on the left, or add a new one.")
        s.setAlignment(Qt.AlignCenter)
        lay.addWidget(s, 0, Qt.AlignHCenter)
        return w

    def set_vault(self, vlt: "vault.Vault | None") -> None:
        self._vault = vlt
        self._selected_id = None
        if vlt is None:
            self.list.clear()
            return
        self.refresh()

    def refresh(self, select_id: int | None = None) -> None:
        if self._vault is None:
            return
        self._creds = self._vault.list_credentials()
        self.count_lbl.setText(str(len(self._creds)))
        self.empty_list_hint.setVisible(not self._creds)
        self._rebuild_list()
        if select_id is not None:
            self._select_by_id(select_id)
        elif not self._creds:
            self.stack.setCurrentIndex(0)

    def _rebuild_list(self) -> None:
        term = self.search.text().strip().lower()
        self.list.blockSignals(True)
        self.list.clear()

        matching = [
            cred for cred in self._creds
            if not term or term in (
                cred["service_name"] + " " + cred["username"] + " "
                + (cred.get("group_name") or "") + " "
                + (cred.get("alt_login") or "")
            ).lower()
        ]

        for label, members in groups.group_credentials(matching):
            # While searching, show every match: a hit hidden inside a
            # collapsed group reads as "no results".
            collapsed = bool(not term and label.casefold() in self._collapsed)

            # A header is a decoration, never a selection target — leaving it
            # selectable would let arrow-key navigation land on a non-item.
            header = QListWidgetItem()
            header.setFlags(Qt.NoItemFlags)
            header.setData(Qt.UserRole, None)
            header.setSizeHint(QSize(0, 30))
            self.list.addItem(header)
            widget = _GroupHeader(label, len(members), collapsed)
            widget.toggled.connect(lambda name=label: self._toggle_group(name))
            self.list.setItemWidget(header, widget)

            if collapsed:
                continue

            for cred in members:
                item = QListWidgetItem()
                item.setData(Qt.UserRole, cred["id"])
                item.setSizeHint(QSize(0, 60))
                self.list.addItem(item)
                self.list.setItemWidget(item, _ItemRow(cred))
                if cred["id"] == self._selected_id:
                    self.list.setCurrentItem(item)
        self.list.blockSignals(False)

    def close_item(self) -> None:
        """Dismiss the open item and go back to the empty state.

        Deselects in the list too, otherwise the row stays highlighted and
        clicking it again would not re-open it.
        """
        self._selected_id = None
        self.list.blockSignals(True)
        self.list.clearSelection()
        self.list.setCurrentItem(None)
        self.list.blockSignals(False)
        self.stack.setCurrentIndex(0)

    def keyPressEvent(self, event) -> None:
        # Esc closes the open item, but only when the editor isn't in front —
        # there it would be mistaken for "discard my changes".
        if event.key() == Qt.Key_Escape and self.stack.currentIndex() == 1:
            self.close_item()
            return
        super().keyPressEvent(event)

    def _toggle_group(self, label: str) -> None:
        """Collapse or expand one group. Session-scoped, not persisted."""
        key = label.casefold()
        if key in self._collapsed:
            self._collapsed.discard(key)
        else:
            self._collapsed.add(key)
        self._rebuild_list()

    def _apply_filter(self) -> None:
        self._rebuild_list()

    def _cred_by_id(self, cred_id: int) -> dict | None:
        return next((c for c in self._creds if c["id"] == cred_id), None)

    def _select_by_id(self, cred_id: int) -> None:
        for i in range(self.list.count()):
            item = self.list.item(i)
            if item.data(Qt.UserRole) == cred_id:
                self.list.setCurrentItem(item)
                return

    def _on_selection(self, current, _previous) -> None:
        if current is None:
            return
        cred_id = current.data(Qt.UserRole)
        cred = self._cred_by_id(cred_id)
        if cred:
            self._selected_id = cred_id
            self.detail.show_credential(cred)
            self.stack.setCurrentIndex(1)

    # -- add / edit / delete -------------------------------------------

    def _add(self) -> None:
        self.editor.load_new()
        self.stack.setCurrentIndex(2)

    def _edit(self, cred: dict) -> None:
        self.editor.load_edit(cred)
        self.stack.setCurrentIndex(2)

    def has_unsaved_editor(self) -> bool:
        return self.stack.currentIndex() == 2 and self.editor.is_dirty()

    def _on_saved(self) -> None:
        service = self.editor.service.text().strip()
        username = self.editor.username.text().strip()
        self.refresh()
        target = next(
            (c for c in self._creds
             if c["service_name"].lower() == service.lower()
             and c["username"].lower() == username.lower()),
            None,
        )
        if target:
            self._selected_id = target["id"]
            self._select_by_id(target["id"])
        else:
            self.stack.setCurrentIndex(0)

    def _on_cancel(self) -> None:
        if self._selected_id and self._cred_by_id(self._selected_id):
            self.stack.setCurrentIndex(1)
        else:
            self.stack.setCurrentIndex(0)

    def _on_deleted(self) -> None:
        self._selected_id = None
        self.refresh()
        self.stack.setCurrentIndex(0)

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()
