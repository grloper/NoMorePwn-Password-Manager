"""Headless smoke tests for the PySide6 views.

`nomorepwn_app/` had no test coverage: CI builds and publishes an .exe that
has never been executed. These do not test appearance — they catch the class
of failure that actually happens here, where a view raises on construction or
a status label silently reports the wrong thing.

Qt runs under the `offscreen` platform plugin, so this needs no display and
works in CI. `QT_QPA_PLATFORM` must be set before QApplication is created,
which is why it is set at import time below.

Run just these:  python -m unittest tests.test_views -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must precede any QApplication construction.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    HAS_QT = True
except ImportError:  # pragma: no cover - PySide6 is optional for core tests
    HAS_QT = False

from nomorepwn import config as config_module
from nomorepwn import vault

MASTER = "correct horse battery staple 42"

_app = None


def setUpModule() -> None:
    """One QApplication for the whole module; Qt allows only one per process."""
    global _app
    if HAS_QT:
        _app = QApplication.instance() or QApplication([])


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class ViewSmokeTests(unittest.TestCase):
    """Every top-level view must construct against a real unlocked vault."""

    def setUp(self):
        from nomorepwn_app import theme
        from nomorepwn_app.context import AppContext
        from nomorepwn_app.util import ClipboardManager

        theme.set_active(theme.get_palette("dark"))

        self.tmp = tempfile.mkdtemp()
        self._real_db_path = config_module.DB_PATH
        config_module.DB_PATH = Path(self.tmp) / "vault.db"
        vault.create_vault(config_module.DB_PATH, MASTER)
        self.vault = vault.Vault.unlock(config_module.DB_PATH, MASTER)
        self.vault.add_credential("github.com", "alice", "s3cret-pass")

        self.toasts: list[tuple[str, str]] = []

        class _Toast:
            def show(_s, text, kind="info", ms=2000):
                self.toasts.append((kind, text))

        from nomorepwn.settings import Settings

        self.ctx = AppContext(
            settings=Settings(),
            toast=_Toast(),
            clipboard=ClipboardManager(),
            notify=lambda title, msg: None,
            get_vault=lambda: self.vault,
        )

    def tearDown(self):
        self.vault.lock()
        config_module.DB_PATH = self._real_db_path

    def test_vault_view_constructs(self):
        from nomorepwn_app.view_vault import VaultView

        VaultView(self.ctx)

    def test_generator_view_constructs(self):
        from nomorepwn_app.view_generator import GeneratorView

        GeneratorView(self.ctx)

    def test_audit_view_renders_a_report(self):
        from nomorepwn_app.view_audit import AuditView

        view = AuditView(self.ctx)
        view.set_vault(self.vault)
        # Render synchronously rather than via run_async, so the assertion is
        # about the rendering logic and not about thread timing.
        report = {
            "total": 1, "no_mfa": [], "stale": [], "weak": [],
            "reused": [], "strengths": {}, "breached": [],
        }
        view._render_report(report)
        self.assertEqual(view.card_total.value.text(), "1")
        self.assertEqual(view.card_breached.value.text(), "0")

    def test_audit_scan_with_no_credentials_does_not_start(self):
        from nomorepwn_app.view_audit import AuditView

        empty = vault.Vault.unlock(config_module.DB_PATH, MASTER)
        for cred in empty.list_credentials():
            empty.delete_credential(cred["id"])

        view = AuditView(self.ctx)
        view.set_vault(empty)
        view._scan_breaches()
        self.assertTrue(any("Nothing to scan" in t for _k, t in self.toasts), self.toasts)
        # The button must not be left disabled/mid-scan.
        self.assertTrue(view.breach_btn.isEnabled())
        empty.lock()

    def test_generator_copy_button_works_on_every_panel(self):
        """The Copy button used to be wired by the *call site*.

        The standalone Generator page connected it; the editor's inline panel
        did not, so the same button worked on one screen and was dead on the
        other. Assert both, or the next panel repeats it.
        """
        from nomorepwn_app.editor import CredentialEditor
        from nomorepwn_app.view_generator import GeneratorView

        # Hold the parents: a temporary would be collected and take its child
        # panel down with it ("Signal source has been deleted").
        gen_view = GeneratorView(self.ctx)
        editor = CredentialEditor(lambda: self.vault, self.ctx)

        for label, panel in (
            ("standalone generator", gen_view.panel),
            ("editor inline panel", editor.generator),
        ):
            with self.subTest(panel=label):
                seen: list[str] = []
                panel.copied.connect(seen.append)
                self.toasts.clear()

                panel.copy_btn.click()

                secret = panel.value()
                self.assertTrue(secret, f"{label}: generator produced nothing to copy")
                self.assertEqual(seen, [secret], f"{label}: Copy button did nothing")
                self.assertTrue(
                    any("copied" in text.lower() for _kind, text in self.toasts),
                    f"{label}: no 'Copied' feedback shown — toasts={self.toasts}",
                )

    def test_generator_copy_is_a_noop_when_there_is_nothing_to_copy(self):
        from nomorepwn_app.view_generator import GeneratorView

        view = GeneratorView(self.ctx)   # held: see the note above
        panel = view.panel
        seen: list[str] = []
        panel.copied.connect(seen.append)
        panel.output.setText("")
        panel.copy_btn.click()
        self.assertEqual(seen, [], "copied an empty value")


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class CredentialGroupUiTests(unittest.TestCase):
    """The group picker and the grouped list, driven headlessly."""

    def setUp(self):
        from nomorepwn.settings import Settings
        from nomorepwn_app import theme
        from nomorepwn_app.context import AppContext
        from nomorepwn_app.util import ClipboardManager

        theme.set_active(theme.get_palette("dark"))
        self.tmp = tempfile.mkdtemp()
        self._real_db_path = config_module.DB_PATH
        config_module.DB_PATH = Path(self.tmp) / "vault.db"
        vault.create_vault(config_module.DB_PATH, MASTER)
        self.vault = vault.Vault.unlock(config_module.DB_PATH, MASTER)
        self.toasts: list[tuple[str, str]] = []

        class _Toast:
            def show(_s, text, kind="info", ms=2000):
                self.toasts.append((kind, text))

        self.ctx = AppContext(
            settings=Settings(), toast=_Toast(), clipboard=ClipboardManager(),
            notify=lambda t, m: None, get_vault=lambda: self.vault,
        )

    def tearDown(self):
        self.vault.lock()
        config_module.DB_PATH = self._real_db_path

    def _editor(self):
        from nomorepwn_app.editor import CredentialEditor
        return CredentialEditor(lambda: self.vault, self.ctx)

    def test_editor_offers_suggested_groups(self):
        from nomorepwn import groups

        ed = self._editor()
        ed.load_new()
        offered = [ed.group.itemText(i) for i in range(ed.group.count())]
        for name in groups.SUGGESTED_GROUPS:
            self.assertIn(name, offered)
        self.assertEqual(offered[0], "", "no ungrouped option")

    def test_editor_suggests_a_group_from_a_known_service(self):
        ed = self._editor()
        ed.load_new()
        ed.service.setText("steampowered.com")
        ed._suggest_group_for_service()
        self.assertEqual(ed.group.currentText(), "Gaming")

    def test_suggestion_never_overwrites_a_chosen_group(self):
        ed = self._editor()
        ed.load_new()
        ed.group.setCurrentText("My Own Group")
        ed.service.setText("gmail.com")
        ed._suggest_group_for_service()
        self.assertEqual(ed.group.currentText(), "My Own Group")

    def test_saving_stores_a_custom_group(self):
        ed = self._editor()
        ed.load_new()
        ed.service.setText("intranet.local")
        ed.username.setText("alice")
        ed.password.setText("pw-123456")
        ed.group.setCurrentText("Homelab")
        ed._save()
        cred = next(c for c in self.vault.list_credentials()
                    if c["service_name"] == "intranet.local")
        self.assertEqual(cred["group_name"], "Homelab")

    def test_editing_an_item_keeps_its_group(self):
        cid = self.vault.add_credential("gmail.com", "bob", "pw-123456", group_name="Email")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        ed = self._editor()
        ed.load_edit(cred)
        self.assertEqual(ed.group.currentText(), "Email")
        ed.mfa.setChecked(True)          # change something else entirely
        ed._save()
        after = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(after["group_name"], "Email")

    def test_existing_custom_groups_appear_in_the_picker(self):
        self.vault.add_credential("a.com", "u", "pw-123456", group_name="Homelab")
        ed = self._editor()
        ed.load_new()
        offered = [ed.group.itemText(i) for i in range(ed.group.count())]
        self.assertIn("Homelab", offered)

    def test_invalid_group_is_reported_and_nothing_is_saved(self):
        ed = self._editor()
        ed.load_new()
        ed.service.setText("example.com")
        ed.username.setText("alice")
        ed.password.setText("pw-123456")
        ed.group.setCurrentText("-bad start")
        ed._save()
        self.assertEqual(self.vault.list_credentials(), [])
        self.assertTrue(any(k == "error" for k, _t in self.toasts), self.toasts)

    def test_alternate_login_is_hidden_until_asked_for(self):
        ed = self._editor()
        ed.load_new()
        self.assertTrue(ed.alt_row.isHidden(), "second field shown unprompted")
        ed.alt_toggle.click()
        self.assertFalse(ed.alt_row.isHidden())
        self.assertIn("Remove", ed.alt_toggle.text())

    def test_alternate_login_saves_and_reloads(self):
        ed = self._editor()
        ed.load_new()
        ed.service.setText("steampowered.com")
        ed.username.setText("ofek")
        ed.password.setText("pw-123456")
        ed.alt_toggle.click()
        ed.alt_login.setText("ofek@gmail.com")
        ed._save()

        cred = next(c for c in self.vault.list_credentials()
                    if c["service_name"] == "steampowered.com")
        self.assertEqual(cred["alt_login"], "ofek@gmail.com")

        ed2 = self._editor()
        ed2.load_edit(cred)
        self.assertFalse(ed2.alt_row.isHidden(), "existing alternate not shown on edit")
        self.assertEqual(ed2.alt_login.text(), "ofek@gmail.com")

    def test_toggling_off_clears_the_alternate_login(self):
        cid = self.vault.add_credential("a.com", "u", "pw-123456", alt_login="me@x.com")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        ed = self._editor()
        ed.load_edit(cred)
        ed.alt_toggle.click()          # hide == remove
        ed._save()
        after = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(after["alt_login"], "")

    def test_editing_something_else_keeps_the_alternate(self):
        cid = self.vault.add_credential("a.com", "u", "pw-123456", alt_login="me@x.com")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        ed = self._editor()
        ed.load_edit(cred)
        ed.mfa.setChecked(True)
        ed._save()
        after = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(after["alt_login"], "me@x.com")

    def test_username_autocomplete_is_populated_from_the_vault(self):
        self.vault.add_credential("a.com", "me@gmail.com", "pw-123456")
        self.vault.add_credential("b.com", "handle", "pw-123456", alt_login="alt@x.com")
        ed = self._editor()
        ed.load_new()
        offered = ed._identifier_model.stringList()
        for expected in ("me@gmail.com", "handle", "alt@x.com"):
            self.assertIn(expected, offered)
        self.assertIsNotNone(ed.username.completer())

    def test_autocomplete_never_offers_a_password(self):
        self.vault.add_credential("a.com", "me@gmail.com", "sup3r-s3cret-pw")
        ed = self._editor()
        ed.load_new()
        self.assertNotIn("sup3r-s3cret-pw", ed._identifier_model.stringList())

    def test_detail_view_shows_and_hides_the_alternate(self):
        from PySide6.QtWidgets import QLabel

        from nomorepwn_app.detail import CredentialDetail, _Field

        def labels(cred):
            view = CredentialDetail(lambda: self.vault, self.ctx)
            view.show_credential(cred)
            return [f.findChildren(QLabel)[0].text()
                    for f in view.findChildren(_Field)]

        cid = self.vault.add_credential("a.com", "u", "pw-123456", alt_login="me@x.com")
        with_alt = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertIn("ALTERNATE LOGIN", labels(with_alt))

        cid2 = self.vault.add_credential("b.com", "u2", "pw-123456")
        without = next(c for c in self.vault.list_credentials() if c["id"] == cid2)
        self.assertNotIn("ALTERNATE LOGIN", labels(without),
                         "empty alternate rendered an empty field")

    def test_search_matches_the_alternate_login(self):
        from nomorepwn_app.view_vault import VaultView, _ItemRow

        self.vault.add_credential("a.com", "handle1", "pw-123456", alt_login="me@gmail.com")
        self.vault.add_credential("b.com", "handle2", "pw-123456")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)
        view.search.setText("me@gmail")
        items = [view.list.itemWidget(view.list.item(i))
                 for i in range(view.list.count())]
        self.assertEqual(len([i for i in items if isinstance(i, _ItemRow)]), 1)

    def test_list_renders_group_headers_above_their_items(self):
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QLabel

        from nomorepwn_app.view_vault import VaultView, _GroupHeader, _ItemRow

        self.vault.add_credential("gmail.com", "a", "pw-123456", group_name="Email")
        self.vault.add_credential("steampowered.com", "b", "pw-123456", group_name="Gaming")
        self.vault.add_credential("nogroup.com", "c", "pw-123456")

        view = VaultView(self.ctx)
        view.set_vault(self.vault)

        seen = []
        for i in range(view.list.count()):
            widget = view.list.itemWidget(view.list.item(i))
            if isinstance(widget, _GroupHeader):
                seen.append(("header", widget.name_label.text()))
            elif isinstance(widget, _ItemRow):
                seen.append(("item", view.list.item(i).data(Qt.UserRole)))

        headers = [text for kind, text in seen if kind == "header"]
        self.assertEqual(headers, ["EMAIL", "GAMING", "UNGROUPED"], seen)
        self.assertEqual(seen[0][0], "header", "list must open with a header")
        self.assertEqual(len([k for k, _ in seen if k == "item"]), 3)

    def test_group_headers_are_not_selectable(self):
        from PySide6.QtCore import Qt

        from nomorepwn_app.view_vault import VaultView, _GroupHeader

        self.vault.add_credential("gmail.com", "a", "pw-123456", group_name="Email")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)
        for i in range(view.list.count()):
            item = view.list.item(i)
            if isinstance(view.list.itemWidget(item), _GroupHeader):
                self.assertFalse(
                    bool(item.flags() & Qt.ItemIsSelectable),
                    "a header is selectable — arrow keys would land on a non-item")

    def _grouped_view(self):
        from nomorepwn_app.view_vault import VaultView

        self.vault.add_credential("gmail.com", "a", "pw-123456", group_name="Email")
        self.vault.add_credential("outlook.com", "b", "pw-123456", group_name="Email")
        self.vault.add_credential("steampowered.com", "c", "pw-123456", group_name="Gaming")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)
        return view

    def _visible_items(self, view):
        from nomorepwn_app.view_vault import _ItemRow

        return [view.list.itemWidget(view.list.item(i))
                for i in range(view.list.count())
                if isinstance(view.list.itemWidget(view.list.item(i)), _ItemRow)]

    def _header(self, view, label):
        from nomorepwn_app.view_vault import _GroupHeader
        from PySide6.QtWidgets import QLabel

        for i in range(view.list.count()):
            w = view.list.itemWidget(view.list.item(i))
            if isinstance(w, _GroupHeader) and w.name_label.text() == label:
                return w
        return None

    def test_clicking_a_group_header_collapses_it(self):
        view = self._grouped_view()
        self.assertEqual(len(self._visible_items(view)), 3)

        self._header(view, "EMAIL").toggled.emit()

        # The two Email rows are gone; Gaming's row stays.
        self.assertEqual(len(self._visible_items(view)), 1)
        self.assertIsNotNone(self._header(view, "EMAIL"), "header vanished with its items")
        self.assertIsNotNone(self._header(view, "GAMING"))

    def test_collapsing_is_reversible(self):
        view = self._grouped_view()
        self._header(view, "EMAIL").toggled.emit()
        self.assertEqual(len(self._visible_items(view)), 1)
        self._header(view, "EMAIL").toggled.emit()
        self.assertEqual(len(self._visible_items(view)), 3)

    def test_collapsed_group_still_reports_its_true_count(self):
        from PySide6.QtWidgets import QLabel

        view = self._grouped_view()
        self._header(view, "EMAIL").toggled.emit()
        tally = self._header(view, "EMAIL").count_label.text()
        self.assertEqual(tally, "2", "collapsed group hid how many items it holds")

    def test_collapse_survives_a_refresh(self):
        view = self._grouped_view()
        self._header(view, "EMAIL").toggled.emit()
        view.refresh()
        self.assertEqual(len(self._visible_items(view)), 1, "refresh forgot the collapse")

    def test_searching_reveals_matches_inside_collapsed_groups(self):
        """A hit hidden in a collapsed group reads as 'no results'."""
        view = self._grouped_view()
        self._header(view, "EMAIL").toggled.emit()
        self.assertEqual(len(self._visible_items(view)), 1)

        view.search.setText("gmail")
        self.assertEqual(len(self._visible_items(view)), 1)
        self.assertIsNotNone(self._header(view, "EMAIL"))

        # Clearing the search restores the collapsed state.
        view.search.setText("")
        self.assertEqual(len(self._visible_items(view)), 1)

    def test_search_matches_group_names(self):
        from nomorepwn_app.view_vault import VaultView, _ItemRow

        self.vault.add_credential("gmail.com", "a", "pw-123456", group_name="Email")
        self.vault.add_credential("steampowered.com", "b", "pw-123456", group_name="Gaming")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)

        view.search.setText("gaming")
        rows = [view.list.itemWidget(view.list.item(i))
                for i in range(view.list.count())]
        items = [r for r in rows if isinstance(r, _ItemRow)]
        self.assertEqual(len(items), 1, "search did not filter by group")


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class SettingsExtensionSectionTests(unittest.TestCase):
    """The browser-extension card must report connection state truthfully."""

    def setUp(self):
        from nomorepwn_app import theme
        from nomorepwn_app.context import AppContext
        from nomorepwn_app.util import ClipboardManager
        from nomorepwn.settings import Settings

        theme.set_active(theme.get_palette("dark"))
        self.toasts: list[tuple[str, str]] = []

        class _Toast:
            def show(_s, text, kind="info", ms=2000):
                self.toasts.append((kind, text))

        self.ctx = AppContext(
            settings=Settings(),
            toast=_Toast(),
            clipboard=ClipboardManager(),
            notify=lambda title, msg: None,
            get_vault=lambda: None,
        )

    def test_settings_view_constructs_and_reports_extension_state(self):
        from nomorepwn_app.view_settings import SettingsView
        from nomorepwn_app import browser_bridge

        view = SettingsView(self.ctx, on_change=lambda: None)
        self.assertTrue(view.ext_status.text())
        # The load-unpacked instructions must name the real folder, or the
        # user is told to select a path that does not exist.
        self.assertIn(str(browser_bridge.extension_dir()), view.ext_steps.text())

    def test_update_section_reports_the_running_version(self):
        from nomorepwn_app import __version__
        from nomorepwn_app.view_settings import SettingsView

        view = SettingsView(self.ctx, on_change=lambda: None)
        self.assertIn(__version__, view.update_status.text())
        # Nothing is downloaded, so there must be no install affordance.
        self.assertFalse(view.update_install_btn.isVisible())


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class UpdateApplyOrderingTests(unittest.TestCase):
    """The vault must be locked BEFORE the installer process starts.

    The installer replaces the running .exe and restarts it. If the key is
    still in memory when it runs, the master key is live across a process
    teardown that is concurrently rewriting the binary.
    """

    def test_lock_runs_before_the_installer_launches(self):
        from nomorepwn_app.update_manager import UpdateManager
        from nomorepwn.settings import Settings

        events: list[str] = []
        mgr = UpdateManager(Settings())

        tmp = Path(tempfile.mkdtemp()) / "NoMorePwn-Setup.exe"
        tmp.write_bytes(b"not a real installer")

        import subprocess as sp

        real_popen = sp.Popen

        def fake_popen(*a, **kw):
            events.append("installer-launched")

            class _P:
                pid = 1234
            return _P()

        sp.Popen = fake_popen
        try:
            started = mgr.apply(tmp, lambda: events.append("vault-locked"))
        finally:
            sp.Popen = real_popen

        self.assertTrue(started)
        self.assertEqual(events, ["vault-locked", "installer-launched"],
                         "the vault must be locked before the installer runs")

    def test_missing_installer_is_refused_without_locking(self):
        from nomorepwn_app.update_manager import UpdateManager
        from nomorepwn.settings import Settings

        events: list[str] = []
        mgr = UpdateManager(Settings())
        missing = Path(tempfile.mkdtemp()) / "nope.exe"
        self.assertFalse(mgr.apply(missing, lambda: events.append("locked")))
        self.assertEqual(events, [])

    def test_dev_build_never_starts_periodic_checks(self):
        """A source checkout has no installer to replace."""
        from nomorepwn_app.update_manager import UpdateManager
        from nomorepwn.settings import Settings

        mgr = UpdateManager(Settings())
        mgr.start()
        self.assertFalse(mgr._timer.isActive())


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class ExtensionIdTests(unittest.TestCase):
    def test_pinned_extension_id_matches_the_committed_manifest_key(self):
        """A mismatch reports "Connected" while refusing every connection."""
        import base64
        import hashlib
        import json

        from nomorepwn_app import browser_bridge

        manifest = json.loads(
            (Path(__file__).resolve().parent.parent / "extension" / "manifest.json")
            .read_text(encoding="utf-8"))
        der = base64.b64decode(manifest["key"])
        derived = "".join(
            chr(ord("a") + int(c, 16)) for c in hashlib.sha256(der).hexdigest()[:32])
        self.assertEqual(derived, browser_bridge.EXTENSION_ID)


if __name__ == "__main__":
    unittest.main()
