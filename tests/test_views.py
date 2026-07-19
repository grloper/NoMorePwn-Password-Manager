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
class BackgroundTaskTests(unittest.TestCase):
    """`run_async` must deliver its callback without the caller holding the Task.

    It did not. Callers write `workers.run_async(work, done)` and drop the
    return value, so the Task and its `_Signals` QObject became unreachable
    immediately; if a GC landed before the worker finished, `done` never ran
    and the work could be cut short. That is how the breach scan came to sit
    at "Scanning… 17/17" forever while reporting nothing.
    """

    def _pump(self, predicate, seconds=10.0):
        import time

        deadline = time.time() + seconds
        while time.time() < deadline and not predicate():
            QApplication.processEvents()
            time.sleep(0.01)
        return predicate()

    def test_callback_fires_when_the_task_is_discarded(self):
        from nomorepwn_app import workers

        got = []
        workers.run_async(lambda: "value", got.append)   # return value dropped
        self.assertTrue(self._pump(lambda: bool(got)),
                        "callback never fired for a discarded Task")
        self.assertEqual(got, ["value"])

    def test_callback_survives_a_collection_mid_flight(self):
        import gc
        import time

        from nomorepwn_app import workers

        got = []

        def slow():
            time.sleep(0.3)
            return "late"

        workers.run_async(slow, got.append)
        gc.collect()
        self.assertTrue(self._pump(lambda: bool(got)),
                        "a garbage collection lost the callback")

    def test_long_task_runs_to_completion(self):
        import gc
        import time

        from nomorepwn_app import workers

        steps = []

        def work():
            for i in range(15):
                time.sleep(0.01)
                steps.append(i)
            return "done"

        got = []
        workers.run_async(work, got.append)
        for _ in range(4):
            gc.collect()
            QApplication.processEvents()
        self.assertTrue(self._pump(lambda: bool(got)))
        self.assertEqual(len(steps), 15, "the worker was cut short")

    def test_error_callback_also_fires_when_discarded(self):
        from nomorepwn_app import workers

        errs = []

        def boom():
            raise RuntimeError("kaboom")

        workers.run_async(boom, lambda r: None, errs.append)
        self.assertTrue(self._pump(lambda: bool(errs)))
        self.assertIsInstance(errs[0], RuntimeError)

    def test_finished_tasks_do_not_accumulate(self):
        from nomorepwn_app import workers

        got = []
        for i in range(5):
            workers.run_async(lambda i=i: i, got.append)
        self.assertTrue(self._pump(lambda: len(got) == 5), str(got))
        self.assertTrue(self._pump(lambda: not workers._INFLIGHT, 3.0),
                        f"keep-alive set leaked {len(workers._INFLIGHT)} tasks")


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class BreachScanTests(unittest.TestCase):
    """The bulk scan must always surface its findings."""

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
        self.vault.add_credential("a.com", "u", "breached-pw")
        self.vault.add_credential("b.com", "u", "clean-pw")

        self.toasts: list[tuple[str, str]] = []

        class _Toast:
            def show(_s, text, kind="info", ms=2000):
                self.toasts.append((kind, text))

        self.ctx = AppContext(
            settings=Settings(), toast=_Toast(), clipboard=ClipboardManager(),
            notify=lambda t, m: None, get_vault=lambda: self.vault,
        )

        from nomorepwn import leakcheck
        self._real_check = leakcheck.check_password
        leakcheck.check_password = lambda pw, timeout=10: 7 if pw == "breached-pw" else 0

    def tearDown(self):
        from nomorepwn import leakcheck
        leakcheck.check_password = self._real_check
        self.vault.lock()
        config_module.DB_PATH = self._real_db_path

    def _pump(self, predicate, seconds=15.0):
        import time

        deadline = time.time() + seconds
        while time.time() < deadline and not predicate():
            QApplication.processEvents()
            time.sleep(0.01)
        return predicate()

    def test_scan_completes_and_reports(self):
        from nomorepwn_app.view_audit import AuditView

        view = AuditView(self.ctx)
        view.set_vault(self.vault)
        view._render_report({"total": 2, "no_mfa": [], "stale": [], "weak": [],
                             "reused": [], "strengths": {}, "breached": []})
        view._scan_breaches()

        self.assertTrue(
            self._pump(lambda: view.breach_btn.text() == "Scan all for breaches"),
            f"scan never finished — button stuck at {view.breach_btn.text()!r}")
        self.assertEqual(view.card_breached.value.text(), "1")
        self.assertTrue(self.toasts, "no result was reported to the user")

    def test_findings_are_not_discarded_when_scanned_before_the_first_refresh(self):
        """Clicking Scan on a freshly opened dashboard used to throw the result away."""
        from nomorepwn_app.view_audit import AuditView

        view = AuditView(self.ctx)
        view.set_vault(self.vault)
        self.assertIsNone(view._report)

        view._scan_breaches()
        self.assertTrue(self._pump(lambda: view.card_breached.value.text() == "1"),
                        f"breached card shows {view.card_breached.value.text()!r}")

    def test_a_later_refresh_keeps_the_findings(self):
        from nomorepwn_app.view_audit import AuditView

        view = AuditView(self.ctx)
        view.set_vault(self.vault)
        view._scan_breaches()
        self.assertTrue(self._pump(lambda: view.card_breached.value.text() == "1"))

        view.refresh()
        self.assertTrue(self._pump(lambda: view.card_breached.value.text() == "1"),
                        "a refresh downgraded 'breached' back to zero")


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class CloseDialogTests(unittest.TestCase):
    """The X button's prompt — every path must actually do something.

    `_on_close_requested` compared `dlg.exec()` against `dlg.Accepted`. PySide6
    does not expose that enum on the *instance* (6.11 raises AttributeError),
    and an exception inside a slot is swallowed — so pressing X and choosing
    either option silently did nothing at all, with no error anywhere. The
    tray's Quit kept working because it calls `quit()` directly, which is
    exactly why this went unnoticed.
    """

    def setUp(self):
        from nomorepwn_app import theme
        theme.set_active(theme.get_palette("dark"))

    def test_dialog_code_is_reachable_the_way_the_controller_reads_it(self):
        from PySide6.QtWidgets import QDialog

        # The class form must work...
        self.assertEqual(int(QDialog.DialogCode.Accepted), 1)
        # ...and the instance form must NOT be relied on, because it raises.
        dlg = QDialog()
        self.assertFalse(hasattr(dlg, "Accepted"),
                         "PySide6 now exposes QDialog.Accepted on instances — "
                         "the comment in controller._on_close_requested is stale")

    def test_choosing_quit_accepts_the_dialog(self):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QDialog

        from nomorepwn.settings import CLOSE_QUIT
        from nomorepwn_app.dialogs import CloseChoiceDialog

        dlg = CloseChoiceDialog(None)
        QTimer.singleShot(0, lambda: dlg.quit_card.clicked.emit())
        result = dlg.exec()

        self.assertEqual(dlg.choice, CLOSE_QUIT)
        # The controller's exact condition must not bail out.
        self.assertFalse(result != QDialog.DialogCode.Accepted or dlg.choice is None,
                         "the controller would return early and never quit")

    def test_choosing_tray_accepts_the_dialog(self):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QDialog

        from nomorepwn.settings import CLOSE_TRAY
        from nomorepwn_app.dialogs import CloseChoiceDialog

        dlg = CloseChoiceDialog(None)
        QTimer.singleShot(0, lambda: dlg.tray_card.clicked.emit())
        result = dlg.exec()
        self.assertEqual(dlg.choice, CLOSE_TRAY)
        self.assertEqual(result, QDialog.DialogCode.Accepted)

    def test_cancelling_is_not_accepted(self):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QDialog

        from nomorepwn_app.dialogs import CloseChoiceDialog

        dlg = CloseChoiceDialog(None)
        QTimer.singleShot(0, dlg.reject)
        result = dlg.exec()
        self.assertNotEqual(result, QDialog.DialogCode.Accepted)
        self.assertIsNone(dlg.choice)

    def test_no_view_reads_a_dialog_enum_off_an_instance(self):
        """Smoke alarm, not a proof: scan for the pattern that broke this.

        `something.exec() != something.Accepted` raises AttributeError at
        runtime and the slot swallows it. Catch it in source instead.
        """
        import re

        app_dir = Path(__file__).resolve().parent.parent / "nomorepwn_app"
        # Owners that legitimately carry the enum as a class attribute.
        allowed = {"QDialog", "QMessageBox", "QFileDialog", "DialogCode"}
        pattern = re.compile(r"(\w+)\.(?:Accepted|Rejected)\b")
        offenders = []
        for path in app_dir.glob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]        # ignore prose in comments
                for owner in pattern.findall(code):
                    if owner not in allowed:
                        offenders.append(f"{path.name}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "read the enum off the class, not an instance:\n"
                                        + "\n".join(offenders))


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

    def test_editor_looks_different_when_adding_versus_editing(self):
        """Add and edit used to be visually identical."""
        cid = self.vault.add_credential("a.com", "u", "pw-123456")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)

        ed = self._editor()
        ed.load_new()
        add_state = (ed.mode_badge.text(), ed.title.text(),
                     ed.save_btn.text(), ed.cancel_btn.text())
        ed.load_edit(cred)
        edit_state = (ed.mode_badge.text(), ed.title.text(),
                      ed.save_btn.text(), ed.cancel_btn.text())

        self.assertNotEqual(add_state, edit_state, "add and edit look the same")
        self.assertEqual(add_state[0], "NEW")
        self.assertEqual(edit_state[0], "EDITING")
        self.assertIn("Discard new item", add_state[3])

    def test_invalid_service_name_shows_a_persistent_inline_error(self):
        """A toast auto-dismisses; that is how a rejected save gets missed."""
        ed = self._editor()
        ed.load_new()
        ed.service.setText("bad;name")          # ';' is still refused
        ed.username.setText("alice")
        ed.password.setText("pw-123456")
        ed._save()

        self.assertEqual(self.vault.list_credentials(), [], "saved despite being invalid")
        self.assertFalse(ed.error_bar.isHidden(), "no inline error was shown")
        self.assertIn(";", ed.error_bar.text(),
                      f"error does not name the offending character: {ed.error_bar.text()!r}")

    def test_fixing_the_error_clears_the_bar_and_saves(self):
        ed = self._editor()
        ed.load_new()
        ed.service.setText("bad;name")
        ed.username.setText("alice")
        ed.password.setText("pw-123456")
        ed._save()
        self.assertFalse(ed.error_bar.isHidden())

        ed.service.setText("Shopify (inactive account)")
        ed._save()
        self.assertTrue(ed.error_bar.isHidden(), "error bar survived a successful save")
        self.assertEqual(len(self.vault.list_credentials()), 1)

    def test_parenthesised_service_names_are_accepted(self):
        """The exact name that was rejected in the field."""
        ed = self._editor()
        ed.load_new()
        ed.service.setText("Shopify (inactive account)")
        ed.username.setText("alice")
        ed.password.setText("pw-123456")
        ed._save()
        self.assertEqual([c["service_name"] for c in self.vault.list_credentials()],
                         ["Shopify (inactive account)"])

    def test_an_open_item_can_be_closed(self):
        from nomorepwn_app.view_vault import VaultView

        self.vault.add_credential("a.com", "u", "pw-123456")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)
        cred = self.vault.list_credentials()[0]

        view._select_by_id(cred["id"])
        view.detail.show_credential(cred)
        view.stack.setCurrentIndex(1)
        self.assertEqual(view.stack.currentIndex(), 1)

        view.close_item()
        self.assertEqual(view.stack.currentIndex(), 0, "did not return to the empty state")
        self.assertIsNone(view._selected_id, "selection was left behind")
        self.assertEqual(view.list.selectedItems(), [], "row stayed highlighted")

    def test_closing_then_reopening_the_same_item_works(self):
        from nomorepwn_app.view_vault import VaultView

        self.vault.add_credential("a.com", "u", "pw-123456")
        view = VaultView(self.ctx)
        view.set_vault(self.vault)
        cred = self.vault.list_credentials()[0]

        view._select_by_id(cred["id"])
        view.close_item()
        # Re-selecting must open it again, not be swallowed as a no-op.
        view._select_by_id(cred["id"])
        self.assertEqual(view._selected_id, cred["id"])

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


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class RecoveryUiTests(unittest.TestCase):
    """Recovery-kit Settings section + the create/recover dialogs' logic."""

    def setUp(self):
        from nomorepwn_app import theme
        from nomorepwn_app.context import AppContext
        from nomorepwn_app.util import ClipboardManager
        from nomorepwn.settings import Settings

        theme.set_active(theme.get_palette("dark"))
        self.tmp = tempfile.mkdtemp()
        self._real_db_path = config_module.DB_PATH
        config_module.DB_PATH = Path(self.tmp) / "vault.db"
        self.db_path = str(config_module.DB_PATH)
        vault.create_vault(config_module.DB_PATH, MASTER)
        self.vault = vault.Vault.unlock(config_module.DB_PATH, MASTER)
        self.cid = self.vault.add_credential("github.com", "alice", "s3cret-pass", "n")

        self.toasts: list[tuple[str, str]] = []

        class _Toast:
            def show(_s, text, kind="info", ms=2000):
                self.toasts.append((kind, text))

        self.ctx = AppContext(
            settings=Settings(), toast=_Toast(), clipboard=ClipboardManager(),
            notify=lambda t, m: None, get_vault=lambda: self.vault,
        )

    def tearDown(self):
        try:
            self.vault.lock()
        except Exception:
            pass
        config_module.DB_PATH = self._real_db_path

    def test_settings_view_has_a_recovery_button(self):
        from nomorepwn_app.view_settings import SettingsView

        view = SettingsView(self.ctx, on_change=lambda: None)
        self.assertTrue(hasattr(view, "recovery_btn"))
        self.assertIn("recovery", view.recovery_btn.text().lower())

    def test_unlock_view_offers_recovery(self):
        from nomorepwn_app.view_unlock import UnlockView

        view = UnlockView(self.db_path, self.ctx.toast)
        self.assertTrue(hasattr(view, "recover_btn"))

    def test_kit_dialog_builds_and_writes_an_openable_kit(self):
        from nomorepwn_app.recovery_dialog import RecoveryKitDialog
        from nomorepwn import recovery

        dlg = RecoveryKitDialog(None, lambda: self.vault, self.ctx)
        result = dlg.build(recovery.MODE_KIT)
        self.assertIn("recovery_code", result)
        self.assertNotIn("totp_secret", result)
        kit_file = Path(self.tmp) / "k.nmpkit"
        dlg.write_kit(kit_file)
        # The written kit opens this vault with the code the dialog produced.
        self.vault.lock()
        rv = vault.Vault.unlock_with_recovery(
            self.db_path, kit_file.read_bytes(), result["recovery_code"])
        self.assertEqual(rv.reveal_password(self.cid), "s3cret-pass")

    def test_kit_dialog_totp_mode_includes_a_seed(self):
        from nomorepwn_app.recovery_dialog import RecoveryKitDialog
        from nomorepwn import recovery

        dlg = RecoveryKitDialog(None, lambda: self.vault, self.ctx)
        result = dlg.build(recovery.MODE_KIT_TOTP)
        self.assertIn("totp_secret", result)
        self.assertTrue(result["totp_uri"].startswith("otpauth://"))

    def test_recover_dialog_recovers_and_rekeys(self):
        from nomorepwn_app.recovery_dialog import RecoverDialog
        from nomorepwn import recovery

        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        self.vault.lock()
        dlg = RecoverDialog(None, self.db_path)
        NEW = "a fresh master password"
        recovered = dlg.recover(kit["kit_bytes"], kit["recovery_code"], "", NEW, NEW)
        self.assertEqual(recovered.reveal_password(self.cid), "s3cret-pass")
        # The vault is now under the new password.
        self.assertEqual(
            vault.Vault.unlock(self.db_path, NEW).reveal_password(self.cid), "s3cret-pass")

    def test_recover_dialog_rejects_bad_input(self):
        from nomorepwn_app.recovery_dialog import RecoverDialog
        from nomorepwn import recovery

        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        self.vault.lock()
        dlg = RecoverDialog(None, self.db_path)
        # No kit chosen.
        with self.assertRaises(recovery.RecoveryError):
            dlg.recover(None, kit["recovery_code"], "", "long enough pw", "long enough pw")
        # Password mismatch.
        with self.assertRaises(vault.VaultError):
            dlg.recover(kit["kit_bytes"], kit["recovery_code"], "", "long enough pw", "different")
        # Too-short password.
        with self.assertRaises(vault.VaultError):
            dlg.recover(kit["kit_bytes"], kit["recovery_code"], "", "short", "short")
        # Wrong recovery code.
        wrong = recovery.encode_recovery_code(recovery.generate_recovery_key())
        with self.assertRaises(recovery.RecoveryError):
            dlg.recover(kit["kit_bytes"], wrong, "", "long enough pw", "long enough pw")


if __name__ == "__main__":
    unittest.main()
