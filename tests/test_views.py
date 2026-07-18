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
