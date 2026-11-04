"""Authentication of the local IPC channel used for single-instance show."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from nomorepwn import config, ipc_auth


class _TempData(unittest.TestCase):
    def setUp(self):
        self._real = config.DATA_DIR
        self.tmp = Path(tempfile.mkdtemp())
        config.DATA_DIR = self.tmp / "data"

    def tearDown(self):
        config.DATA_DIR = self._real


class TokenTests(_TempData):
    def test_token_is_random_hex_and_stable(self):
        a = ipc_auth.load_or_create_token()
        self.assertEqual(len(a), 64)
        int(a, 16)
        self.assertEqual(ipc_auth.load_or_create_token(), a)
        self.assertEqual(ipc_auth.read_token(), a)

    def test_tokens_differ_per_install(self):
        a = ipc_auth.load_or_create_token()
        ipc_auth.token_path().unlink()
        self.assertNotEqual(ipc_auth.load_or_create_token(), a)

    @unittest.skipIf(sys.platform == "win32", "POSIX modes not enforced on Windows")
    def test_token_file_is_user_only(self):
        ipc_auth.load_or_create_token()
        self.assertEqual(stat.S_IMODE(os.stat(ipc_auth.token_path()).st_mode), 0o600)

    @unittest.skipIf(sys.platform == "win32", "POSIX modes not enforced on Windows")
    def test_loose_existing_token_perms_are_tightened(self):
        ipc_auth.load_or_create_token()
        os.chmod(ipc_auth.token_path(), 0o644)
        ipc_auth.load_or_create_token()
        self.assertEqual(stat.S_IMODE(os.stat(ipc_auth.token_path()).st_mode), 0o600)

    def test_read_token_never_creates(self):
        self.assertIsNone(ipc_auth.read_token())
        self.assertFalse(ipc_auth.token_path().exists())

    def test_malformed_token_file_is_ignored(self):
        config.DATA_DIR.mkdir(parents=True)
        ipc_auth.token_path().write_text("short")
        self.assertIsNone(ipc_auth.read_token())

    def test_verify(self):
        tok = ipc_auth.load_or_create_token()
        self.assertTrue(ipc_auth.verify(tok))
        self.assertFalse(ipc_auth.verify(tok[:-1] + ("0" if tok[-1] != "0" else "1")))
        for bad in (None, "", 5, b"x", [tok], tok + "x"):
            self.assertFalse(ipc_auth.verify(bad))

    def test_verify_fails_closed_without_stored_token(self):
        self.assertFalse(ipc_auth.verify("a" * 64))
        self.assertFalse(ipc_auth.verify(""))


try:
    from nomorepwn_app.controller import AppController
    HAS_QT = True
except Exception:  # pragma: no cover
    HAS_QT = False


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class ControllerAuthTests(_TempData):
    """Drives the real handler on a stub ``self`` (no windows/tray are built)."""

    def setUp(self):
        super().setUp()
        self.token = ipc_auth.load_or_create_token()
        self.stub = MagicMock()

    def _call(self, raw):
        return AppController.handle_ipc_message(self.stub, raw)

    def _send(self, raw):
        return json.loads(self._call(raw).decode())

    def test_unauthenticated_messages_are_rejected(self):
        for msg in (
            {"type": "show"},
            {"type": "show", "token": "wrong"},
            {"type": "show", "token": 123},
        ):
            self.assertEqual(self._send(json.dumps(msg).encode())["code"], "unauthorized")
        self.stub.show_window.assert_not_called()

    def test_legacy_bare_show_is_rejected(self):
        self.assertEqual(self._send(b"show")["code"], "bad-json")
        self.stub.show_window.assert_not_called()

    def test_authenticated_show_works(self):
        out = self._call(json.dumps({"type": "show", "token": self.token}).encode())
        self.assertEqual(out, b"ok")
        self.stub.show_window.assert_called_once()

    def test_unknown_authenticated_type_is_ignored(self):
        out = self._call(json.dumps({"type": "save-credential", "token": self.token}).encode())
        self.assertIsNone(out)
