"""Clipboard handling for copied secrets."""
import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from nomorepwn_app.util import ClipboardManager, secret_mime_data


class ClipboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_mime_excludes_from_history_and_cloud(self):
        m = secret_mime_data("hunter2-secret")
        self.assertEqual(m.text(), "hunter2-secret")
        self.assertEqual(bytes(m.data("CanIncludeInClipboardHistory")), b"\0\0\0\0")
        self.assertEqual(bytes(m.data("CanUploadToCloudClipboard")), b"\0\0\0\0")
        self.assertEqual(bytes(m.data("ExcludeClipboardContentFromMonitorProcessing")), b"\1\0\0\0")

    def test_copy_then_wipe_only_if_unchanged(self):
        cm = ClipboardManager()
        cm.copy("abc-secret", 0)
        self.assertEqual(self.app.clipboard().text(), "abc-secret")
        cm._wipe()
        self.assertEqual(self.app.clipboard().text(), "")
        cm.copy("abc-secret", 0)
        self.app.clipboard().setText("user-copied-something-else")
        cm._wipe()
        self.assertEqual(self.app.clipboard().text(), "user-copied-something-else")


if __name__ == "__main__":
    unittest.main()
