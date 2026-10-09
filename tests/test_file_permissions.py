"""Vault and backup files must be owner-only (0600) on POSIX."""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from nomorepwn import db, vault

MASTER = "correct horse battery staple 42"


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@unittest.skipIf(sys.platform == "win32", "POSIX permission bits are not enforced on Windows")
class VaultFilePermissionTests(unittest.TestCase):
    def setUp(self):
        self._old_umask = os.umask(0o022)  # the common default that yields 0644
        self.addCleanup(os.umask, self._old_umask)
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "vault.db"

    def test_new_vault_is_0600_even_with_a_permissive_umask(self):
        vault.create_vault(self.path, MASTER)
        self.assertEqual(_mode(self.path), 0o600)

    def test_new_vault_is_0600_under_umask_000(self):
        os.umask(0)
        vault.create_vault(self.path, MASTER)
        self.assertEqual(_mode(self.path), 0o600)

    def test_existing_loose_vault_is_tightened_on_open(self):
        vault.create_vault(self.path, MASTER)
        os.chmod(self.path, 0o644)
        v = vault.Vault.unlock(self.path, MASTER)
        v.lock()
        self.assertEqual(_mode(self.path), 0o600)

    def test_checking_for_a_missing_vault_does_not_create_it(self):
        self.assertFalse(vault.vault_exists(self.path))
        self.assertFalse(self.path.exists())

    def test_vault_still_works_after_permission_fix(self):
        vault.create_vault(self.path, MASTER)
        v = vault.Vault.unlock(self.path, MASTER)
        v.add_credential("example.com", "alice", "hunter2-hunter2")
        self.assertEqual(len(v.list_credentials()), 1)
        v.lock()

    def test_premigration_and_rekey_copies_are_private(self):
        vault.create_vault(self.path, MASTER)
        v = vault.Vault.unlock(self.path, MASTER)
        v.rekey("another correct horse battery staple")
        v.lock()
        snap = vault.pre_rekey_backup_path(self.path)
        self.assertTrue(snap.exists())
        self.assertEqual(_mode(snap), 0o600)
        self.assertEqual(_mode(self.path), 0o600)

    def test_encrypted_backup_and_restore_are_private(self):
        vault.create_vault(self.path, MASTER)
        v = vault.Vault.unlock(self.path, MASTER)
        out = self.tmp / "b.nmpbak"
        v.write_backup(out)
        v.lock()
        self.assertEqual(_mode(out), 0o600)

    def test_symlink_target_is_not_chmodded(self):
        target = self.tmp / "elsewhere.db"
        target.write_bytes(b"")
        os.chmod(target, 0o644)
        link = self.tmp / "link.db"
        link.symlink_to(target)
        db.secure_file(link)
        self.assertEqual(_mode(target), 0o644)

    def test_write_private_overwrites_loose_file_privately(self):
        p = self.tmp / "x.bin"
        p.write_bytes(b"old")
        os.chmod(p, 0o666)
        db.write_private(p, b"new")
        self.assertEqual(p.read_bytes(), b"new")
        self.assertEqual(_mode(p), 0o600)


if __name__ == "__main__":
    unittest.main()
