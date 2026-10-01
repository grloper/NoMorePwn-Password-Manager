"""Synthetic vault adversarial lifecycle tests; no live profile access."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from nomorepwn import crypto, db, vault

MASTER = "synthetic master password 2026"

class SessionSecurityTests(unittest.TestCase):
    def test_lock_during_rekey_keeps_session_revoked_and_data_recoverable(self):
        new_master = "different synthetic master password"
        for pause_at in ("snapshot", "derivation", "publication"):
            with self.subTest(pause_at=pause_at), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "vault.db"
                vault.create_vault(path, MASTER)
                session = vault.Vault.unlock(path, MASTER)
                identifier = session.add_credential(
                    "example.test", "synthetic", "SyntheticPassword42!", notes="Synthetic note")
                session.update_password(identifier, "SyntheticPassword43!")
                session.set_backup_passphrase("synthetic backup passphrase")
                backup_key = session.backup_material()["key"]
                entered = threading.Event()
                resume = threading.Event()
                errors = []
                target, name = ((db, "snapshot_bytes") if pause_at == "snapshot"
                                else (crypto, "derive_key"))
                original = getattr(target, name)

                def paused(*args, **kwargs):
                    entered.set()
                    if not resume.wait(15):
                        raise AssertionError("rekey was not released")
                    return original(*args, **kwargs)

                def rekey():
                    try:
                        session.rekey(new_master)
                    except BaseException as exc:
                        errors.append(exc)

                if pause_at == "publication":
                    state_lock = session._state_lock

                    class PausePublication:
                        entries = 0

                        def __enter__(self):
                            if threading.current_thread() is worker:
                                self.entries += 1
                                if self.entries == 2:
                                    entered.set()
                                    if not resume.wait(15):
                                        raise AssertionError("publication was not released")
                            return state_lock.__enter__()

                        def __exit__(self, *args):
                            return state_lock.__exit__(*args)

                    patch = mock.patch.object(session, "_state_lock", PausePublication())
                else:
                    patch = mock.patch.object(target, name, paused)

                with patch:
                    worker = threading.Thread(target=rekey)
                    worker.start()
                    try:
                        self.assertTrue(entered.wait(15), "rekey did not reach the pause")
                        session.lock()
                        with self.assertRaises(vault.VaultLockedError):
                            _ = session.session_key
                    finally:
                        resume.set()
                        worker.join(15)
                    self.assertFalse(worker.is_alive(), "rekey did not finish")
                self.assertEqual(errors, [])
                self.assertEqual(session._key, b"", "revoked session retained a new key")
                for operation in (lambda: session.session_key,
                                  lambda: session.reveal_password(identifier),
                                  lambda: session.rekey(MASTER)):
                    with self.assertRaises(vault.VaultLockedError):
                        operation()
                # An already-started rekey finishes its atomic rewrite even if
                # its session is revoked. The new password must still open it.
                reopened = vault.Vault.unlock(path, new_master)
                self.assertEqual(reopened.reveal_password(identifier), "SyntheticPassword43!")
                self.assertEqual(reopened.reveal_notes(identifier), "Synthetic note")
                self.assertEqual(len(reopened.password_history(identifier)), 2)
                self.assertEqual(reopened.verify_integrity(), [])
                self.assertEqual(reopened.backup_material()["key"], backup_key)
                reopened.lock()
                with self.assertRaises(vault.InvalidMasterPasswordError):
                    vault.Vault.unlock(path, MASTER)
                backup = vault.Vault.unlock(vault.pre_rekey_backup_path(path), MASTER)
                self.assertEqual(backup.reveal_password(identifier), "SyntheticPassword43!")
                backup.lock()

    def test_locked_rekey_rejects_before_any_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            vault.create_vault(path, MASTER)
            session = vault.Vault.unlock(path, MASTER)
            before = path.read_bytes()
            session.lock()
            with mock.patch.object(db, "snapshot_bytes") as snapshot, \
                    mock.patch.object(crypto, "derive_key") as derive:
                with self.assertRaises(vault.VaultLockedError):
                    session.rekey("different synthetic master password")
                snapshot.assert_not_called()
                derive.assert_not_called()
            self.assertEqual(before, path.read_bytes())
            self.assertFalse(vault.pre_rekey_backup_path(path).exists())

    def test_lock_during_failed_rekey_preserves_old_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            new_master = "different synthetic master password"
            vault.create_vault(path, MASTER)
            session = vault.Vault.unlock(path, MASTER)
            identifier = session.add_credential(
                "example.test", "synthetic", "SyntheticPassword42!", notes="Synthetic note")
            entered, resume = threading.Event(), threading.Event()
            errors = []

            def fail_history(*args, **kwargs):
                # The credential has been rewritten inside the transaction.
                entered.set()
                if not resume.wait(15):
                    raise AssertionError("rekey was not released")
                raise RuntimeError("synthetic history-write failure")

            def rekey():
                try:
                    session.rekey(new_master)
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(db, "rekey_history", fail_history):
                worker = threading.Thread(target=rekey)
                worker.start()
                try:
                    self.assertTrue(entered.wait(15))
                    session.lock()
                finally:
                    resume.set()
                    worker.join(15)
                self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], RuntimeError)
            self.assertEqual(session._key, b"")
            with self.assertRaises(vault.VaultLockedError):
                _ = session.session_key
            reopened = vault.Vault.unlock(path, MASTER)
            self.assertEqual(reopened.reveal_password(identifier), "SyntheticPassword42!")
            self.assertEqual(reopened.reveal_notes(identifier), "Synthetic note")
            self.assertEqual(reopened.verify_integrity(), [])
            reopened.lock()
            with self.assertRaises(vault.InvalidMasterPasswordError):
                vault.Vault.unlock(path, new_master)

    def test_lock_revokes_reads_mutations_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            vault.create_vault(path, MASTER)
            session = vault.Vault.unlock(path, MASTER)
            identifier = session.add_credential("example.test", "synthetic", "SyntheticPassword42!")
            before = path.read_bytes()
            session.lock()
            operations = [lambda: session.list_credentials(), lambda: session.session_key,
                lambda: session.delete_credential(identifier), lambda: session.set_mfa(identifier, True),
                lambda: session.reveal_password(identifier), lambda: session.password_history(identifier),
                lambda: session.backup_material(), lambda: session.verify_integrity()]
            for operation in operations:
                with self.assertRaises(vault.VaultLockedError):
                    operation()
            self.assertEqual(before, path.read_bytes())
            self.assertEqual(vault.Vault.unlock(path, MASTER).reveal_password(identifier), "SyntheticPassword42!")

    def test_missing_verifier_cannot_reinitialize_existing_ciphertext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            vault.create_vault(path, MASTER)
            with db.connect(path) as connection:
                connection.execute("DELETE FROM vault_meta WHERE key = 'verifier'")
            before = path.read_bytes()
            with self.assertRaises(vault.VaultAlreadyExistsError):
                vault.create_vault(path, "different synthetic password")
            self.assertEqual(before, path.read_bytes())

    def test_malformed_kdf_rejected_without_running_backend(self):
        original = crypto._argon2_raw
        calls = []
        def forbidden(**kwargs):
            calls.append(kwargs)
            raise AssertionError("untrusted metadata reached backend")
        crypto._argon2_raw = forbidden
        try:
            for params in [None, [], {}, {"time_cost": True, "memory_cost": 65536, "parallelism": 4},
                {"time_cost": 3, "memory_cost": 10**12, "parallelism": 4},
                {"time_cost": 3, "memory_cost": 8, "parallelism": 16},
                {"time_cost": 10, "memory_cost": 262144, "parallelism": 4}]:
                with self.assertRaises(crypto.CryptoError):
                    crypto.derive_key(MASTER, bytes(16), "argon2id", params)
            for value in [True, "600000", 600000.0, 10**12, 0]:
                with self.assertRaises(crypto.CryptoError):
                    crypto.derive_key(MASTER, bytes(16), "pbkdf2_sha256", {"iterations": value})
            self.assertEqual(calls, [])
        finally:
            crypto._argon2_raw = original

    def test_native_frame_rejects_nonobject_json_and_continues(self):
        import io
        import struct
        from nomorepwn_app import native_host
        def framed(value):
            payload = json.dumps(value).encode("utf-8")
            return struct.pack("<I", len(payload)) + payload
        stream = io.BytesIO(framed([]) + framed({"type": "ping"}))
        self.assertEqual(native_host._handle(native_host._read(stream))["type"], "error")
        self.assertEqual(native_host._read(stream), {"type": "ping"})

    def test_unlock_normalizes_tampered_metadata_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            vault.create_vault(path, MASTER)
            for name, value in [("kdf_params", "[]"), ("kdf_params", "invalid json"),
                                ("kdf_salt", "not hex"), ("verifier", "not hex")]:
                with db.connect(path) as connection:
                    originals = dict(connection.execute("SELECT key, value FROM vault_meta"))
                    connection.execute("UPDATE vault_meta SET value=? WHERE key=?", (value, name))
                before = path.read_bytes()
                with self.assertRaises(vault.VaultError):
                    vault.Vault.unlock(path, MASTER)
                self.assertEqual(before, path.read_bytes())
                with db.connect(path) as connection:
                    connection.execute("UPDATE vault_meta SET value=? WHERE key=?", (originals[name], name))
