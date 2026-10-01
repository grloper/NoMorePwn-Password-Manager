"""Synthetic vault adversarial lifecycle tests; no live profile access."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from nomorepwn import crypto, vault

MASTER = "synthetic master password 2026"

class SessionSecurityTests(unittest.TestCase):
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
            with sqlite3.connect(path) as connection:
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
                with sqlite3.connect(path) as connection:
                    originals = dict(connection.execute("SELECT key, value FROM vault_meta"))
                    connection.execute("UPDATE vault_meta SET value=? WHERE key=?", (value, name))
                before = path.read_bytes()
                with self.assertRaises(vault.VaultError):
                    vault.Vault.unlock(path, MASTER)
                self.assertEqual(before, path.read_bytes())
                with sqlite3.connect(path) as connection:
                    connection.execute("UPDATE vault_meta SET value=? WHERE key=?", (originals[name], name))
