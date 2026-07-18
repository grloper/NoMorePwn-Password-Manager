"""Core security tests: crypto roundtrips, tamper evidence, validation,
vault lifecycle, and the SQL-injection policy.

Run with:  python -m unittest discover tests -v
"""

from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import crypto, generator, strength, validation, vault
from nomorepwn import db as db_layer

MASTER = "correct horse battery staple 42"


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.salt = crypto.generate_salt()
        kdf, params = crypto.default_kdf()
        self.key = crypto.derive_key(MASTER, self.salt, kdf, params)

    def test_roundtrip(self):
        blob = crypto.encrypt(self.key, b"hunter2", "cred:x:password")
        self.assertEqual(crypto.decrypt(self.key, blob, "cred:x:password"), b"hunter2")

    def test_wrong_key_fails(self):
        kdf, params = crypto.default_kdf()
        wrong = crypto.derive_key("not the password", self.salt, kdf, params)
        blob = crypto.encrypt(self.key, b"secret", "aad")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(wrong, blob, "aad")

    def test_wrong_aad_fails(self):
        """Ciphertext swapped between rows must not decrypt."""
        blob = crypto.encrypt(self.key, b"secret", "cred:row1:password")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, blob, "cred:row2:password")

    def test_bitflip_fails(self):
        blob = bytearray(crypto.encrypt(self.key, b"secret", "aad"))
        blob[-1] ^= 0x01
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, bytes(blob), "aad")

    def test_nonce_uniqueness(self):
        blobs = {crypto.encrypt(self.key, b"same", "aad")[:12] for _ in range(50)}
        self.assertEqual(len(blobs), 50, "GCM nonces must never repeat")

    def test_verifier(self):
        verifier = crypto.make_verifier(self.key)
        self.assertTrue(crypto.check_verifier(self.key, verifier))
        kdf, params = crypto.default_kdf()
        other = crypto.derive_key("other password!", self.salt, kdf, params)
        self.assertFalse(crypto.check_verifier(other, verifier))

    def test_weak_pbkdf2_rejected(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.derive_key(MASTER, self.salt, "pbkdf2_sha256", {"iterations": 1000})

    def test_pbkdf2_fallback_derives_256_bits(self):
        key = crypto.derive_key(MASTER, self.salt, "pbkdf2_sha256", {"iterations": 600_000})
        self.assertEqual(len(key), 32)


class ValidationTests(unittest.TestCase):
    def test_service_ok(self):
        self.assertEqual(validation.validate_service_name("  github.com "), "github.com")

    def test_service_rejects_sqli_chars(self):
        for bad in ("'; DROP TABLE credentials;--", "a\"b", "x' OR '1'='1", ""):
            with self.assertRaises(validation.ValidationError):
                validation.validate_service_name(bad)

    def test_service_length_cap(self):
        with self.assertRaises(validation.ValidationError):
            validation.validate_service_name("a" * 65)

    def test_username_ok(self):
        self.assertEqual(validation.validate_username("alice@example.com"), "alice@example.com")

    def test_username_rejects_spaces_and_quotes(self):
        for bad in ("alice bob", "a'b", "--alice"):
            with self.assertRaises(validation.ValidationError):
                validation.validate_username(bad)

    def test_password_allows_special_chars(self):
        pw = "p@$$w0rd '\";--DROP"
        self.assertEqual(validation.validate_password(pw), pw)

    def test_password_rejects_control_chars_and_overlong(self):
        with self.assertRaises(validation.ValidationError):
            validation.validate_password("abc\x00def")
        with self.assertRaises(validation.ValidationError):
            validation.validate_password("a" * 1025)


class VaultLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "vault.db"
        vault.create_vault(self.db_path, MASTER)
        self.vault = vault.Vault.unlock(self.db_path, MASTER)

    def tearDown(self):
        self.tmp.cleanup()

    def test_wrong_master_password_rejected(self):
        with self.assertRaises(vault.InvalidMasterPasswordError):
            vault.Vault.unlock(self.db_path, "wrong password!")

    def test_add_reveal_roundtrip(self):
        cred_id = self.vault.add_credential(
            "github.com", "alice", "s3cret! pass", notes="work account", mfa_enabled=True
        )
        self.assertEqual(self.vault.reveal_password(cred_id), "s3cret! pass")
        self.assertEqual(self.vault.reveal_notes(cred_id), "work account")
        listed = self.vault.list_credentials()
        self.assertEqual(len(listed), 1)
        self.assertTrue(listed[0]["mfa_enabled"])
        self.assertEqual(listed[0]["age_days"], 0)

    def test_plaintext_never_stored(self):
        self.vault.add_credential("github.com", "alice", "UNIQUE-plaintext-marker")
        raw = self.db_path.read_bytes()
        self.assertNotIn(b"UNIQUE-plaintext-marker", raw)

    def test_duplicate_rejected(self):
        self.vault.add_credential("github.com", "alice", "pw1")
        with self.assertRaises(vault.DuplicateCredentialError):
            self.vault.add_credential("github.com", "alice", "pw2")

    def test_history_grows_on_rotation(self):
        cred_id = self.vault.add_credential("github.com", "alice", "first-pw")
        self.vault.update_password(cred_id, "second-pw")
        history = self.vault.password_history(cred_id)
        self.assertEqual(len(history), 2)
        self.assertTrue(all(entry["checksum_ok"] for entry in history))
        self.assertEqual(self.vault.reveal_password(cred_id), "second-pw")

    def test_integrity_clean_vault(self):
        self.vault.add_credential("github.com", "alice", "pw")
        self.assertEqual(self.vault.verify_integrity(), [])

    def test_integrity_detects_ciphertext_tamper(self):
        cred_id = self.vault.add_credential("github.com", "alice", "pw")
        # Simulate an attacker editing the DB outside the app.
        conn = sqlite3.connect(self.db_path)
        blob = bytearray(
            conn.execute(
                "SELECT password_enc FROM credentials WHERE id = ?", (cred_id,)
            ).fetchone()[0]
        )
        blob[-1] ^= 0xFF
        conn.execute(
            "UPDATE credentials SET password_enc = ? WHERE id = ?",
            (bytes(blob), cred_id),
        )
        conn.commit()
        conn.close()

        issues = self.vault.verify_integrity()
        details = " | ".join(issue.detail for issue in issues)
        self.assertIn("SHA-256", details)
        self.assertIn("AES-GCM", details)
        with self.assertRaises(Exception):
            self.vault.reveal_password(cred_id)

    def test_integrity_detects_history_tamper(self):
        cred_id = self.vault.add_credential("github.com", "alice", "pw")
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE password_history SET ciphertext_sha256 = ? WHERE credential_id = ?",
            ("0" * 64, cred_id),
        )
        conn.commit()
        conn.close()
        issues = self.vault.verify_integrity()
        self.assertTrue(issues)

    def test_sqli_strings_are_inert_when_valid(self):
        """Passwords may contain hostile SQL — stored/retrieved verbatim."""
        payload = "x'; DROP TABLE credentials; --"
        cred_id = self.vault.add_credential("evil.example", "mallory", payload)
        self.assertEqual(self.vault.reveal_password(cred_id), payload)
        # Table still exists and vault still works.
        self.assertEqual(len(self.vault.list_credentials()), 1)

    def test_mfa_toggle(self):
        cred_id = self.vault.add_credential("github.com", "alice", "pw")
        self.vault.set_mfa(cred_id, True)
        self.assertTrue(self.vault.list_credentials()[0]["mfa_enabled"])

    def test_update_credential_metadata(self):
        cred_id = self.vault.add_credential("github.com", "alice", "pw", "old notes", False)
        self.vault.update_credential(cred_id, "gitlab.com", "alice2", "new notes", True)
        cred = self.vault.list_credentials()[0]
        self.assertEqual(cred["service_name"], "gitlab.com")
        self.assertEqual(cred["username"], "alice2")
        self.assertTrue(cred["mfa_enabled"])
        self.assertEqual(self.vault.reveal_notes(cred_id), "new notes")
        # Password is untouched by a metadata edit.
        self.assertEqual(self.vault.reveal_password(cred_id), "pw")

    def test_update_credential_duplicate_rejected(self):
        a = self.vault.add_credential("github.com", "alice", "pw")
        self.vault.add_credential("gitlab.com", "bob", "pw2")
        with self.assertRaises(vault.DuplicateCredentialError):
            # Renaming 'a' onto the (gitlab.com, bob) pair must be rejected.
            self.vault.update_credential(a, "gitlab.com", "bob", "", False)


class GeneratorTests(unittest.TestCase):
    def test_password_length_and_classes(self):
        opts = generator.PasswordOptions(length=24)
        pw = generator.generate_password(opts)
        self.assertEqual(len(pw), 24)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_password_avoids_ambiguous(self):
        opts = generator.PasswordOptions(length=60, avoid_ambiguous=True)
        pw = generator.generate_password(opts)
        self.assertFalse(any(c in generator.AMBIGUOUS for c in pw))

    def test_password_respects_disabled_classes(self):
        opts = generator.PasswordOptions(
            length=40, use_upper=False, use_symbols=False, use_digits=False
        )
        pw = generator.generate_password(opts)
        self.assertTrue(all(c in generator.LOWER for c in pw))

    def test_passwords_are_unique(self):
        opts = generator.PasswordOptions(length=24)
        pws = {generator.generate_password(opts) for _ in range(50)}
        self.assertEqual(len(pws), 50)

    def test_passphrase(self):
        phrase = generator.generate_passphrase(words=4, separator="-", add_number=True)
        parts = phrase.split("-")
        self.assertEqual(len(parts), 5)  # 4 words + trailing number
        self.assertTrue(parts[-1].isdigit())


class SqlInjectionPolicyTests(unittest.TestCase):
    """Static check: no dynamic SQL construction anywhere in db.py."""

    def test_no_dynamic_sql_in_db_layer(self):
        source = Path(db_layer.__file__).read_text(encoding="utf-8")
        # No f-strings, %-format, .format(), or concatenation adjacent to SQL verbs.
        self.assertIsNone(re.search(r'f"[^"]*(SELECT|INSERT|UPDATE|DELETE)', source, re.I))
        self.assertIsNone(re.search(r"%\s*\(", source))
        self.assertIsNone(re.search(r"\.format\(", source))
        self.assertIsNone(re.search(r'"\s*\+\s*\w+\s*\+\s*"', source))


class StrengthTests(unittest.TestCase):
    def test_weak_vs_strong(self):
        weak = strength.evaluate("password")
        strong = strength.evaluate("kJ8#mQ2$vN9pL5xW7z!fR3")
        self.assertLess(weak.score, strong.score)
        self.assertLessEqual(weak.score, 1)
        self.assertGreaterEqual(strong.score, 3)

    def test_entropy_fallback(self):
        weak = strength._evaluate_entropy("abc")
        strong = strength._evaluate_entropy("kJ8#mQ2$vN9pL5xW7z!fR3")
        self.assertLess(weak.score, strong.score)


if __name__ == "__main__":
    unittest.main()
