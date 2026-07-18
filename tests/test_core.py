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

from nomorepwn import backup, crypto, generator, leakcheck, strength, validation, vault
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


class BackupTests(unittest.TestCase):
    """Encrypted backups: round-trip, wrong secrets, tamper, rotation, merge."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = self.dir / "vault.db"
        vault.create_vault(self.db_path, MASTER)
        self.vault = vault.Vault.unlock(self.db_path, MASTER)
        self.vault.add_credential("github.com", "alice", "s3cret-pass", "notes here", True)
        self.vault.add_credential("gmail.com", "bob", "another-pass")

    def tearDown(self):
        self.tmp.cleanup()

    # -- master-password mode -------------------------------------------

    def test_backup_roundtrip_master_mode(self):
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        header = backup.read_header(dest.read_bytes())
        self.assertEqual(header["mode"], backup.MODE_MASTER)

        target = self.dir / "restored.db"
        backup.restore_to_path(dest.read_bytes(), MASTER, target)
        restored = vault.Vault.unlock(target, MASTER)
        creds = restored.list_credentials()
        self.assertEqual(len(creds), 2)
        github = next(c for c in creds if c["service_name"] == "github.com")
        self.assertEqual(restored.reveal_password(github["id"]), "s3cret-pass")
        self.assertEqual(restored.reveal_notes(github["id"]), "notes here")

    def test_backup_rejects_wrong_password(self):
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        with self.assertRaises(backup.BackupPasswordError):
            backup.open_blob(dest.read_bytes(), "definitely not the password")

    def test_backup_plaintext_never_present(self):
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        raw = dest.read_bytes()
        self.assertNotIn(b"s3cret-pass", raw)
        self.assertNotIn(b"github.com", raw)   # even metadata is sealed

    def test_backup_detects_tampering(self):
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        raw = bytearray(dest.read_bytes())
        raw[-1] ^= 0xFF
        with self.assertRaises(backup.BackupPasswordError):
            backup.open_blob(bytes(raw), MASTER)

    def test_backup_header_is_authenticated(self):
        """Editing the header's KDF params must fail decryption, not silently
        weaken it — the header is the GCM additional authenticated data."""
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        raw = dest.read_bytes()
        header = backup.read_header(raw)
        tampered = raw.replace(header["salt"].encode(), (b"0" * len(header["salt"])))
        self.assertNotEqual(tampered, raw)
        with self.assertRaises(backup.BackupError):
            backup.open_blob(tampered, MASTER)

    def test_rejects_non_backup_file(self):
        with self.assertRaises(backup.BackupFormatError):
            backup.read_header(b"just some random bytes")

    # -- separate-passphrase mode ---------------------------------------

    def test_backup_passphrase_mode(self):
        phrase = "a different backup phrase"
        self.vault.set_backup_passphrase(phrase)
        self.assertTrue(self.vault.has_backup_passphrase())

        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        blob = dest.read_bytes()
        self.assertEqual(backup.read_header(blob)["mode"], backup.MODE_PASSPHRASE)

        # The master password must NOT open a passphrase-sealed backup.
        with self.assertRaises(backup.BackupPasswordError):
            backup.open_blob(blob, MASTER)
        # The passphrase must.
        target = self.dir / "restored.db"
        backup.restore_to_path(blob, phrase, target)
        # The restored vault is still unlocked by the MASTER password.
        self.assertEqual(len(vault.Vault.unlock(target, MASTER).list_credentials()), 2)

    def test_clearing_passphrase_returns_to_master_mode(self):
        self.vault.set_backup_passphrase("a different backup phrase")
        self.vault.clear_backup_passphrase()
        self.assertFalse(self.vault.has_backup_passphrase())
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        self.assertEqual(backup.read_header(dest.read_bytes())["mode"], backup.MODE_MASTER)
        backup.open_blob(dest.read_bytes(), MASTER)  # must not raise

    # -- rotation & merge -----------------------------------------------

    def test_rotation_keeps_generations(self):
        dest = self.dir / "b.nmpbak"
        for _ in range(4):
            backup.rotate(dest, keep=3)
            self.vault.write_backup(dest)
        self.assertTrue(dest.exists())
        self.assertTrue(dest.with_suffix(dest.suffix + ".1").exists())
        self.assertTrue(dest.with_suffix(dest.suffix + ".2").exists())
        # keep=3 means primary + .1 + .2, never a .3
        self.assertFalse(dest.with_suffix(dest.suffix + ".3").exists())

    def test_merge_is_additive_and_skips_duplicates(self):
        other_db = self.dir / "other.db"
        vault.create_vault(other_db, MASTER)
        other = vault.Vault.unlock(other_db, MASTER)
        other.add_credential("github.com", "alice", "DIFFERENT-pass")  # duplicate
        other.add_credential("newsite.com", "carol", "brand-new-pass", "note", True)

        imported, skipped = self.vault.merge_from(other)
        self.assertEqual((imported, skipped), (1, 1))
        creds = {c["service_name"]: c for c in self.vault.list_credentials()}
        self.assertIn("newsite.com", creds)
        # The pre-existing entry was NOT overwritten.
        github = creds["github.com"]
        self.assertEqual(self.vault.reveal_password(github["id"]), "s3cret-pass")

    def test_snapshot_is_a_valid_database(self):
        raw = db_layer.snapshot_bytes(self.db_path)
        self.assertTrue(raw.startswith(b"SQLite format 3\x00"))


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


class BulkLeakScanTests(unittest.TestCase):
    """A password that could not be checked must never read as 'clean'.

    This is the regression guard for the bulk scan reporting "No breached
    passwords found" when every HIBP request had actually failed.
    """

    def setUp(self):
        self._real_check = leakcheck.check_password
        self.calls = []

    def tearDown(self):
        leakcheck.check_password = self._real_check

    def _stub(self, behaviour):
        def fake(password, timeout=leakcheck.DEFAULT_TIMEOUT):
            self.calls.append(password)
            result = behaviour(password)
            if isinstance(result, Exception):
                raise result
            return result

        leakcheck.check_password = fake

    def _scan(self, passwords):
        return leakcheck.check_many(passwords, delay=0, _sleep=lambda _s: None)

    def test_failures_are_not_reported_as_clean(self):
        self._stub(lambda pw: leakcheck.LeakCheckError("offline"))
        outcome = self._scan(["a", "b"])
        self.assertEqual(outcome.counts, {})
        self.assertEqual(outcome.failed, {"a", "b"})
        self.assertEqual(outcome.breached, {})
        self.assertFalse(outcome.complete)

    def test_clean_passwords_are_distinguishable_from_failures(self):
        self._stub(lambda pw: 0 if pw == "clean" else leakcheck.LeakCheckError("nope"))
        outcome = self._scan(["clean", "broken"])
        self.assertEqual(outcome.counts, {"clean": 0})
        self.assertEqual(outcome.failed, {"broken"})
        self.assertTrue(outcome.complete is False)

    def test_breached_counts_are_surfaced(self):
        self._stub(lambda pw: 42 if pw == "hunter2" else 0)
        outcome = self._scan(["hunter2", "safe"])
        self.assertEqual(outcome.breached, {"hunter2": 42})
        self.assertTrue(outcome.complete)

    def test_duplicates_are_checked_once(self):
        self._stub(lambda pw: 0)
        outcome = self._scan(["same", "same", "same", "other"])
        self.assertEqual(self.calls, ["same", "other"])
        self.assertEqual(set(outcome.counts), {"same", "other"})

    def test_progress_reports_deduplicated_total(self):
        self._stub(lambda pw: 0)
        seen = []
        leakcheck.check_many(
            ["x", "x", "y"], delay=0, _sleep=lambda _s: None,
            on_progress=lambda done, total: seen.append((done, total)))
        self.assertEqual(seen, [(1, 2), (2, 2)])

    def test_partial_failure_keeps_both_halves(self):
        self._stub(lambda pw: 7 if pw == "leaked" else leakcheck.LeakCheckError("x"))
        outcome = self._scan(["leaked", "unknown"])
        self.assertEqual(outcome.breached, {"leaked": 7})
        self.assertEqual(outcome.failed, {"unknown"})


class LeakCheckRetryTests(unittest.TestCase):
    """HIBP answers bulk callers with 429; we honour Retry-After."""

    class _Response:
        def __init__(self, status, text="", retry_after=None):
            self.status_code = status
            self.text = text
            self.headers = {} if retry_after is None else {"Retry-After": retry_after}

        def raise_for_status(self):
            if self.status_code >= 400:
                import requests
                raise requests.HTTPError(f"{self.status_code}")

    def setUp(self):
        import requests
        self._real_get = requests.get
        self._real_sleep = leakcheck.time.sleep
        self.slept = []
        leakcheck.time.sleep = lambda s: self.slept.append(s)

    def tearDown(self):
        import requests
        requests.get = self._real_get
        leakcheck.time.sleep = self._real_sleep

    def _serve(self, responses):
        import requests
        queue = list(responses)
        requests.get = lambda *a, **kw: queue.pop(0)

    def test_retries_after_429_then_succeeds(self):
        import hashlib
        sha1 = hashlib.sha1(b"pw").hexdigest().upper()
        body = f"{sha1[5:]}:9"
        self._serve([
            self._Response(429, retry_after="0.25"),
            self._Response(200, body),
        ])
        self.assertEqual(leakcheck.check_password("pw"), 9)
        self.assertEqual(self.slept, [0.25])

    def test_gives_up_after_max_retries(self):
        self._serve([self._Response(429) for _ in range(leakcheck.MAX_RETRIES)])
        with self.assertRaises(leakcheck.LeakCheckError):
            leakcheck.check_password("pw")

    def test_absurd_retry_after_is_capped(self):
        import hashlib
        sha1 = hashlib.sha1(b"pw").hexdigest().upper()
        self._serve([
            self._Response(429, retry_after="99999"),
            self._Response(200, f"{sha1[5:]}:1"),
        ])
        leakcheck.check_password("pw")
        self.assertTrue(all(s <= 8.0 for s in self.slept), self.slept)


if __name__ == "__main__":
    unittest.main()
