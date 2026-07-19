"""Core security tests: crypto roundtrips, tamper evidence, validation,
vault lifecycle, and the SQL-injection policy.

Run with:  python -m unittest discover tests -v
"""

from __future__ import annotations

import hashlib
import os
import json
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nomorepwn import (
    backup, crypto, generator, groups, leakcheck, recovery, strength, updater,
    validation, vault,
)
from nomorepwn import config as config_module
from nomorepwn import db as db_layer
from nomorepwn import db

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


class PasswordWhitespaceTests(unittest.TestCase):
    """Surrounding whitespace is *reported*, never removed.

    A trailing space is usually a copy-paste slip, but it can be a real part
    of a password — trimming it silently would lock the user out of the
    account it belongs to. The prompt is the only thing allowed to decide.
    """

    def test_clean_password_reports_nothing(self):
        f = validation.inspect_password_whitespace("hunter2")
        self.assertFalse(f.found)
        self.assertEqual(f.describe(), "")

    def test_trailing_space_is_found(self):
        f = validation.inspect_password_whitespace("hunter2 ")
        self.assertTrue(f.found)
        self.assertEqual(f.trailing, " ")
        self.assertEqual(f.leading, "")
        self.assertEqual(f.cleaned, "hunter2")
        self.assertIn("ends with a space", f.describe())

    def test_leading_space_is_found(self):
        f = validation.inspect_password_whitespace(" hunter2")
        self.assertTrue(f.found)
        self.assertEqual(f.leading, " ")
        self.assertEqual(f.trailing, "")
        self.assertIn("starts with a space", f.describe())

    def test_both_ends_are_described(self):
        f = validation.inspect_password_whitespace(" hunter2\t")
        desc = f.describe()
        self.assertIn("starts with a space", desc)
        self.assertIn("ends with a tab", desc)
        self.assertEqual(f.cleaned, "hunter2")

    def test_multiple_trailing_spaces_are_counted(self):
        f = validation.inspect_password_whitespace("hunter2   ")
        self.assertEqual(f.trailing, "   ")
        self.assertIn("3 spaces", f.describe())

    def test_newline_and_tab_are_named(self):
        self.assertIn("a newline", validation.inspect_password_whitespace("x\n").describe())
        self.assertIn("a tab", validation.inspect_password_whitespace("x\t").describe())

    def test_non_breaking_space_is_caught(self):
        # The nastiest case: renders identically to a space and survives most
        # copy-paste paths. str.strip() does treat it as whitespace.
        f = validation.inspect_password_whitespace("hunter2 ")
        self.assertTrue(f.found)
        self.assertEqual(f.cleaned, "hunter2")

    def test_interior_spaces_are_not_flagged(self):
        # "correct horse battery staple" is a good password, not a mistake.
        f = validation.inspect_password_whitespace("correct horse battery staple")
        self.assertFalse(f.found)

    def test_whitespace_only_password_cannot_be_cleaned_away(self):
        f = validation.inspect_password_whitespace("   ")
        self.assertTrue(f.found)
        self.assertTrue(f.cleaned_is_empty)

    def test_empty_and_non_string_are_inert(self):
        self.assertFalse(validation.inspect_password_whitespace("").found)
        self.assertFalse(validation.inspect_password_whitespace(None).found)

    def test_inspection_never_mutates_the_password(self):
        original = "  hunter2  "
        validation.inspect_password_whitespace(original)
        self.assertEqual(original, "  hunter2  ")

    def test_validate_password_still_does_not_strip(self):
        """Guards the invariant this feature is designed around.

        The fix for trailing whitespace is a prompt, not a `.strip()` in
        validation. If someone "simplifies" this later by stripping here,
        every password with deliberate surrounding whitespace silently
        changes and the vault stops matching the real account.
        """
        self.assertEqual(validation.validate_password(" pw "), " pw ")
        self.assertEqual(validation.validate_password("pw "), "pw ")


class SchemaMigrationTests(unittest.TestCase):
    """Upgrading a v1 vault in place, without losing a single secret.

    `init_schema` only runs inside `create_vault`, so a vault made by an older
    build keeps its original columns forever. Until v2 the version number was
    write-only and bumping it migrated nothing. These tests exist because
    getting this wrong on a password vault is unrecoverable.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.db"
        self.addCleanup(self.tmp.cleanup)

    def _make_v1_vault(self) -> None:
        """Build a real vault, then rewind it to look exactly like v1."""
        vault.create_vault(self.path, MASTER)
        vlt = vault.Vault.unlock(self.path, MASTER)
        vlt.add_credential("github.com", "alice", "s3cret-pass", notes="my note")
        vlt.add_credential("gmail.com", "bob", "other-pass")
        vlt.lock()
        # Drop every post-v1 column and the version marker so this is genuinely v1.
        conn = sqlite3.connect(str(self.path))
        try:
            conn.execute("ALTER TABLE credentials DROP COLUMN group_name")
            conn.execute("ALTER TABLE credentials DROP COLUMN alt_login")
            conn.execute("DELETE FROM vault_meta WHERE key = 'schema_version'")
            conn.commit()
        finally:
            conn.close()

    def _make_v2_vault(self) -> None:
        """A vault from the *intermediate* version, to test a partial upgrade."""
        vault.create_vault(self.path, MASTER)
        vlt = vault.Vault.unlock(self.path, MASTER)
        vlt.add_credential("github.com", "alice", "s3cret-pass", group_name="Development")
        vlt.lock()
        conn = sqlite3.connect(str(self.path))
        try:
            conn.execute("ALTER TABLE credentials DROP COLUMN alt_login")
            conn.execute("UPDATE vault_meta SET value = '2' WHERE key = 'schema_version'")
            conn.commit()
        finally:
            conn.close()

    def test_v1_upgrades_through_every_step_in_one_unlock(self):
        """A vault two versions behind must not need two launches."""
        self._make_v1_vault()
        vlt = vault.Vault.unlock(self.path, MASTER)
        try:
            with db.connect(self.path) as conn:
                cols = db.credential_columns(conn)
                self.assertEqual(db.read_schema_version(conn), db.SCHEMA_VERSION)
            self.assertIn("group_name", cols)   # from v2
            self.assertIn("alt_login", cols)    # from v3
            self.assertEqual(vlt.verify_integrity(), [])
        finally:
            vlt.lock()

    def test_v2_vault_upgrades_to_v3_keeping_its_groups(self):
        self._make_v2_vault()
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), 2)
        vlt = vault.Vault.unlock(self.path, MASTER)
        try:
            cred = vlt.list_credentials()[0]
            self.assertEqual(cred["group_name"], "Development", "v2 data was lost")
            self.assertEqual(cred["alt_login"], "")
            self.assertEqual(vlt.reveal_password(cred["id"]), "s3cret-pass")
        finally:
            vlt.lock()
        self.assertTrue(vault.pre_migration_backup_path(self.path, 2).exists())

    def test_v1_vault_is_detected_as_version_1(self):
        self._make_v1_vault()
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), 1)
            self.assertNotIn("group_name", db.credential_columns(conn))

    def test_unlock_migrates_and_secrets_still_decrypt(self):
        """The whole point: upgrading must not cost a single password.

        AAD is bound to each row's uuid, so adding a column must leave every
        secret decryptable. If a migration ever rewrote uuid or password_enc,
        this is what would catch it.
        """
        self._make_v1_vault()
        vlt = vault.Vault.unlock(self.path, MASTER)
        try:
            creds = {c["service_name"]: c for c in vlt.list_credentials()}
            self.assertEqual(len(creds), 2)
            self.assertEqual(vlt.reveal_password(creds["github.com"]["id"]), "s3cret-pass")
            self.assertEqual(vlt.reveal_password(creds["gmail.com"]["id"]), "other-pass")
            self.assertEqual(vlt.reveal_notes(creds["github.com"]["id"]), "my note")
            self.assertEqual(vlt.verify_integrity(), [])
        finally:
            vlt.lock()

    def test_migration_records_the_new_version(self):
        self._make_v1_vault()
        vault.Vault.unlock(self.path, MASTER).lock()
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), db.SCHEMA_VERSION)
            self.assertIn("group_name", db.credential_columns(conn))

    def test_existing_rows_land_ungrouped(self):
        self._make_v1_vault()
        vlt = vault.Vault.unlock(self.path, MASTER)
        try:
            self.assertTrue(all(c["group_name"] == "" for c in vlt.list_credentials()))
            self.assertEqual(vlt.list_groups(), [])
        finally:
            vlt.lock()

    def test_migration_writes_a_recoverable_backup(self):
        self._make_v1_vault()
        backup_path = vault.pre_migration_backup_path(self.path, 1)
        self.assertFalse(backup_path.exists())
        vault.Vault.unlock(self.path, MASTER).lock()
        self.assertTrue(backup_path.exists(), "no pre-migration backup was written")
        # It must be the *old* schema, and a real openable vault.
        conn = sqlite3.connect(str(backup_path))
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(credentials)")}
            self.assertNotIn("group_name", cols)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 2)
        finally:
            conn.close()

    def test_migration_is_idempotent(self):
        self._make_v1_vault()
        for _ in range(3):
            vault.Vault.unlock(self.path, MASTER).lock()
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), db.SCHEMA_VERSION)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 2)

    def test_already_current_vault_is_not_backed_up(self):
        """A no-op upgrade must not litter a backup beside every vault."""
        vault.create_vault(self.path, MASTER)
        vault.Vault.unlock(self.path, MASTER).lock()
        self.assertEqual(
            list(Path(self.tmp.name).glob("*premigration*")), [],
            "wrote a pre-migration backup for a vault that needed no migration")

    def test_wrong_password_never_migrates(self):
        """Migration runs only after the verifier passes."""
        self._make_v1_vault()
        with self.assertRaises(vault.InvalidMasterPasswordError):
            vault.Vault.unlock(self.path, "definitely-not-the-master-password")
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), 1)
            self.assertNotIn("group_name", db.credential_columns(conn))

    def test_fresh_vault_is_created_at_the_current_version(self):
        vault.create_vault(self.path, MASTER)
        with db.connect(self.path) as conn:
            self.assertEqual(db.read_schema_version(conn), db.SCHEMA_VERSION)
            self.assertIn("group_name", db.credential_columns(conn))


class CredentialGroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.db"
        vault.create_vault(self.path, MASTER)
        self.vault = vault.Vault.unlock(self.path, MASTER)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.vault.lock)

    def test_group_round_trips(self):
        cid = self.vault.add_credential("steampowered.com", "ofek", "pw", group_name="Gaming")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(cred["group_name"], "Gaming")

    def test_group_is_optional(self):
        cid = self.vault.add_credential("example.com", "u", "pw")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(cred["group_name"], "")

    def test_list_groups_is_deduplicated_and_sorted(self):
        self.vault.add_credential("gmail.com", "a", "pw", group_name="Email")
        self.vault.add_credential("outlook.com", "b", "pw", group_name="Email")
        self.vault.add_credential("steampowered.com", "c", "pw", group_name="Gaming")
        self.vault.add_credential("nogroup.com", "d", "pw")
        self.assertEqual(self.vault.list_groups(), ["Email", "Gaming"])

    def test_set_group_moves_and_clears(self):
        cid = self.vault.add_credential("example.com", "u", "pw", group_name="Work")
        self.vault.set_group(cid, "Personal")
        self.assertEqual(self.vault.list_groups(), ["Personal"])
        self.vault.set_group(cid, "")
        self.assertEqual(self.vault.list_groups(), [])

    def test_update_credential_preserves_the_group_by_default(self):
        """Guards against repeating the `notes=""` data-loss trap.

        `update_credential` is a PUT: its notes default erases notes for any
        caller that forgets them. The group deliberately defaults to None
        (leave alone) instead, so editing MFA cannot silently ungroup an item.
        """
        cid = self.vault.add_credential("example.com", "u", "pw", group_name="Gaming")
        self.vault.update_credential(cid, "example.com", "u", mfa_enabled=True)
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(cred["group_name"], "Gaming")

    def test_update_credential_can_clear_the_group_explicitly(self):
        cid = self.vault.add_credential("example.com", "u", "pw", group_name="Gaming")
        self.vault.update_credential(cid, "example.com", "u", group_name="")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(cred["group_name"], "")

    def test_invalid_group_is_rejected(self):
        for bad in ("'; DROP TABLE credentials;--", "-leading", "a" * 49, "café"):
            with self.assertRaises(validation.ValidationError, msg=bad):
                self.vault.add_credential(f"svc-{len(bad)}.com", "u", "pw", group_name=bad)

    def test_group_is_trimmed_not_mangled(self):
        cid = self.vault.add_credential("example.com", "u", "pw", group_name="  Gaming  ")
        cred = next(c for c in self.vault.list_credentials() if c["id"] == cid)
        self.assertEqual(cred["group_name"], "Gaming")


class AlternateLoginTests(unittest.TestCase):
    """The optional second identifier: stored, not buried in notes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.db"
        vault.create_vault(self.path, MASTER)
        self.vault = vault.Vault.unlock(self.path, MASTER)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.vault.lock)

    def _cred(self, cred_id):
        return next(c for c in self.vault.list_credentials() if c["id"] == cred_id)

    def test_round_trips(self):
        cid = self.vault.add_credential("steampowered.com", "ofek", "pw",
                                        alt_login="ofek@gmail.com")
        self.assertEqual(self._cred(cid)["alt_login"], "ofek@gmail.com")

    def test_is_optional(self):
        cid = self.vault.add_credential("example.com", "u", "pw")
        self.assertEqual(self._cred(cid)["alt_login"], "")

    def test_does_not_affect_duplicate_detection(self):
        """Identity stays (service, username) — the alternate is not part of it."""
        self.vault.add_credential("example.com", "u", "pw", alt_login="a@x.com")
        with self.assertRaises(vault.DuplicateCredentialError):
            self.vault.add_credential("example.com", "u", "pw2", alt_login="different@x.com")

    def test_same_alt_login_on_many_entries_is_fine(self):
        # The whole point: one address reused across many sites.
        a = self.vault.add_credential("a.com", "ofek", "pw", alt_login="me@gmail.com")
        b = self.vault.add_credential("b.com", "ofek2", "pw", alt_login="me@gmail.com")
        self.assertEqual(self._cred(a)["alt_login"], self._cred(b)["alt_login"])

    def test_update_preserves_it_by_default(self):
        cid = self.vault.add_credential("example.com", "u", "pw", alt_login="me@x.com")
        self.vault.update_credential(cid, "example.com", "u", mfa_enabled=True)
        self.assertEqual(self._cred(cid)["alt_login"], "me@x.com")

    def test_update_can_clear_it_explicitly(self):
        cid = self.vault.add_credential("example.com", "u", "pw", alt_login="me@x.com")
        self.vault.update_credential(cid, "example.com", "u", alt_login="")
        self.assertEqual(self._cred(cid)["alt_login"], "")

    def test_invalid_alt_login_is_rejected(self):
        for bad in ("has space", "-leading", "a" * 129, "'; DROP TABLE credentials;--"):
            with self.assertRaises(validation.ValidationError, msg=bad):
                self.vault.add_credential(f"s{len(bad)}.com", "u", "pw", alt_login=bad)

    def test_it_is_trimmed(self):
        cid = self.vault.add_credential("example.com", "u", "pw", alt_login="  me@x.com  ")
        self.assertEqual(self._cred(cid)["alt_login"], "me@x.com")


class IdentifierAutocompleteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.db"
        vault.create_vault(self.path, MASTER)
        self.vault = vault.Vault.unlock(self.path, MASTER)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.vault.lock)

    def test_empty_vault_offers_nothing(self):
        self.assertEqual(self.vault.list_identifiers(), [])

    def test_most_reused_identifier_comes_first(self):
        for i, service in enumerate(("a.com", "b.com", "c.com")):
            self.vault.add_credential(service, "me@gmail.com", f"pw{i}")
        self.vault.add_credential("d.com", "rare@example.com", "pw")
        self.assertEqual(self.vault.list_identifiers()[0], "me@gmail.com")

    def test_alternate_logins_are_offered_too(self):
        self.vault.add_credential("a.com", "handle", "pw", alt_login="me@gmail.com")
        self.assertCountEqual(self.vault.list_identifiers(), ["handle", "me@gmail.com"])

    def test_identifiers_are_deduplicated(self):
        self.vault.add_credential("a.com", "me@gmail.com", "pw")
        self.vault.add_credential("b.com", "other", "pw", alt_login="me@gmail.com")
        self.assertEqual(self.vault.list_identifiers().count("me@gmail.com"), 1)

    def test_no_passwords_ever_leak_into_the_suggestions(self):
        self.vault.add_credential("a.com", "me@gmail.com", "sup3r-s3cret-pw")
        self.assertNotIn("sup3r-s3cret-pw", self.vault.list_identifiers())


class GroupSuggestionTests(unittest.TestCase):
    def test_known_services_are_recognised(self):
        cases = {
            "gmail.com": "Email", "mail.google.com": "Email",
            "steampowered.com": "Gaming", "steamcommunity.com": "Gaming",
            "store.steampowered.com": "Gaming",
            "github.com": "Development", "paypal.com": "Banking & Finance",
            "netflix.com": "Entertainment", "amazon.co.uk": "Shopping",
            "reddit.com": "Social",
        }
        for service, expected in cases.items():
            self.assertEqual(groups.suggest_group(service), expected, service)

    def test_case_and_scheme_do_not_matter(self):
        self.assertEqual(groups.suggest_group("HTTPS://GMail.COM/login"), "Email")

    def test_unknown_service_suggests_nothing(self):
        self.assertEqual(groups.suggest_group("some-internal-tool.local"), "")

    def test_empty_input_is_safe(self):
        for value in ("", "   ", None, 5):
            self.assertEqual(groups.suggest_group(value), "")

    def test_longest_hint_wins(self):
        # "ea.com" must not hijack a longer, more specific match.
        self.assertEqual(groups.suggest_group("battle.net"), "Gaming")

    def test_suggestions_pass_their_own_validator(self):
        """A suggested group the user cannot actually save would be a bug."""
        for name in groups.SUGGESTED_GROUPS:
            self.assertEqual(validation.validate_group_name(name), name)
        for name in set(groups._HINTS.values()):
            self.assertEqual(validation.validate_group_name(name), name)

    def test_group_credentials_orders_named_then_ungrouped(self):
        creds = [
            {"id": 1, "group_name": "Work"},
            {"id": 2, "group_name": ""},
            {"id": 3, "group_name": "Email"},
            {"id": 4, "group_name": "Work"},
        ]
        out = groups.group_credentials(creds)
        self.assertEqual([label for label, _ in out], ["Email", "Work", "Ungrouped"])
        self.assertEqual([c["id"] for c in dict(out)["Work"]], [1, 4])

    def test_group_credentials_merges_case_variants(self):
        creds = [{"id": 1, "group_name": "Gaming"}, {"id": 2, "group_name": "gaming"}]
        out = groups.group_credentials(creds)
        self.assertEqual(len(out), 1, out)
        self.assertEqual(len(out[0][1]), 2)

    def test_group_credentials_handles_missing_key(self):
        # Rows read before the migration have no group_name at all.
        out = groups.group_credentials([{"id": 1}])
        self.assertEqual(out, [("Ungrouped", [{"id": 1}])])

    def test_group_credentials_of_nothing_is_empty(self):
        self.assertEqual(groups.group_credentials([]), [])

    def test_choices_puts_suggestions_first_and_dedupes(self):
        out = groups.choices(["Gaming", "gaming", "My Custom"])
        self.assertEqual(out[:len(groups.SUGGESTED_GROUPS)], list(groups.SUGGESTED_GROUPS))
        self.assertEqual(out.count("Gaming"), 1)
        self.assertNotIn("gaming", out)
        self.assertIn("My Custom", out)


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

    # -- corrupt / malicious headers ------------------------------------

    @staticmethod
    def _blob_with_header(header: dict, magic=backup.MAGIC_V2,
                          payload: bytes = b"\x00" * 40) -> bytes:
        """A backup blob carrying an arbitrary (unsealed) header, for testing
        the header-parsing/validation guards without a real key."""
        hb = json.dumps(header, sort_keys=True).encode("utf-8")
        return magic + len(hb).to_bytes(4, "big") + hb + payload

    def test_v1_corrupt_header_raises_backup_error(self):
        # The V1 branch used to call struct.unpack / json.loads with no guard,
        # so a truncated or garbage header escaped as struct.error /
        # JSONDecodeError, past every `except BackupError`. Now each is caught.
        cases = [
            backup.MAGIC_V1,                                    # no length field
            backup.MAGIC_V1 + b"\x00\x00",                      # truncated length
            backup.MAGIC_V1 + (5).to_bytes(4, "big") + b"xx",   # claims 5, has 2
            backup.MAGIC_V1 + (4).to_bytes(4, "big") + b"notj", # 4 bytes, not JSON
            backup.MAGIC_V1 + (2).to_bytes(4, "big") + b"[]",   # JSON, not an object
            backup.MAGIC_V1 + (0).to_bytes(4, "big"),           # zero-length header
        ]
        for blob in cases:
            with self.assertRaises(backup.BackupError):
                backup.read_header(blob)

    def test_header_length_cap_rejects_implausible_length(self):
        # A header claiming ~1 GB must be refused up front, not sliced/parsed.
        for magic in (backup.MAGIC_V1, backup.MAGIC_V2):
            blob = magic + (10 ** 9).to_bytes(4, "big") + b"x"
            with self.assertRaises(backup.BackupError):
                backup.read_header(blob)

    def test_v1_wellformed_header_still_parses(self):
        # Guarding V1 must not break a well-formed V1 header.
        blob = self._blob_with_header(
            {"kdf_name": "argon2id",
             "kdf_params": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4},
             "salt": "00" * 16},
            magic=backup.MAGIC_V1,
        )
        parsed = backup.read_header(blob)
        self.assertEqual(parsed["v"], 1)
        self.assertEqual(parsed["mode"], backup.MODE_MASTER)
        self.assertIsNone(parsed["_header_bytes"])

    def test_malicious_argon2_memory_cost_is_rejected(self):
        # A gigabyte-plus memory_cost used to be fed straight to Argon2, with no
        # cancel path — the app wedged on Restore. It must be rejected instead.
        blob = self._blob_with_header({
            "kdf_name": "argon2id",
            "kdf_params": {"time_cost": 3, "memory_cost": 100 * 1024 * 1024, "parallelism": 4},
            "salt": "00" * 16,
        })
        # read_header does not derive, so it still parses ...
        self.assertEqual(backup.read_header(blob)["kdf_name"], "argon2id")
        # ... but open_blob refuses before the KDF ever allocates.
        with self.assertRaises(backup.BackupError):
            backup.open_blob(blob, MASTER)

    def test_malicious_argon2_time_cost_and_parallelism_rejected(self):
        for params in (
            {"time_cost": 10 ** 9, "memory_cost": 65536, "parallelism": 4},
            {"time_cost": 3, "memory_cost": 65536, "parallelism": 10 ** 6},
        ):
            blob = self._blob_with_header(
                {"kdf_name": "argon2id", "kdf_params": params, "salt": "00" * 16})
            with self.assertRaises(backup.BackupError):
                backup.open_blob(blob, MASTER)

    def test_pbkdf2_iteration_ceiling_is_enforced(self):
        blob = self._blob_with_header({
            "kdf_name": "pbkdf2_sha256",
            "kdf_params": {"iterations": 10 ** 12},
            "salt": "00" * 16,
        })
        with self.assertRaises(backup.BackupError):
            backup.open_blob(blob, MASTER)

    def test_unknown_kdf_is_rejected(self):
        blob = self._blob_with_header(
            {"kdf_name": "scrypt", "kdf_params": {}, "salt": "00" * 16})
        with self.assertRaises(backup.BackupError):
            backup.open_blob(blob, MASTER)

    def test_non_integer_kdf_param_is_rejected(self):
        blob = self._blob_with_header({
            "kdf_name": "argon2id",
            "kdf_params": {"time_cost": "lots", "memory_cost": 65536, "parallelism": 4},
            "salt": "00" * 16,
        })
        with self.assertRaises(backup.BackupError):
            backup.open_blob(blob, MASTER)

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


class BundledExtensionTests(unittest.TestCase):
    """A packaged build must materialise the extension to a stable directory.

    Regression guard: releases shipped no `extension/` folder at all, while
    `register()` still succeeded and Settings said "✓ Connected" — pointing the
    user at a directory that had never been created.
    """

    def setUp(self):
        import shutil as _shutil

        from nomorepwn_app import browser_bridge

        self.bridge = browser_bridge
        repo = Path(__file__).resolve().parent.parent

        # Reproduce the layout build/NoMorePwn.spec bundles into _MEIPASS.
        self.meipass = Path(tempfile.mkdtemp())
        bundled = self.meipass / "extension"
        bundled.mkdir()
        _shutil.copy(repo / "extension" / "manifest.json", bundled / "manifest.json")
        _shutil.copytree(repo / "extension" / "src", bundled / "src")

        self.data = Path(tempfile.mkdtemp())
        self._real_data_dir = config_module.DATA_DIR
        config_module.DATA_DIR = self.data

        self._had_frozen = hasattr(sys, "frozen")
        sys.frozen = True
        sys._MEIPASS = str(self.meipass)

    def tearDown(self):
        config_module.DATA_DIR = self._real_data_dir
        if not self._had_frozen:
            del sys.frozen
        if hasattr(sys, "_MEIPASS"):
            del sys._MEIPASS

    def test_materialises_to_the_data_dir_not_beside_the_exe(self):
        """Onefile builds have no writable folder beside the .exe, and
        _MEIPASS changes every launch — Chrome needs a stable path."""
        self.assertEqual(self.bridge.extension_dir(), self.data / "extension")
        self.assertTrue(self.bridge.ensure_extension_files())
        self.assertTrue((self.data / "extension" / "manifest.json").is_file())
        self.assertTrue(
            (self.data / "extension" / "src" / "background" / "service-worker.js").is_file())

    def test_is_idempotent_for_the_same_version(self):
        self.assertTrue(self.bridge.ensure_extension_files())
        marker = self.data / "extension" / "marker.tmp"
        marker.write_text("x", encoding="utf-8")
        self.assertTrue(self.bridge.ensure_extension_files())
        self.assertTrue(marker.exists(), "same version should not re-copy")

    def test_refreshes_when_the_version_changes(self):
        self.assertTrue(self.bridge.ensure_extension_files())
        stale = self.data / "extension" / "stale.js"
        stale.write_text("removed upstream", encoding="utf-8")
        (self.data / "extension" / ".version").write_text("0.0.1", encoding="utf-8")

        self.assertTrue(self.bridge.ensure_extension_files())
        self.assertFalse(stale.exists(),
                         "a file removed upstream must not survive an update")

    def test_register_fails_closed_without_a_bundled_extension(self):
        """No extension to load means no 'Connected' claim."""
        import shutil as _shutil

        _shutil.rmtree(self.meipass / "extension")
        self.assertIsNone(self.bridge._bundled_source())
        self.assertFalse(self.bridge.ensure_extension_files())
        self.assertEqual(self.bridge.register(), [])

    def test_private_key_is_never_bundled(self):
        """extension/.keys/ signs the pinned extension ID; shipping it would
        let anyone build an extension the user's host already authorizes.

        The structural guarantee is that collection walks only `extension/src`
        and picks up `manifest.json` explicitly — so anything at
        `extension/.keys` is unreachable by construction, not by an exclude
        list somebody has to remember to update.
        """
        repo = Path(__file__).resolve().parent.parent
        spec = (repo / "build" / "NoMorePwn.spec").read_text(encoding="utf-8")
        self.assertIn('os.walk(os.path.join(_ext, "src"))', spec,
                      "collection must be rooted at extension/src")
        self.assertNotIn("extension" + os.sep + ".keys",
                         str(repo / "extension" / "src"))

        # Whatever the bundled tree contains, it must not include a key.
        bundled = sorted(p.name for p in (self.meipass / "extension").rglob("*")
                         if p.is_file())
        self.assertNotIn(".keys", bundled)
        self.assertFalse([n for n in bundled if n.endswith(".pem")], bundled)

    def test_only_runtime_file_types_are_bundled(self):
        allowed = {".js", ".json", ".css", ".html"}
        for path in (self.meipass / "extension").rglob("*"):
            if path.is_file():
                self.assertIn(path.suffix, allowed, f"unexpected file: {path.name}")


class VersionComparisonTests(unittest.TestCase):
    """Numeric, not lexicographic — a string compare strands users on .9."""

    def test_numeric_component_ordering(self):
        self.assertTrue(updater.is_newer("1.0.10", "1.0.9"))
        self.assertFalse(updater.is_newer("1.0.9", "1.0.10"))
        self.assertTrue(updater.is_newer("1.2.0", "1.1.99"))
        self.assertTrue(updater.is_newer("2.0.0", "1.99.99"))

    def test_equal_is_not_newer(self):
        self.assertFalse(updater.is_newer("1.0.5", "1.0.5"))

    def test_v_prefix_is_tolerated(self):
        self.assertTrue(updater.is_newer("v1.0.6", "1.0.5"))
        self.assertFalse(updater.is_newer("v1.0.5", "v1.0.5"))

    def test_dev_builds_never_offered_an_update(self):
        """A source checkout reports 0.0.0-dev; it has no installer to replace."""
        self.assertIsNone(updater.parse_version("0.0.0-dev-garbage-x"))
        self.assertFalse(updater.is_newer("1.0.0", "garbage"))
        self.assertFalse(updater.is_newer("garbage", "1.0.0"))

    def test_downgrade_is_refused(self):
        self.assertFalse(updater.is_newer("0.9.0", "1.0.0"))


class UpdateCheckTests(unittest.TestCase):
    """Release parsing, checksum handling, and download verification."""

    INSTALLER = "NoMorePwn-1.0.9-Setup.exe"

    class _Resp:
        def __init__(self, status=200, payload=None, text="", chunks=None):
            self.status_code = status
            self._payload = payload
            self.text = text
            self._chunks = chunks or []

        def raise_for_status(self):
            if self.status_code >= 400:
                import requests
                raise requests.HTTPError(str(self.status_code))

        def json(self):
            if self._payload is None:
                raise ValueError("not json")
            return self._payload

        def iter_content(self, chunk_size=0):
            return iter(self._chunks)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _release_payload(self, *, prerelease=False, draft=False, assets=None):
        return {
            "tag_name": "v1.0.9",
            "html_url": "https://example.invalid/r",
            "body": "notes",
            "prerelease": prerelease,
            "draft": draft,
            "assets": assets if assets is not None else [
                {"name": self.INSTALLER, "size": 4,
                 "browser_download_url": "https://example.invalid/setup.exe"},
                {"name": "SHA256SUMS.txt",
                 "browser_download_url": "https://example.invalid/sums"},
            ],
        }

    def _session(self, routes):
        """A fake session whose .get dispatches on a substring of the URL."""
        test = self

        class _S:
            def get(self, url, **kw):
                for fragment, response in routes.items():
                    if fragment in url:
                        return response
                test.fail(f"unexpected URL: {url}")

        return _S()

    def test_parses_a_release_and_its_checksum(self):
        body = b"data"
        digest = hashlib.sha256(body).hexdigest()
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload()),
            "sums": self._Resp(text=f"{digest}  {self.INSTALLER}\n"),
        })
        rel = updater.fetch_latest("o", "r", session=session)
        self.assertEqual(rel.version, "1.0.9")
        self.assertEqual(rel.asset_name, self.INSTALLER)
        self.assertEqual(rel.sha256, digest)
        self.assertTrue(rel.has_checksum)

    def test_prerelease_is_refused(self):
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload(prerelease=True)),
        })
        with self.assertRaises(updater.UpdateError):
            updater.fetch_latest("o", "r", session=session)

    def test_draft_is_refused(self):
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload(draft=True)),
        })
        with self.assertRaises(updater.UpdateError):
            updater.fetch_latest("o", "r", session=session)

    def test_release_without_installer_is_an_error(self):
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload(assets=[
                {"name": "notes.txt", "browser_download_url": "u"}])),
        })
        with self.assertRaises(updater.UpdateError):
            updater.fetch_latest("o", "r", session=session)

    def test_portable_exe_is_not_mistaken_for_the_installer(self):
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload(assets=[
                {"name": "NoMorePwn-1.0.9-portable.exe", "size": 1,
                 "browser_download_url": "u"},
                {"name": self.INSTALLER, "size": 1, "browser_download_url": "u2"},
            ])),
        })
        self.assertEqual(
            updater.fetch_latest("o", "r", session=session).asset_name, self.INSTALLER)

    def test_unreachable_server_raises_update_error(self):
        import requests

        class _S:
            def get(self, *a, **kw):
                raise requests.ConnectionError("offline")

        with self.assertRaises(updater.UpdateError):
            updater.fetch_latest("o", "r", session=_S())

    def test_check_returns_none_when_current(self):
        session = self._session({
            "releases/latest": self._Resp(payload=self._release_payload()),
            "sums": self._Resp(text=""),
        })
        self.assertIsNone(updater.check("o", "r", "1.0.9", session=session))
        self.assertIsNone(updater.check("o", "r", "1.1.0", session=session))
        self.assertIsNotNone(updater.check("o", "r", "1.0.8", session=session))

    # -- download verification ------------------------------------------

    def _release(self, sha256, size=4):
        return updater.Release(
            version="1.0.9", tag="v1.0.9", page_url="", asset_name=self.INSTALLER,
            asset_url="https://example.invalid/setup.exe", asset_size=size,
            sha256=sha256, notes="")

    def test_download_writes_a_verified_file(self):
        body = b"data"
        rel = self._release(hashlib.sha256(body).hexdigest())
        session = self._session({"setup.exe": self._Resp(chunks=[body])})
        with tempfile.TemporaryDirectory() as tmp:
            path = updater.download(rel, Path(tmp), session=session)
            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), body)

    def test_checksum_mismatch_raises_and_deletes_the_file(self):
        """A file that failed verification must never survive on disk."""
        rel = self._release(hashlib.sha256(b"expected").hexdigest())
        session = self._session({"setup.exe": self._Resp(chunks=[b"tampered"])})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(updater.UpdateError):
                updater.download(rel, Path(tmp), session=session)
            self.assertEqual(list(Path(tmp).glob("*")), [],
                             "unverified installer was left on disk")

    def test_oversized_download_is_aborted_and_removed(self):
        rel = self._release(None)
        chunk = b"x" * (1024 * 1024)
        huge = [chunk] * (updater.MAX_DOWNLOAD_BYTES // len(chunk) + 2)
        session = self._session({"setup.exe": self._Resp(chunks=huge)})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(updater.UpdateError):
                updater.download(rel, Path(tmp), session=session)
            self.assertEqual(list(Path(tmp).glob("*")), [])

    def test_empty_download_is_rejected(self):
        rel = self._release(None)
        session = self._session({"setup.exe": self._Resp(chunks=[])})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(updater.UpdateError):
                updater.download(rel, Path(tmp), session=session)

    def test_network_failure_mid_download_leaves_nothing_behind(self):
        import requests

        rel = self._release(None)

        class _Broken(self._Resp):
            def iter_content(self, chunk_size=0):
                yield b"partial"
                raise requests.ConnectionError("dropped")

        session = self._session({"setup.exe": _Broken()})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(updater.UpdateError):
                updater.download(rel, Path(tmp), session=session)
            self.assertEqual(list(Path(tmp).glob("*")), [])

    def test_checksum_parser_ignores_junk_lines(self):
        digest = "a" * 64
        parsed = updater._parse_checksums(
            f"# comment\n\n{digest}  file.exe\nnot-a-hash  other.exe\n")
        self.assertEqual(parsed, {"file.exe": digest})


class NativeHostTests(unittest.TestCase):
    """The browser-facing host process: framing and status reporting.

    ``vaultPresent`` is asserted in BOTH directions on purpose. Asserting only
    the False case passes even when the check is permanently broken — which is
    how a ``config.VAULT_PATH`` typo (the attribute is ``DB_PATH``) survived,
    swallowed by an over-broad except.
    """

    def setUp(self):
        from nomorepwn_app import native_host

        self.host = native_host
        self.tmp = tempfile.mkdtemp()
        self._real_db_path = config_module.DB_PATH
        config_module.DB_PATH = Path(self.tmp) / "vault.db"

    def tearDown(self):
        config_module.DB_PATH = self._real_db_path

    def test_reports_absent_vault(self):
        self.assertFalse(self.host._vault_present())

    def test_reports_present_vault(self):
        vault.create_vault(config_module.DB_PATH, MASTER)
        self.assertTrue(self.host._vault_present())

    def test_ping_reports_identity_and_protocol(self):
        reply = self.host._handle({"type": "ping"})
        self.assertEqual(reply["type"], "pong")
        self.assertEqual(reply["app"], "NoMorePwn")
        self.assertEqual(reply["protocol"], self.host.PROTOCOL_VERSION)

    def test_ping_reflects_a_real_vault(self):
        self.assertFalse(self.host._handle({"type": "ping"})["vaultPresent"])
        vault.create_vault(config_module.DB_PATH, MASTER)
        self.assertTrue(self.host._handle({"type": "ping"})["vaultPresent"])

    def test_save_is_refused_not_silently_dropped(self):
        from unittest.mock import patch, MagicMock
        with patch("PySide6.QtNetwork.QLocalSocket") as mock_sock_class, \
             patch("PySide6.QtCore.QCoreApplication") as mock_app_class:
            mock_sock = MagicMock()
            mock_sock.waitForConnected.return_value = False
            mock_sock_class.return_value = mock_sock
            mock_app_class.instance.return_value = MagicMock()
            
            reply = self.host._handle({"type": "save-credential", "password": "s3cret"})
            self.assertEqual(reply["type"], "error")
            self.assertEqual(reply["code"], "app-not-reachable")
            self.assertNotIn("s3cret", json.dumps(reply))

    def test_unknown_type_is_an_error(self):
        self.assertEqual(self.host._handle({"type": "nope"})["code"], "unknown-type")

    def test_frames_roundtrip(self):
        import io
        import struct

        buf = io.BytesIO()
        self.host._send(buf, {"type": "ping"})
        buf.seek(0)
        self.assertEqual(self.host._read(buf), {"type": "ping"})

        # A truncated frame must read as end-of-stream, not raise.
        self.assertIsNone(self.host._read(io.BytesIO(struct.pack("<I", 99) + b"{}")))
        self.assertIsNone(self.host._read(io.BytesIO(b"")))

    def test_oversized_frame_is_rejected(self):
        import io
        import struct

        too_big = struct.pack("<I", self.host.MAX_MESSAGE_BYTES + 1)
        self.assertIsNone(self.host._read(io.BytesIO(too_big + b"x")))


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


class RekeyTests(unittest.TestCase):
    """Vault.rekey: re-encrypt every secret under a new master password."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = self.dir / "vault.db"
        vault.create_vault(self.db_path, MASTER)
        self.vault = vault.Vault.unlock(self.db_path, MASTER)
        self.cid = self.vault.add_credential(
            "github.com", "alice", "s3cret-pass", "notes here", True
        )
        self.vault.add_credential("gmail.com", "bob", "another-pass")
        self.vault.update_password(self.cid, "s3cret-pass-v2")  # a second history row

    def tearDown(self):
        self.tmp.cleanup()

    NEW = "a whole new master phrase"

    def test_rekey_round_trips_every_secret(self):
        self.vault.rekey(self.NEW)
        # The live object now works under the new key ...
        self.assertEqual(self.vault.reveal_password(self.cid), "s3cret-pass-v2")
        self.assertEqual(self.vault.reveal_notes(self.cid), "notes here")
        # ... and so does a fresh unlock with the new password.
        reopened = vault.Vault.unlock(self.db_path, self.NEW)
        self.assertEqual(reopened.reveal_password(self.cid), "s3cret-pass-v2")
        self.assertEqual(reopened.reveal_notes(self.cid), "notes here")
        gmail = next(c for c in reopened.list_credentials()
                     if c["service_name"] == "gmail.com")
        self.assertEqual(reopened.reveal_password(gmail["id"]), "another-pass")

    def test_old_password_no_longer_opens_the_vault(self):
        self.vault.rekey(self.NEW)
        with self.assertRaises(vault.InvalidMasterPasswordError):
            vault.Vault.unlock(self.db_path, MASTER)

    def test_rekey_keeps_integrity_clean(self):
        self.vault.rekey(self.NEW)
        reopened = vault.Vault.unlock(self.db_path, self.NEW)
        # No false tamper alarms: the mirror history row still matches the
        # current ciphertext (invariant 7) and every blob decrypts.
        self.assertEqual(reopened.verify_integrity(), [])

    def test_rekey_preserves_history(self):
        before = self.vault.password_history(self.cid)
        self.vault.rekey(self.NEW)
        reopened = vault.Vault.unlock(self.db_path, self.NEW)
        after = reopened.password_history(self.cid)
        self.assertEqual(len(after), len(before))
        self.assertTrue(all(h["checksum_ok"] for h in after))

    def test_pre_rekey_snapshot_is_written_and_opens_with_old_password(self):
        self.vault.rekey(self.NEW)
        snap = vault.pre_rekey_backup_path(self.db_path)
        self.assertTrue(snap.exists())
        # The snapshot is the untouched pre-rekey vault: still the OLD password.
        recovered = vault.Vault.unlock(snap, MASTER)
        self.assertEqual(recovered.reveal_password(self.cid), "s3cret-pass-v2")

    def test_rekey_rejects_a_short_password(self):
        with self.assertRaises(vault.VaultError):
            self.vault.rekey("short")

    def test_rekey_rewraps_a_backup_passphrase_key(self):
        phrase = "a separate backup phrase"
        self.vault.set_backup_passphrase(phrase)
        self.vault.rekey(self.NEW)
        reopened = vault.Vault.unlock(self.db_path, self.NEW)
        self.assertTrue(reopened.has_backup_passphrase())
        dest = self.dir / "b.nmpbak"
        reopened.write_backup(dest)
        # The backup still opens with the (unchanged) passphrase after a rekey.
        backup.open_blob(dest.read_bytes(), phrase)


class RecoveryKitTests(unittest.TestCase):
    """Out-of-band Recovery Kit: escrow the master key, recover, rekey."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = self.dir / "vault.db"
        vault.create_vault(self.db_path, MASTER)
        self.vault = vault.Vault.unlock(self.db_path, MASTER)
        self.cid = self.vault.add_credential(
            "github.com", "alice", "s3cret-pass", "notes here", True
        )

    def tearDown(self):
        self.tmp.cleanup()

    NEW = "recovered master phrase"

    # -- recovery code round-trip ---------------------------------------

    def test_recovery_code_round_trips(self):
        r = recovery.generate_recovery_key()
        self.assertEqual(recovery.decode_recovery_code(recovery.encode_recovery_code(r)), r)
        # Tolerant of spacing/case the user might introduce transcribing it.
        code = recovery.encode_recovery_code(r)
        self.assertEqual(recovery.decode_recovery_code(code.lower().replace("-", " ")), r)

    def test_malformed_recovery_code_rejected(self):
        for bad in ("", "not base32 !!!", "AAAA"):
            with self.assertRaises(recovery.RecoveryError):
                recovery.decode_recovery_code(bad)

    # -- kit mode -------------------------------------------------------

    def test_kit_mode_recover_then_rekey(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        self.vault.lock()
        rv = vault.Vault.unlock_with_recovery(
            self.db_path, kit["kit_bytes"], kit["recovery_code"]
        )
        self.assertEqual(rv.reveal_password(self.cid), "s3cret-pass")
        self.assertEqual(rv.reveal_notes(self.cid), "notes here")
        rv.rekey(self.NEW)
        self.assertEqual(
            vault.Vault.unlock(self.db_path, self.NEW).reveal_password(self.cid),
            "s3cret-pass",
        )

    def test_kit_mode_wrong_code_fails(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        wrong = recovery.encode_recovery_code(recovery.generate_recovery_key())
        with self.assertRaises(recovery.RecoveryError):
            vault.Vault.unlock_with_recovery(self.db_path, kit["kit_bytes"], wrong)

    # -- kit + TOTP mode ------------------------------------------------

    def test_kit_totp_needs_both_factors(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT_TOTP)
        code, seed = kit["recovery_code"], kit["totp_secret"]
        self.vault.lock()
        # code alone (no seed) is not enough
        with self.assertRaises(recovery.RecoveryError):
            vault.Vault.unlock_with_recovery(self.db_path, kit["kit_bytes"], code)
        # code + wrong seed is not enough
        wrong_seed = recovery.generate_totp_secret()
        with self.assertRaises(recovery.RecoveryError):
            vault.Vault.unlock_with_recovery(self.db_path, kit["kit_bytes"], code, wrong_seed)
        # code + correct seed works
        rv = vault.Vault.unlock_with_recovery(self.db_path, kit["kit_bytes"], code, seed)
        self.assertEqual(rv.reveal_password(self.cid), "s3cret-pass")

    def test_kit_totp_provisioning_uri_is_offline_otpauth(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT_TOTP)
        self.assertTrue(kit["totp_uri"].startswith("otpauth://totp/"))
        self.assertIn("NoMorePwn", kit["totp_uri"])

    def test_verify_totp_accepts_current_rejects_wrong(self):
        secret = recovery.generate_totp_secret()
        import pyotp
        self.assertTrue(recovery.verify_totp(secret, pyotp.TOTP(secret).now()))
        self.assertFalse(recovery.verify_totp(secret, "000000"))

    # -- binding & tamper -----------------------------------------------

    def test_kit_is_bound_to_its_vault(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        # A second, unrelated vault must reject this kit even with the code.
        other = self.dir / "other.db"
        vault.create_vault(other, MASTER)
        with self.assertRaises(recovery.RecoveryError):
            vault.Vault.unlock_with_recovery(other, kit["kit_bytes"], kit["recovery_code"])

    def test_malformed_verifier_fails_closed_not_crash(self):
        # A tampered verifier meta must surface as a clean recovery failure,
        # not an uncaught ValueError from bytes.fromhex.
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        with db.connect(self.db_path) as conn:
            db.set_meta(conn, "verifier", "not-hex-at-all")
        with self.assertRaises(recovery.RecoveryError):
            vault.Vault.unlock_with_recovery(
                self.db_path, kit["kit_bytes"], kit["recovery_code"])

    def test_tampered_kit_header_fails_to_open(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        blob = bytearray(kit["kit_bytes"])
        # Flip a byte in the header region (right after magic + length).
        blob[len(recovery.MAGIC) + 6] ^= 0xFF
        with self.assertRaises(recovery.RecoveryError):
            recovery.open_kit(bytes(blob), kit["recovery_code"])

    def test_corrupt_kit_raises_recovery_error(self):
        for bad in (
            b"not a kit at all",
            recovery.MAGIC,                                   # no length field
            recovery.MAGIC + (5).to_bytes(4, "big") + b"xx",  # claims 5, has 2
            recovery.MAGIC + (4).to_bytes(4, "big") + b"notj",
            recovery.MAGIC + (10 ** 9).to_bytes(4, "big") + b"x",
        ):
            with self.assertRaises(recovery.RecoveryError):
                recovery.read_kit_header(bad)

    def test_lazy_vault_id_for_pre_recovery_vaults(self):
        # A vault created before recovery existed has no vault_id; making a kit
        # generates one rather than failing.
        with db.connect(self.db_path) as conn:
            db.delete_meta(conn, "vault_id")
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT)
        with db.connect(self.db_path) as conn:
            stored = db.get_meta(conn, "vault_id")
        self.assertIsNotNone(stored)
        self.assertEqual(kit["vault_id"], stored)

    # -- the core security property -------------------------------------

    def test_no_recovery_material_touches_vault_or_backup(self):
        kit = self.vault.create_recovery_kit(mode=recovery.MODE_KIT_TOTP)
        code_raw = kit["recovery_code"].replace("-", "").encode()
        seed_raw = kit["totp_secret"].encode()
        secrets_present = [kit["kit_bytes"], code_raw, seed_raw]

        vault_bytes = self.db_path.read_bytes()
        dest = self.dir / "b.nmpbak"
        self.vault.write_backup(dest)
        backup_bytes = dest.read_bytes()

        for needle in secrets_present:
            self.assertNotIn(needle, vault_bytes, "recovery secret leaked into vault.db")
            self.assertNotIn(needle, backup_bytes, "recovery secret leaked into .nmpbak")


if __name__ == "__main__":
    unittest.main()
