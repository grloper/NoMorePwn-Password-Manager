"""SQLite data layer — the ONLY module allowed to touch the database.

SQL injection policy (enforced by convention and by tests):

1. Every statement in this file is a static string literal. SQL text is
   never built with f-strings, ``%`` formatting, ``+`` concatenation,
   or ``str.format``.
2. Every user-influenced value is bound as a parameter (``?``) and
   passed to the driver as a tuple, letting SQLite handle typing and
   quoting: ``conn.execute("... WHERE id = ?", (cred_id,))``.
3. Identifiers (table/column names) are never taken from input.

Anything above this layer (vault logic, UI, import scripts) has no way
to construct SQL at all.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT    NOT NULL UNIQUE,
    service_name    TEXT    NOT NULL,
    username        TEXT    NOT NULL,
    password_enc    BLOB    NOT NULL,
    password_sha256 TEXT    NOT NULL,
    notes_enc       BLOB,
    mfa_enabled     INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
    group_name      TEXT    NOT NULL DEFAULT '',
    alt_login       TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    UNIQUE (service_name, username)
);

CREATE TABLE IF NOT EXISTS password_history (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id     INTEGER NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    password_enc      BLOB    NOT NULL,
    ciphertext_sha256 TEXT    NOT NULL,
    changed_at        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_credential
    ON password_history (credential_id, changed_at);
"""


@contextmanager
def connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Short-lived connection with safe defaults; commits on success."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)


# --------------------------------------------------------------------------
# Schema migration
# --------------------------------------------------------------------------
#
# `init_schema` only ever runs inside `create_vault`, so a vault created by an
# older build keeps its original columns forever. Until v2 the version number
# was write-only — bumping it migrated nothing. These functions make it real.
#
# Rules for anything added here:
#   * Migrations run inside the caller's transaction and must be idempotent —
#     re-running one must be a no-op, so a crash mid-upgrade is recoverable.
#   * Never rewrite `password_enc`, `notes_enc`, or a row's `uuid`. The AAD is
#     bound to the uuid (`cred:{uuid}:password`), so touching it makes every
#     secret permanently undecryptable and there is no rekey path in this repo.
#   * Adding a column is safe precisely because it does not touch either.

def read_schema_version(conn: sqlite3.Connection) -> int:
    """The schema version on disk. Vaults predating versioning read as 1."""
    raw = get_meta(conn, "schema_version")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 1


def credential_columns(conn: sqlite3.Connection) -> set[str]:
    """Column names on `credentials`. Static SQL; the table name is a literal."""
    return {row["name"] for row in conn.execute("PRAGMA table_info(credentials)")}


def _migrate_to_v2(conn: sqlite3.Connection) -> None:
    """v2: user-assigned groups.

    Plaintext, like `service_name` and `username` beside it — group names are
    filterable metadata, not secrets. `DEFAULT ''` means every existing
    credential lands in the ungrouped bucket rather than needing a backfill.
    """
    if "group_name" not in credential_columns(conn):
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN group_name TEXT NOT NULL DEFAULT ''"
        )


def _migrate_to_v3(conn: sqlite3.Connection) -> None:
    """v3: an optional second login identifier.

    Plenty of sites accept either a handle or an email. The alternate lives in
    its own column rather than in `notes` so it can be copied, searched and
    autocompleted — and because notes are the one field the editor can destroy
    on a failed decrypt. Identity stays `(service_name, username)`; the
    alternate is never part of duplicate detection.
    """
    if "alt_login" not in credential_columns(conn):
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN alt_login TEXT NOT NULL DEFAULT ''"
        )


_MIGRATIONS = {2: _migrate_to_v2, 3: _migrate_to_v3}


def migrate(conn: sqlite3.Connection) -> tuple[int, int]:
    """Upgrade the schema to SCHEMA_VERSION. Returns (from_version, to_version).

    A no-op when already current, so callers can invoke it on every unlock.
    """
    start = read_schema_version(conn)
    if start >= SCHEMA_VERSION:
        return start, start
    for version in range(start + 1, SCHEMA_VERSION + 1):
        step = _MIGRATIONS.get(version)
        if step is not None:
            step(conn)
        set_meta(conn, "schema_version", str(version))
    return start, SCHEMA_VERSION


def snapshot_bytes(db_path: str | Path) -> bytes:
    """Return a consistent byte-for-byte copy of the vault database.

    Uses SQLite's online-backup API rather than reading the file directly,
    so a snapshot taken while another connection is mid-write is still a
    valid database (never a torn page).
    """
    import tempfile

    src = sqlite3.connect(str(db_path))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "snapshot.db"
            dst = sqlite3.connect(str(dest))
            try:
                src.backup(dst)
            finally:
                dst.close()
            return dest.read_bytes()
    finally:
        src.close()


# --------------------------------------------------------------------------
# vault_meta
# --------------------------------------------------------------------------

def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute(
        "SELECT value FROM vault_meta WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else None


def delete_meta(conn: sqlite3.Connection, key: str) -> None:
    conn.execute("DELETE FROM vault_meta WHERE key = ?", (key,))


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------

def insert_credential(
    conn: sqlite3.Connection,
    *,
    uuid: str,
    service_name: str,
    username: str,
    password_enc: bytes,
    password_sha256: str,
    notes_enc: bytes | None,
    mfa_enabled: bool,
    now_iso: str,
    group_name: str = "",
    alt_login: str = "",
) -> int:
    cursor = conn.execute(
        "INSERT INTO credentials "
        "(uuid, service_name, username, password_enc, password_sha256, "
        " notes_enc, mfa_enabled, group_name, alt_login, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            uuid,
            service_name,
            username,
            password_enc,
            password_sha256,
            notes_enc,
            1 if mfa_enabled else 0,
            group_name,
            alt_login,
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.lastrowid)


def get_credential(conn: sqlite3.Connection, cred_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM credentials WHERE id = ?", (cred_id,)
    ).fetchone()


def list_credentials(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM credentials ORDER BY service_name COLLATE NOCASE, username"
    ).fetchall()


def find_credential(
    conn: sqlite3.Connection, service_name: str, username: str
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM credentials WHERE service_name = ? AND username = ?",
        (service_name, username),
    ).fetchone()


def update_credential_password(
    conn: sqlite3.Connection,
    cred_id: int,
    password_enc: bytes,
    password_sha256: str,
    now_iso: str,
) -> None:
    conn.execute(
        "UPDATE credentials "
        "SET password_enc = ?, password_sha256 = ?, updated_at = ? "
        "WHERE id = ?",
        (password_enc, password_sha256, now_iso, cred_id),
    )


def update_credential_meta(
    conn: sqlite3.Connection,
    cred_id: int,
    service_name: str,
    username: str,
    notes_enc: bytes | None,
    mfa_enabled: bool,
    now_iso: str,
    group_name: str = "",
    alt_login: str = "",
) -> None:
    """Update everything except the password (which has its own history path)."""
    conn.execute(
        "UPDATE credentials "
        "SET service_name = ?, username = ?, notes_enc = ?, mfa_enabled = ?, "
        "    group_name = ?, alt_login = ?, updated_at = ? "
        "WHERE id = ?",
        (service_name, username, notes_enc, 1 if mfa_enabled else 0,
         group_name, alt_login, now_iso, cred_id),
    )


def list_identifiers(conn: sqlite3.Connection) -> list[str]:
    """Every login identifier in use, most-reused first, for autocomplete.

    Unions `username` and `alt_login` so an address recorded as an alternate
    on one entry is still offered as the primary on the next.
    """
    rows = conn.execute(
        "SELECT value, COUNT(*) AS uses FROM ("
        "    SELECT username  AS value FROM credentials WHERE username  <> '' "
        "    UNION ALL "
        "    SELECT alt_login AS value FROM credentials WHERE alt_login <> '' "
        ") GROUP BY value COLLATE NOCASE "
        "ORDER BY uses DESC, value COLLATE NOCASE"
    ).fetchall()
    return [row["value"] for row in rows]


def list_group_names(conn: sqlite3.Connection) -> list[str]:
    """Distinct non-empty group names currently in use, alphabetically."""
    rows = conn.execute(
        "SELECT DISTINCT group_name FROM credentials "
        "WHERE group_name <> '' ORDER BY group_name COLLATE NOCASE"
    ).fetchall()
    return [row["group_name"] for row in rows]


def set_group_name(
    conn: sqlite3.Connection, cred_id: int, group_name: str, now_iso: str
) -> None:
    conn.execute(
        "UPDATE credentials SET group_name = ?, updated_at = ? WHERE id = ?",
        (group_name, now_iso, cred_id),
    )


def set_mfa_enabled(
    conn: sqlite3.Connection, cred_id: int, enabled: bool, now_iso: str
) -> None:
    conn.execute(
        "UPDATE credentials SET mfa_enabled = ?, updated_at = ? WHERE id = ?",
        (1 if enabled else 0, now_iso, cred_id),
    )


def delete_credential(conn: sqlite3.Connection, cred_id: int) -> None:
    conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))


# --------------------------------------------------------------------------
# password_history
# --------------------------------------------------------------------------

def insert_history(
    conn: sqlite3.Connection,
    *,
    credential_id: int,
    password_enc: bytes,
    ciphertext_sha256: str,
    changed_at_iso: str,
) -> None:
    conn.execute(
        "INSERT INTO password_history "
        "(credential_id, password_enc, ciphertext_sha256, changed_at) "
        "VALUES (?, ?, ?, ?)",
        (credential_id, password_enc, ciphertext_sha256, changed_at_iso),
    )


def list_history(conn: sqlite3.Connection, credential_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM password_history WHERE credential_id = ? "
        "ORDER BY changed_at DESC, id DESC",
        (credential_id,),
    ).fetchall()


def all_history(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT h.*, c.service_name, c.username, c.uuid "
        "FROM password_history AS h "
        "JOIN credentials AS c ON c.id = h.credential_id "
        "ORDER BY h.credential_id, h.changed_at DESC, h.id DESC"
    ).fetchall()


def latest_history_entry(
    conn: sqlite3.Connection, credential_id: int
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM password_history WHERE credential_id = ? "
        "ORDER BY changed_at DESC, id DESC LIMIT 1",
        (credential_id,),
    ).fetchone()
