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

SCHEMA_VERSION = 1

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
) -> int:
    cursor = conn.execute(
        "INSERT INTO credentials "
        "(uuid, service_name, username, password_enc, password_sha256, "
        " notes_enc, mfa_enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            uuid,
            service_name,
            username,
            password_enc,
            password_sha256,
            notes_enc,
            1 if mfa_enabled else 0,
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
