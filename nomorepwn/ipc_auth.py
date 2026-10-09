"""Per-install shared secret authenticating local IPC messages.

The desktop app listens on a local socket; the native-messaging host (and a
second launch of the app) connect to it. Every message must carry the token
stored here, in a file only the current user can read (POSIX mode 0600; on
Windows the file lives in the per-user %APPDATA% directory and inherits its
ACL, since POSIX modes are not enforceable there).
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from . import config

TOKEN_FILENAME = "ipc.token"
TOKEN_BYTES = 32


def token_path() -> Path:
    return Path(config.DATA_DIR) / TOKEN_FILENAME


def _write_new(path: Path) -> str:
    token = secrets.token_hex(TOKEN_BYTES)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(token)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return token


def load_or_create_token() -> str:
    """Return the install token, creating it (0600) on first use. App side."""
    config.ensure_data_dir()
    path = token_path()
    existing = read_token()
    if existing:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return existing
    return _write_new(path)


def read_token() -> str | None:
    """Return the token if present and well-formed; never creates it. Client side."""
    try:
        value = token_path().read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if len(value) != TOKEN_BYTES * 2:
        return None
    return value


def verify(candidate: object) -> bool:
    """Constant-time check of a presented token against the stored one."""
    if not isinstance(candidate, str):
        return False
    expected = read_token()
    if expected is None:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("ascii"))
