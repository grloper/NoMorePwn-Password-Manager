"""The native-messaging host process the browser launches.

Chrome speaks a simple framed protocol over the child process's stdio: a
4-byte little-endian length, then that many bytes of UTF-8 JSON, in both
directions. The browser starts this process; it is *not* the running desktop
app.

That distinction is the whole architecture:

    browser ──spawns──> native host (this file, short-lived, no GUI)
                              │
                              ╵  ...and has no access to the running app's
                                 in-memory master key.

The desktop app holds the master key in its own process's RAM and nowhere
else — by design. A freshly spawned host process therefore cannot read or
write vault secrets: it can see that a vault file exists, but not open it.

So this host currently answers status queries only. Actually saving a
credential needs one of:

  a) host → running app IPC (a local named pipe), so the unlocked app does
     the write and can show the save prompt; or
  b) the host prompting for the master password itself, which means a second
     place that handles master passwords.

(a) is the better shape and keeps the key in one process. Until that exists,
this host is deliberately read-only.

**Nothing may write to stdout except `_send`.** A stray print corrupts the
frame stream and the browser drops the connection — which is why the entry
points dispatch here before importing anything Qt-related.
"""

from __future__ import annotations

import json
import struct
import sys
from typing import Any

from nomorepwn import config

PROTOCOL_VERSION = 1

# Chrome caps a single message at 1 MB; anything larger is a framing bug.
MAX_MESSAGE_BYTES = 1024 * 1024


def _binary_stdio() -> tuple[Any, Any]:
    """Raw stdin/stdout, with newline translation disabled on Windows."""
    if sys.platform == "win32":
        import msvcrt
        import os

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    return sys.stdin.buffer, sys.stdout.buffer


def _read(stream) -> dict | None:
    """Read one framed message, or None at end of stream."""
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    if length == 0 or length > MAX_MESSAGE_BYTES:
        return None
    payload = stream.read(length)
    if len(payload) < length:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"type": "__malformed__"}


def _send(stream, message: dict) -> None:
    encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def _vault_present() -> bool:
    """Whether a vault file exists — NOT whether it can be opened.

    Only OSError is tolerated (an unreadable data directory). A broad
    ``except Exception`` here would turn a typo like ``config.VAULT_PATH``
    into a permanent, silent "no vault" — which is exactly how it read
    before this was narrowed.
    """
    from nomorepwn import vault

    try:
        return vault.vault_exists(config.DB_PATH)
    except OSError:
        return False


def _handle(message: dict) -> dict:
    kind = message.get("type")

    if kind == "ping":
        from . import __version__

        return {
            "type": "pong",
            "protocol": PROTOCOL_VERSION,
            "app": "NoMorePwn",
            "version": __version__,
            "vaultPresent": _vault_present(),
        }

    if kind == "save-credential":
        # See the module docstring: this process cannot reach the unlocked
        # vault. Refuse clearly rather than silently dropping the credential,
        # so the extension can keep its own state honest.
        return {
            "type": "error",
            "code": "not-implemented",
            "message": "Saving is not wired up yet: the host process cannot "
                       "reach the running app's unlocked vault.",
        }

    return {"type": "error", "code": "unknown-type", "message": f"Unsupported: {kind!r}"}


def run() -> int:
    """Serve messages until the browser closes the pipe."""
    stdin, stdout = _binary_stdio()
    while True:
        message = _read(stdin)
        if message is None:
            return 0
        try:
            _send(stdout, _handle(message))
        except OSError:
            return 0  # browser went away mid-write
