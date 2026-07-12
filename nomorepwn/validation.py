"""Strict server-side input validation.

Every value that reaches the database layer passes through here first.
This is defense-in-depth: the database layer already neutralizes SQL
injection via parameterized queries, so validation's job is data
hygiene — enforcing character allowlists and hard length limits so
malformed or hostile input can never masquerade as a legitimate record.

Allowlist philosophy: service names and usernames accept alphanumerics
plus a small set of punctuation needed for real-world identifiers
(emails, domains). Passwords are intentionally permissive — restricting
password characters weakens security — but are length-capped and must
not contain control characters.
"""

from __future__ import annotations

import re

MAX_SERVICE_LEN = 64
MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_NOTES_LEN = 2000

# Must start alphanumeric; then alphanumerics, spaces, and . _ @ + : / -
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+:/-]*$")
# Usernames/emails: alphanumerics and . _ @ + - (no spaces).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]*$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(ValueError):
    """Raised when user input fails validation. Message is UI-safe."""


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string.")
    return value


def validate_service_name(value: object) -> str:
    value = _require_str(value, "Service name").strip()
    if not value:
        raise ValidationError("Service name is required.")
    if len(value) > MAX_SERVICE_LEN:
        raise ValidationError(f"Service name must be at most {MAX_SERVICE_LEN} characters.")
    if not _SERVICE_RE.fullmatch(value):
        raise ValidationError(
            "Service name may only contain letters, digits, spaces, and . _ @ + : / - "
            "and must start with a letter or digit."
        )
    return value


def validate_username(value: object) -> str:
    value = _require_str(value, "Username").strip()
    if not value:
        raise ValidationError("Username is required.")
    if len(value) > MAX_USERNAME_LEN:
        raise ValidationError(f"Username must be at most {MAX_USERNAME_LEN} characters.")
    if not _USERNAME_RE.fullmatch(value):
        raise ValidationError(
            "Username may only contain letters, digits, and . _ @ + - "
            "and must start with a letter or digit."
        )
    return value


def validate_password(value: object) -> str:
    value = _require_str(value, "Password")
    if not value:
        raise ValidationError("Password is required.")
    if len(value) > MAX_PASSWORD_LEN:
        raise ValidationError(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError("Password must not contain control characters.")
    return value


def validate_notes(value: object) -> str:
    value = _require_str(value, "Notes")
    if len(value) > MAX_NOTES_LEN:
        raise ValidationError(f"Notes must be at most {MAX_NOTES_LEN} characters.")
    # Newlines and tabs are fine in notes; all other control chars are not.
    if _CONTROL_CHARS_RE.search(value.replace("\n", "").replace("\t", "")):
        raise ValidationError("Notes must not contain control characters.")
    return value
