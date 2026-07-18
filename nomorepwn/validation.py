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
from dataclasses import dataclass

MAX_SERVICE_LEN = 64
MAX_GROUP_LEN = 48
MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_NOTES_LEN = 2000

# Must start alphanumeric; then alphanumerics, spaces, and . _ @ + : / -
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+:/-]*$")
# Usernames/emails: alphanumerics and . _ @ + - (no spaces).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]*$")
# Group labels: like service names, plus & for "Banking & Finance".
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._&@+-]*$")
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


def validate_group_name(value: object) -> str:
    """Validate a group label. Empty is valid and means 'ungrouped'.

    Unlike a service name, absence is a normal state — most credentials have
    no group — so this returns "" rather than raising on empty input.
    """
    if value is None:
        return ""
    value = _require_str(value, "Group").strip()
    if not value:
        return ""
    if len(value) > MAX_GROUP_LEN:
        raise ValidationError(f"Group must be at most {MAX_GROUP_LEN} characters.")
    if not _GROUP_RE.fullmatch(value):
        raise ValidationError(
            "Group may only contain letters, digits, spaces, and . _ & @ + - "
            "and must start with a letter or digit."
        )
    return value


def validate_alt_login(value: object) -> str:
    """Validate the optional second login identifier.

    Same character rules as a username — it is the same kind of value, just
    the one you use less often. Empty is valid and normal: most credentials
    have a single identifier.
    """
    if value is None:
        return ""
    value = _require_str(value, "Alternate login").strip()
    if not value:
        return ""
    if len(value) > MAX_USERNAME_LEN:
        raise ValidationError(
            f"Alternate login must be at most {MAX_USERNAME_LEN} characters.")
    if not _USERNAME_RE.fullmatch(value):
        raise ValidationError(
            "Alternate login may only contain letters, digits, and . _ @ + - "
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


# ----------------------------------------------------------------------
# Surrounding-whitespace inspection
# ----------------------------------------------------------------------
#
# A password that ends with a space is almost always a copy-paste artifact —
# and today it is saved silently, so the user only finds out when the login
# fails. But it can also be deliberate, and a password is exactly the kind of
# value we must not "helpfully" rewrite: silently trimming one locks the user
# out of the account it belongs to.
#
# So this module *describes* the whitespace and never removes it. Stripping is
# a decision for the person who typed it, made in a prompt. This is why
# `validate_password` still does not call `.strip()` and must not start.

_WS_NAMES = {
    " ": "a space",
    "\t": "a tab",
    "\n": "a newline",
    "\r": "a carriage return",
    " ": "a non-breaking space",
}


def _describe_run(chunk: str) -> str:
    """Name a run of whitespace in words, e.g. 'a space' / '3 spaces'."""
    kinds = {_WS_NAMES.get(c, "a whitespace character") for c in chunk}
    if len(chunk) == 1:
        return _WS_NAMES.get(chunk, "a whitespace character")
    if len(kinds) == 1:
        # "a space" -> "spaces"; keeps the plural readable.
        single = kinds.pop()
        noun = single.split(" ", 1)[1] if single.startswith("a ") else single
        return f"{len(chunk)} {noun}s"
    return f"{len(chunk)} whitespace characters"


@dataclass(frozen=True)
class WhitespaceFinding:
    """What surrounding whitespace a password carries.

    Purely descriptive: ``cleaned`` is what the value *would* be, never what
    it becomes. Nothing here mutates the password.
    """

    leading: str
    trailing: str
    cleaned: str

    @property
    def found(self) -> bool:
        return bool(self.leading or self.trailing)

    @property
    def cleaned_is_empty(self) -> bool:
        """True when the password is nothing *but* whitespace.

        Removing it would leave an empty password, so callers must not offer
        the fix in this case.
        """
        return not self.cleaned

    def describe(self) -> str:
        """A UI-safe sentence naming what was found."""
        if self.leading and self.trailing:
            return (f"This password starts with {_describe_run(self.leading)} "
                    f"and ends with {_describe_run(self.trailing)}.")
        if self.trailing:
            return f"This password ends with {_describe_run(self.trailing)}."
        if self.leading:
            return f"This password starts with {_describe_run(self.leading)}."
        return ""


def inspect_password_whitespace(value: object) -> WhitespaceFinding:
    """Report leading/trailing whitespace on a password without altering it."""
    if not isinstance(value, str) or not value:
        return WhitespaceFinding("", "", value if isinstance(value, str) else "")
    lead_len = len(value) - len(value.lstrip())
    trail_len = len(value) - len(value.rstrip())
    return WhitespaceFinding(
        leading=value[:lead_len],
        trailing=value[len(value) - trail_len:],
        cleaned=value.strip(),
    )


def validate_notes(value: object) -> str:
    value = _require_str(value, "Notes")
    if len(value) > MAX_NOTES_LEN:
        raise ValidationError(f"Notes must be at most {MAX_NOTES_LEN} characters.")
    # Newlines and tabs are fine in notes; all other control chars are not.
    if _CONTROL_CHARS_RE.search(value.replace("\n", "").replace("\t", "")):
        raise ValidationError("Notes must not contain control characters.")
    return value
