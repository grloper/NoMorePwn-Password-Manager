"""Multi-source breach checking with k-anonymity.

Why multiple sources
--------------------
No single "pwned passwords" corpus is complete. HIBP's Pwned Passwords
list only contains passwords that were dumped in plaintext or cracked
form — your account can be in a breach while your exact password string
never enters that corpus. To reduce false negatives, every password is
checked against ALL available sources, and a password counts as
breached if ANY source knows it:

* **HIBP Pwned Passwords** — SHA-1 hashed locally; only the FIRST 5 hex
  characters are sent to ``api.pwnedpasswords.com/range/``. Suffix
  comparison happens locally. The ``Add-Padding`` header hides the
  bucket size.
* **XposedOrNot** — Keccak-512 hashed locally; only the FIRST 10 hex
  characters (of 128) are sent to ``passwords.xposedornot.com``. Same
  k-anonymity property: the service sees a bucket prefix, never the
  password or its full hash.

Account-level exposure (``check_email_exposure``) answers a different
question: *has this email appeared in a breach at all?* — which catches
breaches where the password itself wasn't dumped. PRIVACY TRADEOFF:
unlike the password checks, this sends the FULL email address to
XposedOrNot (and to HIBP if you supply a paid API key). It is therefore
strictly opt-in in the UI and never runs automatically.

The raw password never leaves the machine under any code path.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field

import requests

try:
    from Crypto.Hash import keccak as _keccak  # pycryptodome

    HAS_KECCAK = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_KECCAK = False

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
XON_PASSWORD_URL = "https://passwords.xposedornot.com/api/v1/pass/anon/{prefix}"
XON_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/{email}"

_USER_AGENT = "NoMorePwn-local-security-audit"
DEFAULT_TIMEOUT = 10


class LeakCheckError(Exception):
    """Network or API failure — distinct from 'not found in breaches'."""


@dataclass
class PasswordLeakResult:
    """Aggregated verdict across all password corpora.

    ``sources`` maps source name -> occurrence count, or ``None`` if
    that source could not be reached (so callers can distinguish
    'clean' from 'unchecked').
    """

    breached: bool
    worst_count: int
    sources: dict[str, int | None] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class EmailExposureResult:
    """Breaches in which an email address itself has appeared."""

    email: str
    breaches: list[dict] = field(default_factory=list)  # {"name", "sources"}
    sources_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return bool(self.breaches)


# ---------------------------------------------------------------------------
# Password corpora (k-anonymity — only hash prefixes leave the machine)
# ---------------------------------------------------------------------------

# A genuine HIBP range line: 35 hex chars of hash suffix, colon, count.
_HIBP_LINE_RE = re.compile(r"^[0-9A-F]{35}:\d+$")


def check_password_hibp(password: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    """HIBP Pwned Passwords range query. 5 SHA-1 hex chars sent."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise LeakCheckError(f"HIBP range query failed: {exc}") from exc

    lines = [line.strip() for line in response.text.splitlines() if line.strip()]
    # A corporate proxy or captive portal returning HTML with HTTP 200 must
    # surface as an ERROR, never as a false "clean" verdict.
    if not lines or not all(_HIBP_LINE_RE.match(line) for line in lines):
        raise LeakCheckError(
            "HIBP returned an unrecognized response body — something (proxy, "
            "captive portal) may be intercepting the request. Verdict withheld."
        )

    for line in lines:
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            occurrences = int(count)
            # Padding entries are returned with a count of 0 — not real hits.
            return occurrences if occurrences > 0 else 0
    return 0


def check_password_xon(password: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    """XposedOrNot anonymized query. 10 Keccak-512 hex chars sent."""
    if not HAS_KECCAK:
        raise LeakCheckError(
            "XposedOrNot check needs pycryptodome (pip install pycryptodome)."
        )
    digest = _keccak.new(digest_bits=512)
    digest.update(password.encode("utf-8"))
    prefix = digest.hexdigest()[:10]

    try:
        response = requests.get(
            XON_PASSWORD_URL.format(prefix=prefix),
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
        )
        if response.status_code == 404:
            return 0  # documented "not in corpus" response
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise LeakCheckError(f"XposedOrNot query failed: {exc}") from exc

    try:
        return int(payload["SearchPassAnon"]["count"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LeakCheckError(f"XposedOrNot returned an unexpected payload: {payload!r}") from exc


def password_sources() -> list[tuple[str, object]]:
    """Available corpora, in check order."""
    sources: list[tuple[str, object]] = [("HIBP Pwned Passwords", check_password_hibp)]
    if HAS_KECCAK:
        sources.append(("XposedOrNot", check_password_xon))
    return sources


def check_password(password: str, timeout: int = DEFAULT_TIMEOUT) -> PasswordLeakResult:
    """Check `password` against every available corpus.

    Breached if ANY source reports it. A source that fails is recorded
    as ``None`` with an error note instead of poisoning the whole
    check; only if EVERY source fails does this raise LeakCheckError,
    so callers can never mistake "couldn't check" for "clean".
    """
    sources: dict[str, int | None] = {}
    errors: list[str] = []
    for name, checker in password_sources():
        try:
            sources[name] = checker(password, timeout)
        except LeakCheckError as exc:
            sources[name] = None
            errors.append(str(exc))

    if all(count is None for count in sources.values()):
        raise LeakCheckError("All breach sources failed: " + " | ".join(errors))

    counts = [count for count in sources.values() if count]
    return PasswordLeakResult(
        breached=bool(counts),
        worst_count=max(counts, default=0),
        sources=sources,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# False-negative diagnostics: invisible characters & Unicode form
#
# Breach corpora hash the password byte-for-byte. A stored copy that
# differs from the "real" password by a single invisible character —
# a trailing space from a notepad import, a non-breaking space from a
# paste, an NFD-composed accent from macOS — hashes to a completely
# different value and reports as clean even though the real password
# is breached. These helpers surface such near-miss variants.
# ---------------------------------------------------------------------------

_INVISIBLE_CHARS = {
    "\u00a0": "non-breaking space",
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\ufeff": "byte-order mark",
}


def password_anomalies(password: str) -> list[str]:
    """Human-readable red flags that make breach checks silently miss."""
    notes = []
    if password != password.strip():
        notes.append("leading/trailing whitespace")
    for char, label in _INVISIBLE_CHARS.items():
        if char in password:
            notes.append(f"{label} (U+{ord(char):04X})")
    if unicodedata.normalize("NFC", password) != password:
        notes.append("non-NFC Unicode form (e.g. macOS decomposed accents)")
    return notes


def password_variants(password: str) -> dict[str, str]:
    """The stored string plus cleaned-up variants worth checking too."""
    variants = {"as stored": password}

    stripped = password.strip()
    if stripped and stripped != password:
        variants["whitespace-trimmed"] = stripped

    cleaned = stripped or password
    for char in _INVISIBLE_CHARS:
        cleaned = cleaned.replace(char, "")
    if cleaned and cleaned not in variants.values():
        variants["invisible-chars-removed"] = cleaned

    nfc = unicodedata.normalize("NFC", password)
    if nfc not in variants.values():
        variants["NFC-normalized"] = nfc

    return variants


def check_password_thorough(
    password: str, timeout: int = DEFAULT_TIMEOUT
) -> dict[str, PasswordLeakResult]:
    """Check the stored string AND its anomaly-corrected variants.

    If "as stored" is clean but "whitespace-trimmed" is breached, the
    vault almost certainly holds a corrupted copy of a breached
    password — the UI treats that as a full alarm, not a clean bill.
    """
    return {
        label: check_password(variant, timeout)
        for label, variant in password_variants(password).items()
    }


# ---------------------------------------------------------------------------
# Account-level exposure (sends the FULL email — strictly opt-in)
# ---------------------------------------------------------------------------

def _check_email_xon(email: str, timeout: int) -> list[str]:
    try:
        response = requests.get(
            XON_EMAIL_URL.format(email=email),
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
        )
        if response.status_code == 404:
            return []  # not found in any breach
        if response.status_code == 429:
            raise LeakCheckError(
                "XposedOrNot rate limit hit (free tier: ~25 email checks/hour). "
                "Try again later."
            )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise LeakCheckError(f"XposedOrNot email query failed: {exc}") from exc

    groups = payload.get("breaches") or []
    return [str(name) for group in groups for name in group]


def _check_email_hibp(email: str, api_key: str, timeout: int) -> list[str]:
    try:
        response = requests.get(
            HIBP_ACCOUNT_URL.format(email=email),
            headers={"User-Agent": _USER_AGENT, "hibp-api-key": api_key},
            params={"truncateResponse": "true"},
            timeout=timeout,
        )
        if response.status_code == 404:
            return []
        if response.status_code == 401:
            raise LeakCheckError("HIBP rejected the API key (check HIBP_API_KEY).")
        if response.status_code == 429:
            raise LeakCheckError("HIBP rate limit hit — slow down and retry.")
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise LeakCheckError(f"HIBP account query failed: {exc}") from exc
    return [str(item.get("Name", "")) for item in payload if item.get("Name")]


def check_email_exposure(
    email: str,
    hibp_api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> EmailExposureResult:
    """Which known breaches contain `email`?

    Catches the case a password-corpus check cannot: the account was
    breached but the password dump was hashed/uncracked, so the
    password string is in no corpus. Always queries XposedOrNot (free);
    also queries HIBP's breachedaccount API when a paid key is given.
    Raises LeakCheckError only if every source fails.
    """
    if "@" not in email:
        raise LeakCheckError(f"{email!r} is not an email address.")

    found: dict[str, set[str]] = {}
    checked: list[str] = []
    errors: list[str] = []

    runners = [("XposedOrNot", lambda: _check_email_xon(email, timeout))]
    if hibp_api_key:
        runners.append(("HIBP", lambda: _check_email_hibp(email, hibp_api_key, timeout)))

    for source_name, runner in runners:
        try:
            names = runner()
        except LeakCheckError as exc:
            errors.append(str(exc))
            continue
        checked.append(source_name)
        for name in names:
            found.setdefault(name.strip(), set()).add(source_name)

    if not checked:
        raise LeakCheckError("All email exposure sources failed: " + " | ".join(errors))

    breaches = [
        {"name": name, "sources": sorted(srcs)}
        for name, srcs in sorted(found.items(), key=lambda kv: kv[0].lower())
    ]
    return EmailExposureResult(
        email=email, breaches=breaches, sources_checked=checked, errors=errors
    )
