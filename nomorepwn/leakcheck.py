"""HaveIBeenPwned breach check via k-anonymity.

Privacy model — what actually crosses the network:
1. The password is SHA-1 hashed **locally**.
2. Only the FIRST 5 hex characters of that hash are sent to
   ``https://api.pwnedpasswords.com/range/<prefix>``.
3. The API returns every known-breached hash suffix sharing that prefix
   (hundreds of candidates), and the full-hash comparison happens
   **locally**. HIBP never sees the password, its full hash, or even
   which of the returned suffixes (if any) matched.
4. The ``Add-Padding`` header makes HIBP pad responses with dummy
   entries so response size can't be used to fingerprint the prefix.

The raw password never leaves this function's stack frame.
Checks run only when the caller asks — never automatically on unlock.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_HEADERS = {
    # Identify ourselves per HIBP API etiquette; enable padded responses.
    "User-Agent": "NoMorePwn-local-security-audit",
    "Add-Padding": "true",
}
DEFAULT_TIMEOUT = 10

# HIBP throttles bulk callers with 429. It tells us how long to wait in
# Retry-After, so honour it rather than hammering and getting nothing.
MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 8.0


class LeakCheckError(Exception):
    """Network or API failure — distinct from 'not found in breaches'."""


def _retry_delay(response: requests.Response, attempt: int) -> float:
    """Seconds to wait before retrying a 429, from Retry-After if sane."""
    try:
        wait = float(response.headers.get("Retry-After", ""))
    except ValueError:
        wait = 0.0
    if wait <= 0:
        wait = 0.5 * (2 ** attempt)  # 0.5s, 1s, 2s …
    return min(wait, _MAX_BACKOFF_SECONDS)


def check_password(password: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    """Return how many times `password` appears in known breaches (0 = none).

    Raises LeakCheckError on network/API failure so callers never
    mistake "check didn't run" for "password is clean".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                HIBP_RANGE_URL.format(prefix=prefix),
                headers=_HEADERS,
                timeout=timeout,
            )
            if response.status_code == 429 and attempt < MAX_RETRIES - 1:
                time.sleep(_retry_delay(response, attempt))
                continue
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LeakCheckError(f"HIBP range query failed: {exc}") from exc
        break
    else:  # pragma: no cover - loop always breaks or raises
        raise LeakCheckError("HIBP range query failed: rate limited")

    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            occurrences = int(count.strip() or 0)
            # Padding entries are returned with a count of 0 — not real hits.
            return occurrences if occurrences > 0 else 0
    return 0


# Gap between bulk queries. A single check never waits; bursting a whole
# vault at the API is what earns a 429.
BULK_DELAY_SECONDS = 0.12


@dataclass
class ScanOutcome:
    """Result of a bulk scan, keeping "clean" and "couldn't check" separate.

    That separation is the whole point: reporting an unchecked password as
    clean tells the user they're safe when nothing was actually verified.
    """

    counts: dict[str, int] = field(default_factory=dict)
    """password -> breach count, for checks that actually completed."""

    failed: set[str] = field(default_factory=set)
    """Passwords whose check did not complete (offline, rate-limited, …)."""

    cancelled: bool = False
    """True when the caller aborted mid-scan; remaining passwords are neither
    in ``counts`` nor in ``failed`` — they were simply not attempted."""

    @property
    def breached(self) -> dict[str, int]:
        return {pw: n for pw, n in self.counts.items() if n}

    @property
    def complete(self) -> bool:
        return not self.failed and not self.cancelled


def check_many(
    passwords: Iterable[str],
    *,
    delay: float = BULK_DELAY_SECONDS,
    on_progress: Callable[[int, int], None] | None = None,
    on_checked: Callable[[str, int], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    _sleep: Callable[[float], None] = time.sleep,
) -> ScanOutcome:
    """Check many passwords, de-duplicating and pacing the requests.

    Duplicates are collapsed first: reused passwords share a SHA-1, so
    checking each copy is a redundant round trip against a service that
    rate-limits us.

    A password that cannot be checked lands in ``failed``, never in
    ``counts`` — callers must not treat it as clean. A mid-scan cancel
    leaves remaining passwords untouched (neither counted nor failed).

    ``on_checked(password, count)`` fires after each successful check so
    callers can persist immediately — a cancel must not wipe finished work.
    """
    unique = list(dict.fromkeys(passwords))
    outcome = ScanOutcome()
    total = len(unique)

    for i, password in enumerate(unique):
        if should_cancel and should_cancel():
            outcome.cancelled = True
            if on_progress:
                on_progress(i, total)
            break
        if i and delay:
            _sleep(delay)
            if should_cancel and should_cancel():
                outcome.cancelled = True
                if on_progress:
                    on_progress(i, total)
                break
        try:
            count = check_password(password)
            outcome.counts[password] = count
            if on_checked:
                on_checked(password, count)
        except Exception:  # noqa: BLE001 - any failure means "not checked"
            outcome.failed.add(password)
        if on_progress:
            on_progress(i + 1, total)

    return outcome


def status_label(checked_at: str | None, count: int | None) -> str:
    """Human-readable per-entry breach status for the UI.

    Never-scanned (either field missing) reads as "Not checked" — never as
    clean. A completed check with count 0 is "Clean"; count > 0 names the
    breach total. The date is the UTC calendar day of ``checked_at``.
    """
    if not checked_at or count is None:
        return "Not checked"
    when = checked_at[:10]
    if count > 0:
        return f"Found in {count:,} breaches · checked {when}"
    return f"Clean · checked {when}"


def breached_credentials(creds: Iterable[dict]) -> list[dict]:
    """Credentials whose *persisted* HIBP count is positive.

    Attaches ``_breach_count`` for the audit view. Entries that were never
    scanned (NULL count) are excluded — absence of a result is not a clean
    bill of health, and it is also not a breach finding.
    """
    out: list[dict] = []
    for c in creds:
        n = c.get("breach_count")
        if n is None:
            continue
        try:
            count = int(n)
        except (TypeError, ValueError):
            continue
        if count > 0:
            row = dict(c)
            row["_breach_count"] = count
            out.append(row)
    return out
