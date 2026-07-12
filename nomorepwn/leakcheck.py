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
"""

from __future__ import annotations

import hashlib

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_HEADERS = {
    # Identify ourselves per HIBP API etiquette; enable padded responses.
    "User-Agent": "NoMorePwn-local-security-audit",
    "Add-Padding": "true",
}
DEFAULT_TIMEOUT = 10


class LeakCheckError(Exception):
    """Network or API failure — distinct from 'not found in breaches'."""


def check_password(password: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    """Return how many times `password` appears in known breaches (0 = none).

    Raises LeakCheckError on network/API failure so callers never
    mistake "check didn't run" for "password is clean".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers=_HEADERS,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise LeakCheckError(f"HIBP range query failed: {exc}") from exc

    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            occurrences = int(count.strip() or 0)
            # Padding entries are returned with a count of 0 — not real hits.
            return occurrences if occurrences > 0 else 0
    return 0
