"""Local HIBP breach catalog — named breach details by service domain.

Privacy model for this feature (hard rules):
1. The only network call is an unauthenticated GET of the public breach
   list. Nothing about the vault, the user, any email, password, or hash
   is transmitted — not even a domain filter query string.
2. Matching of vault ``service_name`` values against breach domains runs
   entirely on device against the cached JSON.
3. Catalog download is **user-initiated only**. Unlock, list, and edit
   never touch the network. A failed refresh leaves the previous cache
   untouched so the vault keeps working offline.
4. No paid API key, no third-party email lookup, no dark-web email API.

This is a separate concern from ``leakcheck`` (password k-anonymity).
Phase-1 password status (``breach_count`` / ``breach_checked_at``) is
untouched here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests

from . import config

# Public, keyless catalog. Never append ?domain= or any vault-derived
# query — that would send service domains off-device.
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
_HEADERS = {
    "User-Agent": "NoMorePwn-local-breach-catalog",
    "Accept": "application/json",
}
DEFAULT_TIMEOUT = 30
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
STALE_AFTER_DAYS = 30

_CACHE_VERSION = 1

# Host-like token: labels separated by dots, TLD letters.
_HOST_RE = re.compile(
    r"(?i)\b(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b"
)


class CatalogError(Exception):
    """Network or parse failure — distinct from 'no matching breaches'."""


@dataclass(frozen=True)
class BreachInfo:
    """One named breach from the public catalog."""

    name: str
    title: str
    domain: str
    breach_date: str
    data_classes: tuple[str, ...] = ()

    @property
    def display_name(self) -> str:
        return self.title or self.name


@dataclass
class Catalog:
    """Cached public breach list plus fetch metadata."""

    breaches: list[BreachInfo] = field(default_factory=list)
    fetched_at: str | None = None
    path: Path | None = None

    def stale(self, *, now: datetime | None = None) -> bool:
        return catalog_is_stale(self.fetched_at, now=now)

    @property
    def is_stale(self) -> bool:
        return self.stale()

    def by_domain(self) -> dict[str, list[BreachInfo]]:
        """Index breaches that declare a domain (lowercased)."""
        index: dict[str, list[BreachInfo]] = {}
        for b in self.breaches:
            if not b.domain:
                continue
            key = b.domain.strip().lower()
            if not key:
                continue
            index.setdefault(key, []).append(b)
        return index


def catalog_path() -> Path:
    """On-disk cache path under the data directory."""
    return config.DATA_DIR / "breach_catalog.json"


def catalog_is_stale(
    fetched_at: str | None,
    *,
    now: datetime | None = None,
    max_age_days: int = STALE_AFTER_DAYS,
) -> bool:
    """True when there is no fetch time or it is older than ``max_age_days``."""
    if not fetched_at:
        return True
    try:
        when = datetime.fromisoformat(fetched_at)
    except ValueError:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    ref = now or datetime.now(timezone.utc)
    return (ref - when).days >= max_age_days


def status_label(
    catalog: Catalog | None,
    *,
    now: datetime | None = None,
) -> str:
    """Human-readable catalog freshness for the dashboard."""
    if catalog is None or not catalog.fetched_at:
        return "No breach catalog yet — download the public list to match services"
    when = catalog.fetched_at[:10]
    if catalog.stale(now=now):
        return f"Catalog updated {when} (stale — refresh recommended)"
    return f"Catalog updated {when}"


def extract_domain(service_name: str) -> str | None:
    """Pull a hostname from a vault service label, or None if none present.

    Accepts bare hosts (``adobe.com``), URLs, and labels that embed a host
    (``Adobe — adobe.com``). Pure display names with no domain return None
    so we never invent a match.
    """
    if not isinstance(service_name, str):
        return None
    text = service_name.strip()
    if not text:
        return None

    candidate = text
    lowered = text.lower()
    if "://" in lowered or lowered.startswith("www."):
        parsed = urlparse(text if "://" in lowered else f"https://{text}")
        if parsed.hostname:
            candidate = parsed.hostname
    else:
        match = _HOST_RE.search(text)
        if not match:
            return None
        candidate = match.group(1)

    host = candidate.strip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    if "." not in host or not _HOST_RE.fullmatch(host):
        return None
    return host


def domains_match(service_domain: str, breach_domain: str) -> bool:
    """True when the service host is the breach domain or a subdomain of it."""
    s = (service_domain or "").strip().lower().lstrip(".")
    b = (breach_domain or "").strip().lower().lstrip(".")
    if not s or not b:
        return False
    if s.startswith("www."):
        s = s[4:]
    if b.startswith("www."):
        b = b[4:]
    return s == b or s.endswith("." + b)


def _breach_from_raw(raw: dict[str, Any]) -> BreachInfo | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("Name") or raw.get("name") or ""
    title = raw.get("Title") or raw.get("title") or name
    domain = raw.get("Domain") or raw.get("domain") or ""
    breach_date = raw.get("BreachDate") or raw.get("breach_date") or ""
    classes = raw.get("DataClasses") or raw.get("data_classes") or []
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(domain, str):
        domain = ""
    if not isinstance(breach_date, str):
        breach_date = ""
    if not isinstance(title, str) or not title.strip():
        title = name
    if not isinstance(classes, list):
        classes = []
    cleaned = tuple(str(c) for c in classes if c)
    return BreachInfo(
        name=name.strip(),
        title=title.strip(),
        domain=domain.strip().lower(),
        breach_date=breach_date.strip(),
        data_classes=cleaned,
    )


def parse_breaches(payload: Any) -> list[BreachInfo]:
    """Normalize a HIBP-style JSON array into ``BreachInfo`` rows."""
    if not isinstance(payload, list):
        raise CatalogError("Breach catalog must be a JSON array")
    out: list[BreachInfo] = []
    for item in payload:
        info = _breach_from_raw(item)
        if info is not None:
            out.append(info)
    return out


def load_catalog(path: Path | None = None) -> Catalog | None:
    """Read the local cache. Missing or corrupt files return None."""
    path = path or catalog_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    breaches_raw = data.get("breaches")
    try:
        breaches = parse_breaches(breaches_raw if breaches_raw is not None else [])
    except CatalogError:
        return None
    fetched_at = data.get("fetched_at")
    if fetched_at is not None and not isinstance(fetched_at, str):
        fetched_at = None
    return Catalog(breaches=breaches, fetched_at=fetched_at, path=path)


def save_catalog(
    breaches: list[BreachInfo],
    path: Path | None = None,
    *,
    fetched_at: str | None = None,
) -> Catalog:
    """Atomically write the cache. Never called with vault secrets."""
    path = path or catalog_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    when = fetched_at or datetime.now(timezone.utc).isoformat()
    payload = {
        "v": _CACHE_VERSION,
        "fetched_at": when,
        "breaches": [
            {
                "Name": b.name,
                "Title": b.title,
                "Domain": b.domain,
                "BreachDate": b.breach_date,
                "DataClasses": list(b.data_classes),
            }
            for b in breaches
        ],
    }
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return Catalog(breaches=list(breaches), fetched_at=when, path=path)


def download_breaches(
    *,
    timeout: int = DEFAULT_TIMEOUT,
    session: Any | None = None,
) -> list[BreachInfo]:
    """GET the public catalog. Transmits no vault- or user-derived data."""
    get = session.get if session is not None else requests.get
    try:
        response = get(
            HIBP_BREACHES_URL,
            headers=_HEADERS,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise CatalogError(f"HIBP breach catalog download failed: {exc}") from exc

    # Prefer bytes so a hostile endpoint cannot stream past the size cap
    # via a lazily-decoded .text property.
    raw = getattr(response, "content", None)
    if raw is None:
        text = getattr(response, "text", "") or ""
        raw = text.encode("utf-8") if isinstance(text, str) else b""
    if not isinstance(raw, (bytes, bytearray)):
        raise CatalogError("HIBP breach catalog response had no body")
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise CatalogError("HIBP breach catalog exceeded size cap")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CatalogError(f"HIBP breach catalog was not valid JSON: {exc}") from exc

    return parse_breaches(payload)


def refresh_catalog(
    path: Path | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    session: Any | None = None,
) -> Catalog:
    """Download and replace the cache. On failure the old file is untouched."""
    path = path or catalog_path()
    breaches = download_breaches(timeout=timeout, session=session)
    return save_catalog(breaches, path)


def match_domain(domain: str | None, catalog: Catalog | None) -> list[BreachInfo]:
    """Local-only match of one domain against the cached catalog."""
    if not domain or catalog is None:
        return []
    hits: list[BreachInfo] = []
    seen: set[str] = set()
    for breach in catalog.breaches:
        if not breach.domain:
            continue
        if not domains_match(domain, breach.domain):
            continue
        key = breach.name.lower()
        if key in seen:
            continue
        seen.add(key)
        hits.append(breach)
    hits.sort(key=lambda b: (b.breach_date or "", b.display_name), reverse=True)
    return hits


def match_service(service_name: str, catalog: Catalog | None) -> list[BreachInfo]:
    """Extract a domain from ``service_name`` and match locally."""
    return match_domain(extract_domain(service_name), catalog)


def format_breach_detail(breach: BreachInfo) -> str:
    """One-line UI summary: name, date, data classes."""
    name = breach.display_name
    date = breach.breach_date or "unknown date"
    if breach.data_classes:
        classes = ", ".join(breach.data_classes)
        return f"{name} ({date}) — {classes}"
    return f"{name} ({date})"


def affected_services(
    creds: Iterable[dict],
    catalog: Catalog | None,
) -> list[dict]:
    """Vault entries whose service domain appears in a known breach.

    Returns copies with ``_service_breaches`` attached. Entries with no
    extractable domain, or no catalog match, are omitted. Matching never
    contacts the network.
    """
    if catalog is None:
        return []
    out: list[dict] = []
    for cred in creds:
        name = cred.get("service_name", "")
        hits = match_service(name if isinstance(name, str) else "", catalog)
        if not hits:
            continue
        row = dict(cred)
        row["_service_breaches"] = hits
        row["_service_domain"] = extract_domain(name if isinstance(name, str) else "")
        out.append(row)
    # Stable-ish: by service name then username, case-insensitive.
    out.sort(key=lambda c: (
        str(c.get("service_name", "")).lower(),
        str(c.get("username", "")).lower(),
    ))
    return out
