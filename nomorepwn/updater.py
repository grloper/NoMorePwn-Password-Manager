"""Update checks against GitHub Releases.

## Why this is the second network path

Before this module, `leakcheck` was the only outbound request in the codebase
and it leaks 5 hex characters. This one downloads an executable and hands it to
the OS — a materially larger surface on a machine holding a password vault. The
mitigations are deliberate and each exists for a stated reason:

- **HTTPS with certificate verification.** `requests` verifies by default and
  the frozen build bundles certifi. Never pass `verify=False`.
- **`/releases/latest` excludes pre-releases and drafts.** Every push to main
  publishes a pre-release; only a release you explicitly promote is ever
  offered to users. This is the entire stable-channel mechanism — do not
  switch to `/releases` and pick `[0]`, which would include pre-releases.
- **SHA-256 verified before the file is executed.** Read the honest limits
  below.
- **Downgrade refused.** A rollback attack cannot walk a user back onto a build
  with a known hole.
- **Size cap.** A hostile or broken endpoint cannot fill the disk.

## What the SHA-256 check does and does not buy

It is published *in the same release* as the installer. So it detects a
corrupted or truncated download, and a CDN asset swapped without touching the
release metadata. It does **not** protect against a compromised GitHub account
or Actions token: an attacker who can publish a release can publish a matching
checksum. Closing that needs the checksum signed by a key that never lives in
CI, with the public half pinned in the app. Until then, the trust anchor is
GitHub's TLS plus the repo's account security — say so plainly rather than
implying the hash makes it tamper-proof.

The application step is in `nomorepwn_app/update_manager.py`; this module never
executes anything.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

RELEASES_API = "https://api.github.com/repos/{owner}/{repo}/releases/latest"

_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "NoMorePwn-updater",
}

DEFAULT_TIMEOUT = 15

# A NoMorePwn installer is ~50 MB. The cap is generous but finite so a hostile
# or malfunctioning endpoint cannot stream until the disk fills.
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024

CHECKSUM_ASSET = "SHA256SUMS.txt"

# Deliberately a FULL match: `1.0.42` and `v1.0.42` parse, `0.0.0-dev` does
# not. A dev checkout must be unparseable so `is_newer` returns False in both
# directions — belt and braces with `is_packaged_build()`, because offering a
# source tree an installer would leave the user running two different copies.
_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


class UpdateError(Exception):
    """Any failure to check for or fetch an update."""


@dataclass
class Release:
    version: str
    tag: str
    page_url: str
    asset_name: str
    asset_url: str
    asset_size: int
    sha256: str | None
    notes: str

    @property
    def has_checksum(self) -> bool:
        return bool(self.sha256)


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Parse `1.2.3` / `v1.2.3` / `1.2.3-dev` into a comparable tuple.

    Returns None for anything unparseable, including the `0.0.0-dev` a source
    checkout reports — callers must treat None as "do not offer an update".
    """
    if not text:
        return None
    match = _VERSION_RE.fullmatch(text.strip())
    if not match:
        return None
    return tuple(int(p) for p in match.groups())  # type: ignore[return-value]


def is_newer(candidate: str, current: str) -> bool:
    """Whether `candidate` is a strictly newer release than `current`.

    Numeric per-component comparison, so 1.0.10 > 1.0.9 — a string compare
    would get that backwards and strand everyone on .9 forever.
    """
    new, old = parse_version(candidate), parse_version(current)
    if new is None or old is None:
        return False
    return new > old


def _pick_installer(assets: list[dict]) -> dict | None:
    for asset in assets:
        name = (asset.get("name") or "").lower()
        if name.endswith(".exe") and "setup" in name:
            return asset
    return None


def _parse_checksums(text: str) -> dict[str, str]:
    """Parse `sha256sum`-style lines into {filename: digest}."""
    digests: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            digests[parts[-1].lstrip("*")] = parts[0].lower()
    return digests


def fetch_latest(owner: str, repo: str, timeout: int = DEFAULT_TIMEOUT,
                 session: requests.Session | None = None) -> Release:
    """Fetch the latest *stable* release. Raises UpdateError on any failure."""
    get = (session or requests).get
    url = RELEASES_API.format(owner=owner, repo=repo)

    try:
        response = get(url, headers=_HEADERS, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise UpdateError(f"Could not reach the update server: {exc}") from exc
    except ValueError as exc:
        raise UpdateError("Update server returned a malformed response.") from exc

    # Defence in depth: /releases/latest already excludes these, but a wrong
    # endpoint or an API change should fail closed rather than ship a draft.
    if payload.get("draft") or payload.get("prerelease"):
        raise UpdateError("Latest release is a draft or pre-release.")

    assets = payload.get("assets") or []
    installer = _pick_installer(assets)
    if not installer:
        raise UpdateError("Release contains no installer asset.")

    sha256 = None
    checksum_asset = next(
        (a for a in assets if (a.get("name") or "") == CHECKSUM_ASSET), None)
    if checksum_asset:
        try:
            sums = get(checksum_asset["browser_download_url"],
                       headers=_HEADERS, timeout=timeout)
            sums.raise_for_status()
            sha256 = _parse_checksums(sums.text).get(installer["name"])
        except (requests.RequestException, ValueError):
            sha256 = None  # surfaced to the user as "unverified"

    tag = str(payload.get("tag_name") or "")
    return Release(
        version=tag.lstrip("v"),
        tag=tag,
        page_url=str(payload.get("html_url") or ""),
        asset_name=str(installer.get("name") or ""),
        asset_url=str(installer.get("browser_download_url") or ""),
        asset_size=int(installer.get("size") or 0),
        sha256=sha256,
        notes=str(payload.get("body") or ""),
    )


def check(owner: str, repo: str, current_version: str, **kwargs) -> Release | None:
    """Return a newer stable release, or None if already current."""
    release = fetch_latest(owner, repo, **kwargs)
    return release if is_newer(release.version, current_version) else None


def download(release: Release, dest_dir: Path,
             on_progress: Callable[[int, int], None] | None = None,
             timeout: int = DEFAULT_TIMEOUT,
             session: requests.Session | None = None) -> Path:
    """Download the installer and verify it. Returns the verified path.

    On ANY failure — including a checksum mismatch — the partial file is
    removed and UpdateError is raised. A file that failed verification must
    never be left on disk where something else could execute it.
    """
    get = (session or requests).get
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / release.asset_name

    digest = hashlib.sha256()
    written = 0

    try:
        with get(release.asset_url, headers=_HEADERS, timeout=timeout,
                 stream=True) as response:
            response.raise_for_status()
            with open(target, "wb") as fh:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > MAX_DOWNLOAD_BYTES:
                        raise UpdateError("Update download exceeded the size limit.")
                    digest.update(chunk)
                    fh.write(chunk)
                    if on_progress:
                        on_progress(written, release.asset_size)

        if release.sha256 and digest.hexdigest() != release.sha256:
            raise UpdateError(
                "Downloaded installer failed its checksum — discarded. "
                "This can mean a corrupted download or a tampered file.")
        if written == 0:
            raise UpdateError("Update download was empty.")

    except UpdateError:
        target.unlink(missing_ok=True)
        raise
    except requests.RequestException as exc:
        target.unlink(missing_ok=True)
        raise UpdateError(f"Update download failed: {exc}") from exc
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise UpdateError(f"Could not write the update to disk: {exc}") from exc

    return target
