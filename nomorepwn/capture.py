"""Browser-capture policy and the pure planner behind it.

Two things live here, both deliberately free of Qt and of the vault so they can
be unit-tested in isolation (the repo's "put security decisions where they can
be tested" rule):

1. :class:`CapturePolicy` — a small per-origin memory of what the user decided a
   site is: a login worth saving, or a form to ignore. This is *non-secret*
   metadata (the same class of data as a group label), persisted as JSON beside
   ``settings.json``. No credential ever lands here.

2. :func:`plan_capture` — a pure function mapping (learned decision, the user's
   global capture setting, whether the extension already verified the login) to
   one of a few plans the controller executes. The controller only *renders*
   the plan; the decision is here where a test can pin it.

The learning loop: the extension verifies what it can. What it cannot verify
(SPA logins, multi-step flows like Google) is no longer dropped silently —
it is sent through as *unverified*, and for an origin we have never seen we ask
the user once. Their answer is remembered per origin, so a "yes" makes the site
automatic and a "no" makes it quiet.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from . import config

# Learned per-origin decisions.
SAVE = "save"       # the user confirmed this origin is a login worth saving
IGNORE = "ignore"   # the user said this origin is not a login — stop asking

# Plans the controller executes for a captured credential.
PLAN_SAVE = "save"        # add to Captured Logins without interrupting
PLAN_EDITOR = "editor"    # open the editor prefilled for the user to review
PLAN_CONFIRM = "confirm"  # ask "was this a login?" — an origin we have not seen
PLAN_IGNORE = "ignore"    # do nothing


def origin_of(target_url: str) -> str:
    """Scheme+host(+port) key for a captured URL, lowercased.

    Grouping by origin (not full URL) is what lets a single "yes" on
    ``https://accounts.google.com`` cover every sign-in there. Falls back to the
    raw string for inputs that are not URLs, so a bad value still keys
    *something* consistent rather than throwing.
    """
    raw = (target_url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "//" in raw else "//" + raw)
        host = (parsed.hostname or "").lower()
        if not host:
            return raw.lower()
        scheme = (parsed.scheme or "https").lower()
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        return f"{scheme}://{netloc}"
    except ValueError:
        return raw.lower()


class CapturePolicy:
    """Per-origin login/ignore decisions, persisted as JSON.

    Unknown/legacy keys and a missing or corrupt file degrade to "no decisions
    yet" rather than raising — the same forgiving posture as
    :class:`nomorepwn.settings.Settings`.
    """

    def __init__(self, path: Path | None = None):
        self._path = Path(path) if path else (config.DATA_DIR / "capture_policy.json")
        self._map: dict[str, str] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._map = {}
            return
        if not isinstance(raw, dict):
            self._map = {}
            return
        self._map = {
            str(k): v for k, v in raw.items() if v in (SAVE, IGNORE)
        }

    def save(self) -> None:
        try:
            config.ensure_data_dir()
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._map, indent=2), encoding="utf-8")
            tmp.replace(self._path)  # atomic on the same volume
        except OSError:
            pass  # a policy we cannot persist is a lost convenience, not a failure

    def decision(self, origin: str) -> str | None:
        """The learned decision for *origin*, or None if never seen."""
        return self._map.get(origin)

    def remember(self, origin: str, decision: str) -> None:
        if decision not in (SAVE, IGNORE) or not origin:
            return
        self._map[origin] = decision
        self.save()

    def forget(self, origin: str) -> None:
        if self._map.pop(origin, None) is not None:
            self.save()

    def known(self) -> dict[str, str]:
        return dict(self._map)


def plan_capture(*, decision: str | None, capture_action: str, verified: bool) -> str:
    """Decide what to do with a captured credential.

    Pure over its inputs:

    * ``decision``       — learned policy for the origin (``SAVE`` / ``IGNORE`` /
      ``None``).
    * ``capture_action`` — the user's global setting (silent / prompt / disabled).
    * ``verified``       — whether the extension already verified the login.

    A learned ``IGNORE`` and the global "disabled" both mean do nothing. A
    verified login, or an origin the user already blessed, is saved the way the
    user asked captures to be handled. Anything else — unverified on an origin we
    have never seen — is where we ask.
    """
    from .settings import CAPTURE_DISABLED, CAPTURE_PROMPT

    if capture_action == CAPTURE_DISABLED:
        return PLAN_IGNORE
    if decision == IGNORE:
        return PLAN_IGNORE
    if verified or decision == SAVE:
        return PLAN_EDITOR if capture_action == CAPTURE_PROMPT else PLAN_SAVE
    return PLAN_CONFIRM
