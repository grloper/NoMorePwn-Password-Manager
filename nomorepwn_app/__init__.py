"""NoMorePwn desktop application (PySide6).

A modern, tray-resident Windows password manager built on the
``nomorepwn`` security core.

Versioning: ``build/NoMorePwn.spec`` writes ``_build_info.py`` from
``NOMOREPWN_VERSION`` at *build* time, and PyInstaller bundles it. Reading
the environment variable here instead would evaluate on the **user's**
machine, where it is never set — which is why every released build used to
report "1.0.0" and the auto-updater could not tell what it was running.
"""

import os

APP_NAME = "NoMorePwn"
APP_DISPLAY_NAME = "NoMorePwn"
APP_TAGLINE = "Your passwords, sealed on your machine."
ORG_NAME = "grloper"

# Where the updater looks for new releases.
GITHUB_OWNER = "grloper"
GITHUB_REPO = "NoMorePwn-Password-Manager"

try:
    # Generated at build time; present only in a packaged build.
    from ._build_info import VERSION as __version__
except ImportError:
    # Source checkout: honour the env var for local packaging experiments,
    # else mark it clearly as a dev build so it never looks like a release.
    __version__ = os.environ.get("NOMOREPWN_VERSION", "0.0.0-dev")


def is_packaged_build() -> bool:
    """True when running from a frozen build with a real baked version.

    The updater must not offer to "update" a source checkout — the
    installer would land beside it and the user would end up running two
    different copies.
    """
    import sys

    return getattr(sys, "frozen", False) and not __version__.endswith("-dev")
