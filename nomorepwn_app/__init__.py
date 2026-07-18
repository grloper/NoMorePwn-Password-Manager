"""NoMorePwn desktop application (PySide6).

A modern, tray-resident Windows password manager built on the
``nomorepwn`` security core. The version is baked in below; the release
workflow overrides it via the ``NOMOREPWN_VERSION`` environment variable
so the shipped ``.exe`` reports the exact build it came from.
"""

import os

APP_NAME = "NoMorePwn"
APP_DISPLAY_NAME = "NoMorePwn"
APP_TAGLINE = "Your passwords, sealed on your machine."
ORG_NAME = "grloper"

__version__ = os.environ.get("NOMOREPWN_VERSION", "1.0.0")
