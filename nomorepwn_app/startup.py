"""Windows 'launch at sign-in' integration via the per-user Run key.

Uses HKCU so it never needs admin rights. The registered command starts
NoMorePwn straight into the tray (locked), so sign-in stays quiet.
"""

from __future__ import annotations

import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_KEY = "NoMorePwn"


def _startup_command() -> str:
    if getattr(sys, "frozen", False):
        # Packaged .exe — launch it directly.
        return f'"{sys.executable}" --tray'
    # Dev / source run.
    return f'"{sys.executable}" -m nomorepwn_app --tray'


def set_launch_at_startup(enabled: bool) -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, APP_KEY, 0, winreg.REG_SZ, _startup_command())
            else:
                try:
                    winreg.DeleteValue(key, APP_KEY)
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        return False


def is_launch_at_startup() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_KEY)
            return True
    except OSError:
        return False
