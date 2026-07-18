"""Native-messaging registration for the NoMorePwn browser extension.

The extension talks to this app over Chrome's native-messaging channel: the
browser launches a local host process and speaks a length-prefixed JSON
protocol over its stdin/stdout. Nothing here opens a socket or a port — the
transport is a child process owned by the browser.

Setting that up means two artefacts per browser:

1. A **host manifest** — a small JSON file naming the executable to launch and
   which extension IDs may talk to it (``allowed_origins``).
2. A **registry value** under HKCU pointing the browser at that manifest.
   HKCU throughout, so this never needs admin rights (same approach as
   :mod:`nomorepwn_app.startup`).

``allowed_origins`` is the security boundary that matters: only the extension
whose ID is listed can launch this host. That ID is pinned by the ``key``
field in the extension's manifest.json, which is why it can be a constant here
instead of something the user has to copy by hand.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from nomorepwn import config

HOST_NAME = "com.nomorepwn.bridge"

# Pinned by the "key" field in extension/manifest.json. If that key changes,
# this must change with it or the browser will refuse the connection.
EXTENSION_ID = "cjgphedkabfdfbhkfleagmanmmhlolkl"

# Chromium-family browsers that share the native-messaging registry layout.
BROWSERS: dict[str, str] = {
    "Chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "Edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "Brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
}


@dataclass
class BridgeStatus:
    """What is currently registered, for the settings UI to render."""

    registered: list[str]
    """Browser names with a live registration pointing at our manifest."""

    manifest_path: Path
    extension_dir: Path
    host_command: str
    supported: bool = True
    detail: str = ""

    @property
    def is_registered(self) -> bool:
        return bool(self.registered)


def extension_dir() -> Path:
    """Where the unpacked extension lives, for 'Load unpacked'.

    Frozen builds ship it beside the executable; from source it sits at the
    repo root.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "extension"
    return Path(__file__).resolve().parent.parent / "extension"


def manifest_path() -> Path:
    """The host manifest lives with our data, not in the install dir.

    Under Program Files it would need admin rights to write.
    """
    return Path(config.DATA_DIR) / "native-messaging" / f"{HOST_NAME}.json"


def _host_command() -> tuple[str, list[str]]:
    """The executable the browser should launch, plus its fixed arguments."""
    if getattr(sys, "frozen", False):
        return sys.executable, ["--native-host"]
    return sys.executable, ["-m", "nomorepwn_app", "--native-host"]


def host_command_display() -> str:
    exe, args = _host_command()
    return " ".join([f'"{exe}"', *args])


def _launcher_path() -> Path:
    """A .bat shim, because native-messaging manifests take no arguments.

    Chrome launches ``path`` with no way to pass ``-m nomorepwn_app``, so a
    source install needs a one-line wrapper. A frozen build points straight
    at the .exe and skips this.
    """
    return manifest_path().parent / "nomorepwn-bridge.bat"


def _ensure_launcher() -> Path:
    exe, args = _host_command()
    if not args:
        return Path(exe)

    launcher = _launcher_path()
    launcher.parent.mkdir(parents=True, exist_ok=True)
    quoted = " ".join(f'"{a}"' if " " in a else a for a in args)
    launcher.write_text(f'@echo off\r\n"{exe}" {quoted} %*\r\n', encoding="utf-8")
    return launcher


def write_manifest() -> Path:
    """Write the native-messaging host manifest and return its path."""
    target = manifest_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": HOST_NAME,
        "description": "NoMorePwn vault bridge",
        "path": str(_ensure_launcher()),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def register(browsers: list[str] | None = None) -> list[str]:
    """Register the host with each browser. Returns the names that succeeded."""
    if sys.platform != "win32":
        return []
    import winreg

    write_manifest()
    done = []
    for name in browsers or list(BROWSERS):
        subkey = BROWSERS.get(name)
        if not subkey:
            continue
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{subkey}\\{HOST_NAME}") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest_path()))
            done.append(name)
        except OSError:
            continue
    return done


def unregister() -> None:
    """Remove every registration and the manifest itself."""
    if sys.platform != "win32":
        return
    import winreg

    for subkey in BROWSERS.values():
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{subkey}\\{HOST_NAME}")
        except OSError:
            pass

    shutil.rmtree(manifest_path().parent, ignore_errors=True)


def status() -> BridgeStatus:
    """Inspect what is registered right now."""
    base = BridgeStatus(
        registered=[],
        manifest_path=manifest_path(),
        extension_dir=extension_dir(),
        host_command=host_command_display(),
    )
    if sys.platform != "win32":
        base.supported = False
        base.detail = "Browser integration is Windows-only for now."
        return base

    import winreg

    expected = str(manifest_path())
    for name, subkey in BROWSERS.items():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{subkey}\\{HOST_NAME}") as key:
                value, _ = winreg.QueryValueEx(key, "")
        except OSError:
            continue
        # A registration pointing at a manifest we no longer write is stale —
        # report it as absent so "Set up" re-points it.
        if str(value).strip().lower() == expected.lower() and manifest_path().exists():
            base.registered.append(name)

    if not base.extension_dir.exists():
        base.detail = "The extension folder is missing from this install."
    return base
