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


def _bundled_source() -> Path | None:
    """The read-only copy of the extension inside a frozen build.

    PyInstaller unpacks bundled data to ``sys._MEIPASS``, a temp directory
    that is different on every launch — fine to copy *from*, useless to point
    Chrome at.
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "extension"
    return candidate if candidate.is_dir() else None


def extension_dir() -> Path:
    """The stable directory to hand to Chrome's "Load unpacked".

    From source this is the repo's ``extension/``. In a frozen build it is
    ``%APPDATA%\\NoMorePwn\\extension`` — *not* a path beside the .exe, which
    would not exist for the portable single-file build, and not ``_MEIPASS``,
    which changes every launch and would break the loaded extension the moment
    the app restarted.
    """
    if getattr(sys, "frozen", False):
        return Path(config.DATA_DIR) / "extension"
    return Path(__file__).resolve().parent.parent / "extension"


def ensure_extension_files() -> bool:
    """Materialise the bundled extension to its stable directory.

    Copies on first run and after an update (the version stamp changes). A
    source checkout needs no copy. Returns whether a usable extension folder
    exists afterwards.
    """
    target = extension_dir()
    if not getattr(sys, "frozen", False):
        return (target / "manifest.json").is_file()

    source = _bundled_source()
    if source is None:
        return False

    from . import __version__

    stamp = target / ".version"
    if (target / "manifest.json").is_file() and stamp.is_file():
        try:
            if stamp.read_text(encoding="utf-8").strip() == __version__:
                return True
        except OSError:
            pass

    try:
        # Replace wholesale so a file removed upstream does not linger and
        # get loaded by Chrome.
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target)
        stamp.write_text(__version__, encoding="utf-8")
    except OSError:
        return (target / "manifest.json").is_file()

    return (target / "manifest.json").is_file()


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
    """Register the host with each browser. Returns the names that succeeded.

    Fails closed when there is no extension folder to load. Registering the
    host regardless used to report "✓ Connected" for a build that shipped no
    extension at all — the user was told to load a directory that had never
    been created.
    """
    if sys.platform != "win32":
        return []
    import winreg

    if not ensure_extension_files():
        return []

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
    ensure_extension_files()
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

    if not (base.extension_dir / "manifest.json").is_file():
        base.detail = "The browser extension is missing from this install."
    return base
