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

**The unpacked extension is browser-specific.** Chrome (and its Chromium
cousins) and Firefox need different manifests — Chrome wants
``background.service_worker`` and a ``key``; Firefox wants ``background.scripts``
and ``browser_specific_settings``. ``extension/build.py`` writes those two
variants to ``extension/dist/chrome`` and ``extension/dist/firefox``; this
module hands each browser the folder built for *it*, never the shared source
tree, which no browser can load as-is.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from nomorepwn import config

HOST_NAME = "com.nomorepwn.bridge"

# Pinned by the "key" field in extension/manifest.json. If that key changes,
# this must change with it or the browser will refuse the connection.
EXTENSION_ID = "cjgphedkabfdfbhkfleagmanmmhlolkl"

# Declared in extension/manifest.json under browser_specific_settings.gecko.id.
FIREFOX_EXTENSION_ID = "extension@nomorepwn.com"

# Chromium-family browsers that share the native-messaging registry layout, plus Firefox.
BROWSERS: dict[str, str] = {
    "Chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "Edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "Brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    "Firefox": r"Software\Mozilla\NativeMessagingHosts",
}

# Chromium browsers all load the "chrome" build; Firefox loads its own.
CHROMIUM_BROWSERS = {"Chrome", "Edge", "Brave"}

# The two per-browser builds ``extension/build.py`` produces.
_VARIANTS = ("chrome", "firefox")


# --------------------------------------------------------------------------
# Per-browser build selection
# --------------------------------------------------------------------------


def variant_for(browser: str) -> str:
    """Which unpacked build a browser loads: ``"firefox"`` or ``"chrome"``.

    Everything that is not Firefox is Chromium here, which keeps a stray
    browser name (or an empty string) defaulting to the Chrome build rather
    than raising.
    """
    key = (browser or "").strip().lower()
    if key in ("firefox", "gecko", "mozilla"):
        return "firefox"
    return "chrome"


def extensions_page(browser: str) -> str:
    """The in-browser URL where a user loads an unpacked extension."""
    if variant_for(browser) == "firefox":
        return "about:debugging#/runtime/this-firefox"
    return "chrome://extensions"


def _repo_dist_dir() -> Path:
    """``extension/dist`` in a source checkout (holds ``chrome/`` + ``firefox/``)."""
    return Path(__file__).resolve().parent.parent / "extension" / "dist"


def _bundled_source() -> Path | None:
    """The read-only per-browser builds inside a frozen build.

    PyInstaller unpacks bundled data to ``sys._MEIPASS``, a temp directory
    that is different on every launch — fine to copy *from*, useless to point
    a browser at. The directory holds ``chrome/`` and ``firefox/`` subfolders.
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "extension"
    return candidate if candidate.is_dir() else None


def extension_dir(browser: str = "chrome") -> Path:
    """The stable directory to hand a browser's "Load unpacked".

    Browser-specific: Chrome/Edge/Brave get the ``chrome`` build, Firefox the
    ``firefox`` build. From source these are the committed
    ``extension/dist/<variant>`` folders. In a frozen build they live under
    ``%APPDATA%\\NoMorePwn\\extension\\<variant>`` — *not* a path beside the
    .exe (which would not exist for the portable single-file build) and not
    ``_MEIPASS`` (which changes every launch and would break the loaded
    extension the moment the app restarted).
    """
    variant = variant_for(browser)
    if getattr(sys, "frozen", False):
        return Path(config.DATA_DIR) / "extension" / variant
    return _repo_dist_dir() / variant


def _variant_ready(base: Path) -> bool:
    return all((base / v / "manifest.json").is_file() for v in _VARIANTS)


def _build_dist_from_source() -> bool:
    """Best-effort rebuild of the committed ``extension/dist`` builds.

    Only reached if a source checkout is somehow missing them (they are
    committed, so normally a no-op). Runs ``extension/build.py`` in-process.
    """
    try:
        import importlib.util

        script = Path(__file__).resolve().parent.parent / "extension" / "build.py"
        spec = importlib.util.spec_from_file_location("_nmp_ext_build", script)
        if spec is None or spec.loader is None:
            return False
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.build_chrome()
        mod.build_firefox()
    except Exception:
        pass
    return _variant_ready(_repo_dist_dir())


def ensure_extension_files() -> bool:
    """Materialise the per-browser extension builds to their stable location.

    Copies on first run and after an update (the version stamp changes). A
    source checkout loads the committed ``extension/dist`` builds directly.
    Returns whether both usable (chrome + firefox) folders exist afterwards.
    """
    if not getattr(sys, "frozen", False):
        if _variant_ready(_repo_dist_dir()):
            return True
        return _build_dist_from_source()

    source = _bundled_source()
    if source is None:
        return False

    from . import __version__

    base = Path(config.DATA_DIR) / "extension"
    stamp = base / ".version"
    if _variant_ready(base) and stamp.is_file():
        try:
            if stamp.read_text(encoding="utf-8").strip() == __version__:
                return True
        except OSError:
            pass

    try:
        # Replace wholesale so a file removed upstream does not linger and
        # get loaded by the browser.
        if base.exists():
            shutil.rmtree(base, ignore_errors=True)
        base.mkdir(parents=True, exist_ok=True)
        for variant in _VARIANTS:
            src = source / variant
            if src.is_dir():
                shutil.copytree(src, base / variant)
        stamp.write_text(__version__, encoding="utf-8")
    except OSError:
        return _variant_ready(base)

    return _variant_ready(base)


# --------------------------------------------------------------------------
# Browser detection (Windows)
# --------------------------------------------------------------------------

# Executable relative to a Program Files / LocalAppData root.
_WINDOWS_BROWSER_EXES: dict[str, str] = {
    "Chrome": r"Google\Chrome\Application\chrome.exe",
    "Edge": r"Microsoft\Edge\Application\msedge.exe",
    "Brave": r"BraveSoftware\Brave-Browser\Application\brave.exe",
    "Firefox": r"Mozilla Firefox\firefox.exe",
}


def registration_supported() -> bool:
    """Whether this platform can register the native-messaging host.

    Registration is HKCU-based and therefore Windows-only today. Everything
    else here (paths, load-unpacked steps) works cross-platform, so this gates
    only the auto-install / registry actions, not the informational display.
    """
    return sys.platform == "win32"


def _windows_program_roots() -> list[Path]:
    roots: list[Path] = []
    for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        val = os.environ.get(var)
        if val:
            roots.append(Path(val))
    return roots


def browser_executable(browser: str) -> Path | None:
    """The installed executable for *browser*, or None if not found.

    Windows-only; returns None elsewhere (we do not launch browsers on other
    platforms). Checks the standard per-machine and per-user install roots.
    """
    if sys.platform != "win32":
        return None
    rel = _WINDOWS_BROWSER_EXES.get(browser)
    if not rel:
        return None
    for root in _windows_program_roots():
        exe = root / rel
        try:
            if exe.is_file():
                return exe
        except OSError:
            continue
    return None


def installed_browsers() -> list[str]:
    """Supported browsers with an executable present on this machine."""
    return [name for name in BROWSERS if browser_executable(name) is not None]


def _browser_from_progid(prog_id: str) -> str | None:
    """Map a Windows https-handler ProgId to one of our browser names.

    Pure string matching so it is testable without a registry: the ProgIds
    are things like ``ChromeHTML``, ``MSEdgeHTM``, ``BraveHTML``,
    ``FirefoxURL-…``.
    """
    pid = (prog_id or "").lower()
    if "firefox" in pid:
        return "Firefox"
    if "brave" in pid:
        return "Brave"
    if "edge" in pid or "msedge" in pid:
        return "Edge"
    if "chrome" in pid:
        return "Chrome"
    return None


def default_browser() -> str | None:
    """Best-effort name of the user's default browser, or None.

    Reads the per-user https UrlAssociation UserChoice on Windows. Any failure
    (key absent, non-Windows) yields None; callers fall back to a sensible
    default rather than treating None as an error.
    """
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\Shell\Associations"
            r"\UrlAssociations\https\UserChoice",
        ) as key:
            prog_id, _ = winreg.QueryValueEx(key, "ProgId")
    except OSError:
        return None
    return _browser_from_progid(str(prog_id))


def open_extensions_page(browser: str) -> bool:
    """Launch *browser* at its extensions page. Windows-only best effort.

    Returns whether the launch was attempted successfully. The user still has
    to click "Load unpacked" — browsers deliberately forbid an app silently
    installing an unpacked extension — but this puts them one click away.
    """
    exe = browser_executable(browser)
    if exe is None:
        return False
    import subprocess

    try:
        subprocess.Popen([str(exe), extensions_page(browser)])
        return True
    except OSError:
        return False


@dataclass
class InstallOutcome:
    """Result of an :func:`auto_install` run, for the settings UI to render."""

    browser: str
    folder: Path
    files_ready: bool
    registered: bool
    page_opened: bool
    supported: bool


def auto_install(browser: str) -> InstallOutcome:
    """Do everything we can toward installing the extension for *browser*.

    Materialises the files, registers the native-messaging host, and opens the
    browser at its extensions page. Loading the unpacked folder is the one step
    the browser reserves for the user; the caller opens the folder and copies
    its path so that step is trivial.
    """
    folder = extension_dir(browser)
    files_ready = ensure_extension_files()
    registered = False
    page_opened = False
    if files_ready and registration_supported():
        registered = browser in register([browser])
        page_opened = open_extensions_page(browser)
    return InstallOutcome(
        browser=browser,
        folder=folder,
        files_ready=files_ready,
        registered=registered,
        page_opened=page_opened,
        supported=registration_supported(),
    )


@dataclass
class BridgeStatus:
    """What is currently registered, for the settings UI to render."""

    registered: list[str]
    """Browser names with a live registration pointing at our manifest."""

    manifest_path: Path
    extension_dir: Path
    host_command: str
    firefox_dir: Path = field(default_factory=lambda: extension_dir("firefox"))
    supported: bool = True
    detail: str = ""

    @property
    def is_registered(self) -> bool:
        return bool(self.registered)

    @property
    def files_missing(self) -> bool:
        """True when either per-browser build is absent."""
        return not (
            (self.extension_dir / "manifest.json").is_file()
            and (self.firefox_dir / "manifest.json").is_file()
        )

    def folder_for(self, browser: str) -> Path:
        return self.firefox_dir if variant_for(browser) == "firefox" else self.extension_dir


def manifest_path(browser: str = "chrome") -> Path:
    """The host manifest lives with our data, not in the install dir.

    Under Program Files it would need admin rights to write.
    Firefox rejects ``allowed_origins`` and Chrome ignores
    ``allowed_extensions``, so we write two separate files.
    """
    if browser == "Firefox":
        return Path(config.DATA_DIR) / "native-messaging" / f"{HOST_NAME}.firefox.json"
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


# ---- Chromium browsers (allowed_origins) ----


def write_manifest() -> Path:
    """Write the Chromium native-messaging host manifest and return its path."""
    target = manifest_path("chrome")
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


# ---- Firefox (allowed_extensions) ----

def write_firefox_manifest() -> Path:
    """Write the Firefox native-messaging host manifest and return its path."""
    target = manifest_path("Firefox")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": HOST_NAME,
        "description": "NoMorePwn vault bridge",
        "path": str(_ensure_launcher()),
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
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

    # Write both manifests once.
    write_manifest()
    write_firefox_manifest()

    done = []
    for name in browsers or list(BROWSERS):
        subkey = BROWSERS.get(name)
        if not subkey:
            continue
        # Each browser's registry points at the correct manifest variant.
        mpath = manifest_path("Firefox") if name == "Firefox" else manifest_path("chrome")
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{subkey}\\{HOST_NAME}") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(mpath))
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
        extension_dir=extension_dir("chrome"),
        firefox_dir=extension_dir("firefox"),
        host_command=host_command_display(),
    )
    if sys.platform != "win32":
        base.supported = False
        base.detail = "Automatic setup is Windows-only for now — the folder and steps below still apply."
        return base

    import winreg

    for name, subkey in BROWSERS.items():
        expected = str(manifest_path("Firefox") if name == "Firefox" else manifest_path("chrome"))
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{subkey}\\{HOST_NAME}") as key:
                value, _ = winreg.QueryValueEx(key, "")
        except OSError:
            continue
        # A registration pointing at a manifest we no longer write is stale —
        # report it as absent so "Set up" re-points it.
        if str(value).strip().lower() == expected.lower() and Path(expected).exists():
            base.registered.append(name)

    if base.files_missing:
        base.detail = "The browser extension is missing from this install."
    return base
