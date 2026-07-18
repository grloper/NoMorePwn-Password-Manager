"""Shared services handed to every view (toast, clipboard, settings)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from nomorepwn.settings import Settings

from .components import ToastHost
from .util import ClipboardManager


@dataclass
class AppContext:
    settings: Settings
    toast: ToastHost
    clipboard: ClipboardManager
    notify: Callable[[str, str], None]           # tray balloon (title, message)
    mark_activity: Callable[[], None] = lambda: None

    def copy_secret(self, text: str, label: str = "Copied to clipboard") -> None:
        if not text:
            return
        secs = self.settings.clipboard_clear_seconds
        self.clipboard.copy(text, secs)
        msg = f"{label} · clears in {secs}s" if secs else label
        self.toast.show(msg, "success")
