"""Small UI-side helpers: clipboard auto-wipe, time formatting, avatars."""

from __future__ import annotations

import hashlib

from PySide6.QtCore import QObject, QTimer
from PySide6.QtGui import QGuiApplication


class ClipboardManager(QObject):
    """Copies secrets to the clipboard and wipes them after a delay.

    Only clears if the clipboard still holds *our* value, so we never
    stomp on something the user copied in the meantime.
    """

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._wipe)
        self._pending: str | None = None

    def copy(self, text: str, clear_seconds: int = 20) -> None:
        clip = QGuiApplication.clipboard()
        clip.setText(text)
        self._pending = text
        self._timer.stop()
        if clear_seconds and clear_seconds > 0:
            self._timer.start(clear_seconds * 1000)

    def _wipe(self) -> None:
        clip = QGuiApplication.clipboard()
        if self._pending is not None and clip.text() == self._pending:
            clip.clear()
        self._pending = None


# Deterministic, friendly avatar colours (paired bg tint / strong fg).
_AVATAR_COLORS = [
    ("#6366F1", "#EEF0FF"), ("#2DD4BF", "#E4FFFB"), ("#F59E0B", "#FFF6E6"),
    ("#EC4899", "#FFE9F4"), ("#22C55E", "#E7FCEF"), ("#3B82F6", "#E8F1FF"),
    ("#A855F7", "#F6EBFF"), ("#F43F5E", "#FFE9EC"), ("#14B8A6", "#E2FBF6"),
    ("#EAB308", "#FCF6DC"),
]


def avatar_color(seed: str) -> tuple[str, str]:
    """Return a stable (strong, soft) colour pair for a service name."""
    h = int(hashlib.md5(seed.lower().encode("utf-8")).hexdigest(), 16)
    return _AVATAR_COLORS[h % len(_AVATAR_COLORS)]


def initials(name: str) -> str:
    name = (name or "?").strip()
    parts = [p for p in name.replace(".", " ").split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[1][0]).upper()


def human_age(days: int | None) -> str:
    """Turn an age in days into a friendly phrase."""
    if days is None:
        return "unknown"
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    if days < 365:
        months = max(1, days // 30)
        return f"{months} month{'s' if months > 1 else ''} ago"
    years = days // 365
    rem_months = (days % 365) // 30
    if rem_months:
        return f"{years}y {rem_months}mo ago"
    return f"{years} year{'s' if years > 1 else ''} ago"
