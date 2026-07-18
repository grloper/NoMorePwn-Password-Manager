"""Vector icon system — all icons are rendered from inline SVG at runtime.

Keeping icons as code (rather than shipping PNG assets) means the bundled
``.exe`` has no external image dependencies and every glyph re-colours
itself to match the active palette. Icons are Lucide/Feather-style
stroke drawings on a 24x24 grid.
"""

from __future__ import annotations

import functools

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QLinearGradient, QPainter, QPainterPath, QPixmap
from PySide6.QtSvg import QSvgRenderer

from . import theme

# Stroke-based icon path data (inside a 0 0 24 24 viewBox).
_PATHS: dict[str, str] = {
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2.2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "unlock": '<rect x="4" y="11" width="16" height="10" rx="2.2"/><path d="M8 11V7a4 4 0 0 1 7.8-1.2"/>',
    "shield": '<path d="M12 22s7.5-3.6 7.5-9.3V5.4L12 2.5 4.5 5.4v7.3C4.5 18.4 12 22 12 22z"/>',
    "shield-check": '<path d="M12 22s7.5-3.6 7.5-9.3V5.4L12 2.5 4.5 5.4v7.3C4.5 18.4 12 22 12 22z"/><path d="M8.8 12.2l2.2 2.2 4.2-4.4"/>',
    "key": '<circle cx="7.8" cy="15.5" r="4"/><path d="M10.6 12.7 20 3.3"/><path d="M16.5 6.8l2.3 2.3"/><path d="M14.3 9l1.8 1.8"/>',
    "eye": '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M9.6 5.3A9.3 9.3 0 0 1 12 5c6 0 9.5 7 9.5 7a13 13 0 0 1-2 2.9"/><path d="M6.2 6.7A12.8 12.8 0 0 0 2.5 12S6 19 12 19a9 9 0 0 0 3.4-.7"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><line x1="3" y1="3" x2="21" y2="21"/>',
    "copy": '<rect x="9" y="9" width="12" height="12" rx="2.2"/><path d="M5 15H4.5A2 2 0 0 1 3 13V4.5A2 2 0 0 1 4.5 3H13a2 2 0 0 1 2 1.5V5"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "check-circle": '<circle cx="12" cy="12" r="9"/><path d="M8.5 12.2l2.4 2.4 4.6-4.8"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    "trash": '<path d="M3.5 6h17"/><path d="M18.5 6v13.5a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2V6"/><path d="M8.5 6V4.5a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2V6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
    "edit": '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 9 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/>',
    "refresh": '<path d="M21 3v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 21v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/>',
    "sparkles": '<path d="m12 3-1.9 5.6a2 2 0 0 1-1.3 1.3L3 12l5.8 2.1a2 2 0 0 1 1.3 1.3L12 21l1.9-5.6a2 2 0 0 1 1.3-1.3L21 12l-5.8-2.1a2 2 0 0 1-1.3-1.3Z"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4.5 20c0-4 3.6-6 7.5-6s7.5 2 7.5 6"/>',
    "alert-triangle": '<path d="M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><circle cx="12" cy="17" r="0.6"/>',
    "alert-circle": '<circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12.5"/><circle cx="12" cy="16" r="0.6"/>',
    "info": '<circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16"/><circle cx="12" cy="8" r="0.6"/>',
    "x": '<path d="M18 6 6 18M6 6l12 12"/>',
    "chevron-right": '<path d="m9 18 6-6-6-6"/>',
    "chevron-left": '<path d="m15 18-6-6 6-6"/>',
    "chevron-down": '<path d="m6 9 6 6 6-6"/>',
    "arrow-left": '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
    "external": '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5"/>',
    "grid": '<rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.6"/>',
    "activity": '<path d="M22 12h-4l-3 8-6-16-3 8H2"/>',
    "sliders": '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1.5" y1="14" x2="6.5" y2="14"/><line x1="9.5" y1="8" x2="14.5" y2="8"/><line x1="17.5" y1="16" x2="22.5" y2="16"/>',
    "power": '<path d="M18.4 6.6a9 9 0 1 1-12.8 0"/><line x1="12" y1="2.5" x2="12" y2="12"/>',
    "moon": '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M4 4l1.8 1.8M18.2 18.2 20 20M2 12h2.5M19.5 12H22M4 20l1.8-1.8M18.2 5.8 20 4"/>',
    "clipboard": '<rect x="8" y="3" width="8" height="4" rx="1.2"/><path d="M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>',
    "star": '<path d="m12 3 2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.8-5.2 2.8 1-5.8-4.2-4.1 5.8-.8z"/>',
    "history": '<path d="M3 3v6h6"/><path d="M3.5 9a9 9 0 1 1-1 4"/><path d="M12 8v4l3 2"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/>',
    "minimize": '<path d="M5 12h14"/>',
    "maximize": '<rect x="4" y="4" width="16" height="16" rx="2"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "dice": '<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><circle cx="8.5" cy="8.5" r="1.1"/><circle cx="15.5" cy="15.5" r="1.1"/><circle cx="12" cy="12" r="1.1"/>',
    "download": '<path d="M12 3v12"/><path d="m7 11 5 5 5-5"/><path d="M4 20h16"/>',
    "log-out": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
    "wifi-off": '<line x1="2" y1="2" x2="22" y2="22"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M5 12.9a10 10 0 0 1 5.2-2.7"/><path d="M19 12.9a10 10 0 0 0-3.6-2.4"/><path d="M2 8.8a15 15 0 0 1 4.2-2.6"/><path d="M22 8.8a15 15 0 0 0-6.8-3.4"/><circle cx="12" cy="20" r="0.6"/>',
}

_SVG_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
    'stroke="{color}" stroke-width="{sw}" stroke-linecap="round" '
    'stroke-linejoin="round">{paths}</svg>'
)


def render_svg(svg: str, size: int) -> QPixmap:
    """Render an SVG string to a crisp HiDPI QPixmap."""
    dpr = 3
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    img = QImage(size * dpr, size * dpr, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    painter = QPainter(img)
    painter.setRenderHint(QPainter.Antialiasing, True)
    renderer.render(painter, QRectF(0, 0, size * dpr, size * dpr))
    painter.end()
    pm = QPixmap.fromImage(img)
    pm.setDevicePixelRatio(dpr)
    return pm


@functools.lru_cache(maxsize=512)
def _pixmap(name: str, color: str, size: int, sw: float) -> QPixmap:
    paths = _PATHS.get(name, _PATHS["info"])
    svg = _SVG_TEMPLATE.format(color=color, sw=sw, paths=paths)
    return render_svg(svg, size)


def pixmap(name: str, color: str | None = None, size: int = 20, stroke: float = 2.0) -> QPixmap:
    color = color or theme.active().text_muted
    return _pixmap(name, color, size, stroke)


def icon(name: str, color: str | None = None, size: int = 20, stroke: float = 2.0) -> QIcon:
    return QIcon(pixmap(name, color, size, stroke))


# --------------------------------------------------------------------------
# Brand logo & app / tray icons
# --------------------------------------------------------------------------

def _draw_shield(painter: QPainter, rect: QRectF, fill: QColor, glyph: str | None) -> None:
    """Draw a rounded shield filled with a gradient, optional white glyph."""
    w, h = rect.width(), rect.height()
    x, y = rect.x(), rect.y()
    path = QPainterPath()
    # A shield: rounded top, tapering to a point at the bottom.
    path.moveTo(x + w * 0.5, y + h * 0.02)
    path.lineTo(x + w * 0.90, y + h * 0.20)
    path.lineTo(x + w * 0.90, y + h * 0.55)
    path.cubicTo(
        x + w * 0.90, y + h * 0.82,
        x + w * 0.70, y + h * 0.94,
        x + w * 0.50, y + h * 0.99,
    )
    path.cubicTo(
        x + w * 0.30, y + h * 0.94,
        x + w * 0.10, y + h * 0.82,
        x + w * 0.10, y + h * 0.55,
    )
    path.lineTo(x + w * 0.10, y + h * 0.20)
    path.closeSubpath()
    painter.fillPath(path, fill)

    if glyph == "keyhole":
        white = QColor("#FFFFFF")
        cx, cy = x + w * 0.5, y + h * 0.42
        r = w * 0.11
        painter.setBrush(white)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(cx - r, cy - r, 2 * r, 2 * r))
        stem = QPainterPath()
        stem.moveTo(cx - r * 0.55, cy + r * 0.2)
        stem.lineTo(cx - r * 0.95, cy + r * 2.3)
        stem.lineTo(cx + r * 0.95, cy + r * 2.3)
        stem.lineTo(cx + r * 0.55, cy + r * 0.2)
        stem.closeSubpath()
        painter.fillPath(stem, white)


def logo_pixmap(size: int = 96, locked: bool | None = None) -> QPixmap:
    """The NoMorePwn brand mark: a gradient shield with a keyhole.

    When ``locked`` is given, a small status dot (amber locked / green
    unlocked) is added for the system-tray variant.
    """
    dpr = 3
    p = theme.active()
    img = QImage(size * dpr, size * dpr, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    painter = QPainter(img)
    painter.setRenderHint(QPainter.Antialiasing, True)

    rect = QRectF(size * dpr * 0.08, size * dpr * 0.04, size * dpr * 0.84, size * dpr * 0.92)
    grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
    grad.setColorAt(0.0, QColor("#6366F1"))
    grad.setColorAt(1.0, QColor("#8B5CF6"))
    from PySide6.QtGui import QBrush
    _draw_shield(painter, rect, QBrush(grad), "keyhole")

    if locked is not None:
        dot = QColor(p.warning if locked else p.success)
        dr = size * dpr * 0.26
        dx = size * dpr - dr * 1.02
        dy = size * dpr - dr * 1.02
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(p.window))
        painter.drawEllipse(QRectF(dx - dr * 0.14, dy - dr * 0.14, dr * 1.28, dr * 1.28))
        painter.setBrush(dot)
        painter.drawEllipse(QRectF(dx, dy, dr, dr))

    painter.end()
    pm = QPixmap.fromImage(img)
    pm.setDevicePixelRatio(dpr)
    return pm


def app_icon() -> QIcon:
    ic = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(logo_pixmap(s))
    return ic


def tray_icon(locked: bool) -> QIcon:
    ic = QIcon()
    for s in (16, 24, 32, 48, 64):
        ic.addPixmap(logo_pixmap(s, locked=locked))
    return ic
