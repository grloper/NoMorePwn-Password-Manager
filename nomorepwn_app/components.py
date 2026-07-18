"""Reusable UI building blocks styled to the active palette.

Kept deliberately small and composable: buttons, cards, pills, avatars,
an animated password-strength meter, and a toast/snackbar host.
"""

from __future__ import annotations

from PySide6.QtCore import (
    Property, QEasingCurve, QPoint, QPropertyAnimation, QRectF, QSize, Qt, QTimer,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QFrame, QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from . import icons, theme

# --------------------------------------------------------------------------
# Buttons
# --------------------------------------------------------------------------


def icon_button(name: str, tooltip: str = "", size: int = 18, color: str | None = None,
                stroke: float = 2.0, checkable: bool = False) -> QPushButton:
    btn = QPushButton()
    btn.setObjectName("IconButton")
    btn.setIcon(icons.icon(name, color, size, stroke))
    btn.setIconSize(_qsize(size))
    btn.setCursor(Qt.PointingHandCursor)
    btn.setCheckable(checkable)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def primary_button(text: str, icon_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("Primary")
    btn.setCursor(Qt.PointingHandCursor)
    if icon_name:
        btn.setIcon(icons.icon(icon_name, theme.active().on_primary, 18))
        btn.setIconSize(_qsize(18))
    return btn


def button(text: str, icon_name: str | None = None, object_name: str = "") -> QPushButton:
    btn = QPushButton(text)
    if object_name:
        btn.setObjectName(object_name)
    btn.setCursor(Qt.PointingHandCursor)
    if icon_name:
        col = theme.active().danger if object_name == "Danger" else theme.active().text
        btn.setIcon(icons.icon(icon_name, col, 18))
        btn.setIconSize(_qsize(18))
    return btn


def _qsize(n: int) -> QSize:
    return QSize(n, n)


def add_reveal_action(line: QLineEdit) -> None:
    """Add an inline eye toggle to a password QLineEdit."""
    line.setEchoMode(QLineEdit.Password)
    p = theme.active()
    act = line.addAction(icons.icon("eye", p.text_muted, 18), QLineEdit.TrailingPosition)

    def toggle():
        if line.echoMode() == QLineEdit.Password:
            line.setEchoMode(QLineEdit.Normal)
            act.setIcon(icons.icon("eye-off", p.text_muted, 18))
        else:
            line.setEchoMode(QLineEdit.Password)
            act.setIcon(icons.icon("eye", p.text_muted, 18))

    act.triggered.connect(toggle)


# --------------------------------------------------------------------------
# Labels & structure
# --------------------------------------------------------------------------


def heading(text: str, level: str = "H2") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(level)
    return lbl


def muted(text: str, name: str = "Muted") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(name)
    lbl.setWordWrap(True)
    return lbl


def field_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("FieldLabel")
    return lbl


class Card(QFrame):
    def __init__(self, parent=None, padding: int = 20, shadow: bool = False):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(padding, padding, padding, padding)
        lay.setSpacing(14)
        self.body = lay
        if shadow:
            eff = QGraphicsDropShadowEffect(self)
            eff.setBlurRadius(40)
            eff.setColor(QColor(0, 0, 0, 60))
            eff.setOffset(0, 10)
            self.setGraphicsEffect(eff)

    def add(self, w) -> None:
        self.body.addWidget(w)


def divider() -> QFrame:
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background:{theme.active().border}; border:none;")
    return line


# --------------------------------------------------------------------------
# Pill / badge
# --------------------------------------------------------------------------


class Pill(QLabel):
    """A small rounded status chip, e.g. 'MFA on' / 'No MFA'."""

    KINDS = {
        "success": ("success", "success_soft"),
        "warning": ("warning", "warning_soft"),
        "danger": ("danger", "danger_soft"),
        "primary": ("primary", "primary_soft"),
    }

    def __init__(self, text: str, kind: str = "neutral", icon_name: str | None = None,
                 parent=None):
        super().__init__(parent)
        self._icon_name = icon_name
        self.set(text, kind)

    def set(self, text: str, kind: str = "neutral") -> None:
        p = theme.active()
        if kind in self.KINDS:
            fg = getattr(p, self.KINDS[kind][0])
            bg = getattr(p, self.KINDS[kind][1])
        else:
            fg, bg = p.text_muted, p.surface_alt
        if self._icon_name:
            self.setPixmap(icons.pixmap(self._icon_name, fg, 13))
        self.setText(f"  {text}" if self._icon_name else text)
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border-radius:9px;"
            f"padding:3px 9px; font-size:11px; font-weight:700;"
        )
        self.setAlignment(Qt.AlignCenter)


# --------------------------------------------------------------------------
# Avatar
# --------------------------------------------------------------------------


class Avatar(QWidget):
    def __init__(self, seed: str, initials: str, size: int = 40, parent=None):
        super().__init__(parent)
        self._seed = seed
        self._initials = initials
        self._size = size
        self.setFixedSize(size, size)

    def update_for(self, seed: str, initials: str) -> None:
        self._seed, self._initials = seed, initials
        self.update()

    def paintEvent(self, event) -> None:
        from .util import avatar_color
        strong, soft = avatar_color(self._seed)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(0, 0, self._size, self._size)
        path = QPainterPath()
        radius = self._size * 0.3
        path.addRoundedRect(rect, radius, radius)
        painter.fillPath(path, QColor(strong))
        painter.setPen(QColor("#FFFFFF"))
        font = QFont(self.font())
        font.setPixelSize(int(self._size * 0.4))
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, self._initials)
        painter.end()


# --------------------------------------------------------------------------
# Password-strength meter
# --------------------------------------------------------------------------


class StrengthMeter(QWidget):
    """Four-segment animated meter + label, coloured by zxcvbn score."""

    COLORS = {0: "#F04438", 1: "#F97316", 2: "#F59E0B", 3: "#84CC16", 4: "#22C55E"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = -1
        self._label = ""
        self._fill = 0.0  # animated 0..1
        self.setMinimumHeight(30)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._anim = QPropertyAnimation(self, b"fill", self)
        self._anim.setDuration(320)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def set_result(self, score: int, label: str) -> None:
        self._score = score
        self._label = label
        target = (score + 1) / 5.0
        self._anim.stop()
        self._anim.setStartValue(self._fill)
        self._anim.setEndValue(target)
        self._anim.start()
        self.update()

    def clear(self) -> None:
        self._score = -1
        self._label = ""
        self._anim.stop()
        self._fill = 0.0
        self.update()

    # animated property
    def get_fill(self):
        return self._fill

    def set_fill(self, v):
        self._fill = v
        self.update()

    fill = Property(float, get_fill, set_fill)

    def paintEvent(self, event) -> None:
        p = theme.active()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        seg_gap = 6
        seg_w = (w - seg_gap * 3) / 4
        bar_h = 7
        y = 2
        color = QColor(self.COLORS.get(self._score, p.border_strong))
        filled_segments = self._fill * 4
        for i in range(4):
            x = i * (seg_w + seg_gap)
            rect = QRectF(x, y, seg_w, bar_h)
            path = QPainterPath()
            path.addRoundedRect(rect, 3.5, 3.5)
            painter.fillPath(path, QColor(p.surface_alt))
            fill_ratio = max(0.0, min(1.0, filled_segments - i))
            if fill_ratio > 0:
                frect = QRectF(x, y, seg_w * fill_ratio, bar_h)
                fpath = QPainterPath()
                fpath.addRoundedRect(frect, 3.5, 3.5)
                painter.fillPath(fpath, color)
        if self._label:
            painter.setPen(color if self._score >= 0 else QColor(p.text_faint))
            font = QFont(self.font())
            font.setPixelSize(12)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(QRectF(0, bar_h + 6, w, 18), Qt.AlignLeft | Qt.AlignVCenter, self._label)
        painter.end()


# --------------------------------------------------------------------------
# Toast / snackbar
# --------------------------------------------------------------------------


class _Toast(QFrame):
    def __init__(self, parent, text: str, kind: str):
        super().__init__(parent)
        p = theme.active()
        accent = {"success": p.success, "error": p.danger, "info": p.primary}.get(kind, p.primary)
        icon_name = {"success": "check-circle", "error": "alert-circle", "info": "info"}.get(kind, "info")
        self.setStyleSheet(
            f"background:{p.surface_alt}; border:1px solid {p.border_strong};"
            f"border-radius:12px;"
        )
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 11, 16, 11)
        lay.setSpacing(10)
        ico = QLabel()
        ico.setPixmap(icons.pixmap(icon_name, accent, 18))
        lay.addWidget(ico)
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color:{p.text}; font-weight:600; background:transparent; border:none;")
        lay.addWidget(lbl)

        eff = QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(38)
        eff.setColor(QColor(0, 0, 0, 90))
        eff.setOffset(0, 8)
        self.setGraphicsEffect(eff)


class ToastHost:
    """Shows transient toasts near the bottom-centre of a host widget."""

    def __init__(self, host: QWidget):
        self._host = host
        self._current: _Toast | None = None

    def show(self, text: str, kind: str = "info", duration: int = 2600) -> None:
        if self._current is not None:
            self._current.deleteLater()
            self._current = None
        toast = _Toast(self._host, text, kind)
        toast.adjustSize()
        self._current = toast
        self._reposition(toast)
        toast.show()
        toast.raise_()

        opacity = QGraphicsOpacityEffect(toast)
        # NOTE: opacity effect and drop shadow can't coexist on one widget;
        # keep the shadow (set above) and animate geometry instead.
        toast.setGraphicsEffect(None)
        toast.setGraphicsEffect(opacity)
        opacity.setOpacity(0.0)
        fade_in = QPropertyAnimation(opacity, b"opacity", toast)
        fade_in.setDuration(200)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.OutCubic)

        start_pos = toast.pos() + QPoint(0, 14)
        end_pos = toast.pos()
        toast.move(start_pos)
        slide = QPropertyAnimation(toast, b"pos", toast)
        slide.setDuration(240)
        slide.setStartValue(start_pos)
        slide.setEndValue(end_pos)
        slide.setEasingCurve(QEasingCurve.OutCubic)
        fade_in.start()
        slide.start()
        toast._anims = (fade_in, slide)  # keep refs alive

        QTimer.singleShot(duration, lambda: self._dismiss(toast, opacity))

    def _dismiss(self, toast: _Toast, opacity) -> None:
        if toast is not self._current:
            return
        fade = QPropertyAnimation(opacity, b"opacity", toast)
        fade.setDuration(220)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.finished.connect(toast.deleteLater)
        fade.start()
        toast._fade_out = fade
        self._current = None

    def _reposition(self, toast: _Toast) -> None:
        host = self._host
        x = (host.width() - toast.width()) // 2
        y = host.height() - toast.height() - 28
        toast.move(max(12, x), max(12, y))
