"""Visual design system: colour palettes and the application stylesheet.

The look targets the calm, trustworthy feel of a modern password manager
(1Password / Bitwarden lineage): a deep indigo brand colour, generous
spacing, soft rounded surfaces, and a single confident accent. Both a
dark and a light palette are provided; the active one is chosen from
:class:`nomorepwn.settings.Settings`.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QPalette


@dataclass(frozen=True)
class Palette:
    name: str
    window: str        # app background
    surface: str       # cards / panels
    surface_alt: str   # raised / hovered surface
    sidebar: str       # left rail
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_faint: str
    primary: str
    primary_hover: str
    primary_press: str
    primary_soft: str  # translucent primary for subtle fills
    on_primary: str
    success: str
    success_soft: str
    warning: str
    warning_soft: str
    danger: str
    danger_soft: str
    field: str
    field_focus_border: str
    selection: str
    shadow: str


DARK = Palette(
    name="dark",
    window="#0E1017",
    surface="#171A23",
    surface_alt="#1F2431",
    sidebar="#0B0D13",
    border="#262B38",
    border_strong="#333A4A",
    text="#EAEDF4",
    text_muted="#9BA4B5",
    text_faint="#6B7385",
    primary="#6366F1",
    primary_hover="#7679F5",
    primary_press="#585BE0",
    primary_soft="rgba(99,102,241,0.16)",
    on_primary="#FFFFFF",
    success="#22C55E",
    success_soft="rgba(34,197,94,0.15)",
    warning="#F59E0B",
    warning_soft="rgba(245,158,11,0.15)",
    danger="#F04438",
    danger_soft="rgba(240,68,56,0.15)",
    field="#12141C",
    field_focus_border="#6366F1",
    selection="rgba(99,102,241,0.20)",
    shadow="rgba(0,0,0,0.45)",
)

LIGHT = Palette(
    name="light",
    window="#F4F5FA",
    surface="#FFFFFF",
    surface_alt="#F0F2F8",
    sidebar="#FFFFFF",
    border="#E5E8F0",
    border_strong="#D3D8E4",
    text="#1B1F2A",
    text_muted="#5B6474",
    text_faint="#8A93A5",
    primary="#5457E5",
    primary_hover="#6366F1",
    primary_press="#4144C9",
    primary_soft="rgba(84,87,229,0.10)",
    on_primary="#FFFFFF",
    success="#12A150",
    success_soft="rgba(18,161,80,0.12)",
    warning="#B25E00",
    warning_soft="rgba(178,94,0,0.12)",
    danger="#D92D20",
    danger_soft="rgba(217,45,32,0.10)",
    field="#F7F8FC",
    field_focus_border="#5457E5",
    selection="rgba(84,87,229,0.12)",
    shadow="rgba(20,25,40,0.14)",
)

PALETTES = {"dark": DARK, "light": LIGHT}

# The palette currently applied to the app. Widgets read this to colour
# icons and custom-painted elements consistently with the stylesheet.
_ACTIVE: Palette = DARK


def get_palette(name: str) -> Palette:
    return PALETTES.get(name, DARK)


def set_active(palette: Palette) -> None:
    global _ACTIVE
    _ACTIVE = palette


def active() -> Palette:
    return _ACTIVE


def build_palette(p: Palette) -> QPalette:
    """A real QPalette for the theme.

    The stylesheet only reaches widgets its selectors match; anything
    unstyled (scroll-area content widgets, plain page containers) would
    otherwise fall back to Qt's default *light* palette — which is how
    white panels leak into the dark theme. Setting the palette makes the
    whole app dark/light at the source.
    """
    qp = QPalette()
    qp.setColor(QPalette.Window, QColor(p.window))
    qp.setColor(QPalette.WindowText, QColor(p.text))
    qp.setColor(QPalette.Base, QColor(p.field))
    qp.setColor(QPalette.AlternateBase, QColor(p.surface_alt))
    qp.setColor(QPalette.Text, QColor(p.text))
    qp.setColor(QPalette.Button, QColor(p.surface_alt))
    qp.setColor(QPalette.ButtonText, QColor(p.text))
    qp.setColor(QPalette.ToolTipBase, QColor(p.surface_alt))
    qp.setColor(QPalette.ToolTipText, QColor(p.text))
    qp.setColor(QPalette.Highlight, QColor(p.primary))
    qp.setColor(QPalette.HighlightedText, QColor(p.on_primary))
    qp.setColor(QPalette.PlaceholderText, QColor(p.text_faint))
    qp.setColor(QPalette.Link, QColor(p.primary))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        qp.setColor(QPalette.Disabled, role, QColor(p.text_faint))
    return qp


def build_stylesheet(p: Palette) -> str:
    """Return the full application QSS for the given palette."""
    return f"""
* {{
    font-family: "Segoe UI", "Inter", system-ui, sans-serif;
    font-size: 14px;
    color: {p.text};
    outline: none;
}}

QWidget#Root, QMainWindow, QDialog {{
    background: {p.window};
}}

/* ---- Sidebar / left rail ---- */
QWidget#Sidebar {{
    background: {p.sidebar};
    border-right: 1px solid {p.border};
}}
QPushButton#NavButton, QToolButton#NavButton {{
    background: transparent;
    border: none;
    border-radius: 14px;
    padding: 10px 4px;
    color: {p.text_muted};
    font-size: 11px;
}}
QPushButton#NavButton:hover, QToolButton#NavButton:hover {{
    background: {p.surface_alt};
    color: {p.text};
}}
QPushButton#NavButton:checked, QToolButton#NavButton:checked {{
    background: {p.primary_soft};
    color: {p.primary};
    font-weight: 700;
}}

/* ---- Cards / panels ---- */
QFrame#Card, QWidget#Card {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 16px;
}}
QFrame#DetailPanel {{
    background: {p.surface};
    border-left: 1px solid {p.border};
}}
QFrame#ListPanel {{
    background: {p.window};
    border-right: 1px solid {p.border};
}}

/* ---- Headings & text ---- */
QLabel#H1 {{ font-size: 26px; font-weight: 700; color: {p.text}; }}
QLabel#H2 {{ font-size: 19px; font-weight: 700; color: {p.text}; }}
QLabel#H3 {{ font-size: 15px; font-weight: 600; color: {p.text}; }}
QLabel#Muted, QLabel#Subtle {{ color: {p.text_muted}; }}
QLabel#Faint {{ color: {p.text_faint}; font-size: 12px; }}
QLabel#FieldLabel {{ color: {p.text_muted}; font-size: 12px; font-weight: 600; }}
QLabel#Mono {{ font-family: "Cascadia Code", "Consolas", monospace; }}

/* ---- Buttons ---- */
QPushButton {{
    background: {p.surface_alt};
    color: {p.text};
    border: 1px solid {p.border_strong};
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {p.border}; }}
QPushButton:pressed {{ background: {p.border_strong}; }}
QPushButton:disabled {{ color: {p.text_faint}; background: {p.surface}; border-color: {p.border}; }}

QPushButton#Primary {{
    background: {p.primary};
    color: {p.on_primary};
    border: none;
    padding: 11px 20px;
    font-weight: 700;
}}
QPushButton#Primary:hover {{ background: {p.primary_hover}; }}
QPushButton#Primary:pressed {{ background: {p.primary_press}; }}
QPushButton#Primary:disabled {{ background: {p.border_strong}; color: {p.text_faint}; }}

QPushButton#Danger {{
    background: transparent;
    color: {p.danger};
    border: 1px solid {p.danger};
}}
QPushButton#Danger:hover {{ background: {p.danger_soft}; }}

QPushButton#Ghost {{
    background: transparent;
    border: none;
    color: {p.text_muted};
    padding: 6px 10px;
}}
QPushButton#Ghost:hover {{ background: {p.surface_alt}; color: {p.text}; }}

QPushButton#IconButton {{
    background: transparent;
    border: none;
    border-radius: 9px;
    padding: 7px;
    color: {p.text_muted};
}}
QPushButton#IconButton:hover {{ background: {p.surface_alt}; color: {p.text}; }}
QPushButton#IconButton:pressed {{ background: {p.border}; }}

QPushButton#LinkButton {{
    background: transparent; border: none; color: {p.primary};
    font-weight: 600; padding: 2px;
}}
QPushButton#LinkButton:hover {{ color: {p.primary_hover}; }}

/* ---- Inputs ---- */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background: {p.field};
    border: 1px solid {p.border_strong};
    border-radius: 10px;
    padding: 10px 12px;
    color: {p.text};
    selection-background-color: {p.primary};
    selection-color: {p.on_primary};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {p.field_focus_border};
    background: {p.surface};
}}
QLineEdit::placeholder {{ color: {p.text_faint}; }}
QLineEdit:disabled {{ color: {p.text_faint}; }}

QLineEdit#Search {{
    padding-left: 36px;
    border-radius: 12px;
}}

QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: 10px;
    selection-background-color: {p.primary_soft};
    selection-color: {p.text};
    padding: 4px;
    outline: none;
}}
QSpinBox::up-button, QSpinBox::down-button {{ width: 18px; border: none; background: {p.surface_alt}; }}

/* ---- Item list ---- */
QListWidget {{
    background: transparent;
    border: none;
    outline: none;
}}
QListWidget::item {{
    border-radius: 12px;
    margin: 2px 6px;
    padding: 0px;
}}
QListWidget::item:hover {{ background: {p.surface_alt}; }}
QListWidget::item:selected {{ background: {p.selection}; }}

/* ---- Settings category nav ---- */
QListWidget#SettingsNav {{
    background: {p.window};
    border: none;
    border-right: 1px solid {p.border};
    padding: 12px 8px;
    outline: none;
}}
QListWidget#SettingsNav::item {{
    border-radius: 10px;
    margin: 2px 4px;
    padding: 10px 12px;
    color: {p.text_muted};
    font-weight: 600;
}}
QListWidget#SettingsNav::item:hover {{
    background: {p.surface_alt};
    color: {p.text};
}}
QListWidget#SettingsNav::item:selected {{
    background: {p.primary_soft};
    color: {p.primary};
}}

/* ---- Checkboxes / toggles ---- */
QCheckBox {{ spacing: 8px; color: {p.text}; }}
QCheckBox::indicator {{
    width: 20px; height: 20px; border-radius: 6px;
    border: 1px solid {p.border_strong}; background: {p.field};
}}
QCheckBox::indicator:checked {{
    background: {p.primary}; border-color: {p.primary};
    image: url(:/check);
}}

/* ---- Scroll areas: let the themed parent show through ---- */
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QAbstractScrollArea::viewport {{ background: transparent; }}

/* ---- Scrollbars ---- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px; }}
QScrollBar::handle:vertical {{ background: {p.border_strong}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {p.text_faint}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 4px; }}
QScrollBar::handle:horizontal {{ background: {p.border_strong}; border-radius: 5px; min-width: 30px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ---- Progress / meters ---- */
QProgressBar {{
    background: {p.surface_alt};
    border: none; border-radius: 5px; height: 8px; text-align: center;
}}
QProgressBar::chunk {{ border-radius: 5px; background: {p.primary}; }}

/* ---- Menus (incl. tray) ---- */
QMenu {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: 12px;
    padding: 6px;
}}
QMenu::item {{ padding: 8px 26px 8px 14px; border-radius: 8px; }}
QMenu::item:selected {{ background: {p.primary_soft}; color: {p.primary}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 6px 8px; }}

/* ---- Tooltips ---- */
QToolTip {{
    background: {p.surface_alt};
    color: {p.text};
    border: 1px solid {p.border_strong};
    border-radius: 8px;
    padding: 6px 9px;
}}

/* ---- Tabs (used sparingly) ---- */
QTabBar::tab {{
    background: transparent; color: {p.text_muted};
    padding: 8px 14px; border-radius: 9px; margin-right: 4px; font-weight: 600;
}}
QTabBar::tab:selected {{ background: {p.primary_soft}; color: {p.primary}; }}
QTabWidget::pane {{ border: none; }}
"""
