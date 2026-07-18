"""Reusable password / passphrase generator panel.

Used both on the standalone Generator page and inline in the credential
editor. All randomness comes from :mod:`nomorepwn.generator` (CSPRNG).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSlider, QVBoxLayout, QWidget,
)

from nomorepwn import generator, strength

from . import components, icons, theme


class _Segmented(QWidget):
    """A two-option pill toggle (Password / Passphrase)."""

    changed = Signal(int)

    def __init__(self, options: list[str], parent=None):
        super().__init__(parent)
        p = theme.active()
        self.setStyleSheet(
            f"QWidget#seg {{ background:{p.surface_alt}; border-radius:11px; }}"
        )
        self.setObjectName("seg")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        for i, opt in enumerate(options):
            btn = QPushButton(opt)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(
                f"QPushButton {{ background:transparent; border:none; border-radius:8px;"
                f" padding:7px 18px; color:{p.text_muted}; font-weight:600; }}"
                f"QPushButton:checked {{ background:{p.primary}; color:{p.on_primary}; }}"
            )
            self._group.addButton(btn, i)
            lay.addWidget(btn)
            if i == 0:
                btn.setChecked(True)
        self._group.idClicked.connect(self.changed.emit)

    def current(self) -> int:
        return self._group.checkedId()


class GeneratorPanel(QWidget):
    """Emits ``generated`` whenever a fresh secret is produced."""

    generated = Signal(str)
    use_requested = Signal(str)

    def __init__(self, show_use_button: bool = False, parent=None):
        super().__init__(parent)
        p = theme.active()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(16)

        # -- Output display --------------------------------------------
        out_row = QHBoxLayout()
        out_row.setSpacing(8)
        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(56)
        self.output.setObjectName("Mono")
        self.output.setStyleSheet(
            f"QLineEdit {{ font-family:'Cascadia Code','Consolas',monospace;"
            f" font-size:18px; padding:8px 14px; background:{p.field};"
            f" border:1px solid {p.border_strong}; border-radius:12px; color:{p.text}; }}"
        )
        out_row.addWidget(self.output, 1)
        self.copy_btn = components.icon_button("copy", "Copy", 20)
        self.copy_btn.setFixedSize(44, 44)
        self.regen_btn = components.icon_button("refresh", "Regenerate", 20)
        self.regen_btn.setFixedSize(44, 44)
        out_row.addWidget(self.copy_btn)
        out_row.addWidget(self.regen_btn)
        root.addLayout(out_row)

        self.meter = components.StrengthMeter()
        root.addWidget(self.meter)

        # -- Mode toggle -----------------------------------------------
        self.mode = _Segmented(["Password", "Passphrase"])
        root.addWidget(self.mode, 0, Qt.AlignLeft)

        # -- Password options ------------------------------------------
        self.pw_box = QWidget()
        pw = QVBoxLayout(self.pw_box)
        pw.setContentsMargins(0, 0, 0, 0)
        pw.setSpacing(12)

        len_row = QHBoxLayout()
        len_lbl = QLabel("Length")
        len_lbl.setObjectName("Muted")
        self.length = QSlider(Qt.Horizontal)
        self.length.setRange(8, 64)
        self.length.setValue(20)
        self.len_value = QLabel("20")
        self.len_value.setFixedWidth(28)
        self.len_value.setStyleSheet(f"font-weight:700; color:{p.primary};")
        len_row.addWidget(len_lbl)
        len_row.addWidget(self.length, 1)
        len_row.addWidget(self.len_value)
        pw.addLayout(len_row)

        opts = QHBoxLayout()
        opts.setSpacing(18)
        self.cb_upper = QCheckBox("A-Z")
        self.cb_lower = QCheckBox("a-z")
        self.cb_digits = QCheckBox("0-9")
        self.cb_symbols = QCheckBox("!@#")
        for cb in (self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols):
            cb.setChecked(True)
            opts.addWidget(cb)
        opts.addStretch(1)
        pw.addLayout(opts)
        self.cb_ambig = QCheckBox("Avoid ambiguous characters (O/0, l/1)")
        pw.addWidget(self.cb_ambig)
        root.addWidget(self.pw_box)

        # -- Passphrase options ----------------------------------------
        self.pp_box = QWidget()
        pp = QVBoxLayout(self.pp_box)
        pp.setContentsMargins(0, 0, 0, 0)
        pp.setSpacing(12)
        words_row = QHBoxLayout()
        words_lbl = QLabel("Words")
        words_lbl.setObjectName("Muted")
        self.words = QSlider(Qt.Horizontal)
        self.words.setRange(3, 8)
        self.words.setValue(4)
        self.words_value = QLabel("4")
        self.words_value.setFixedWidth(28)
        self.words_value.setStyleSheet(f"font-weight:700; color:{p.primary};")
        words_row.addWidget(words_lbl)
        words_row.addWidget(self.words, 1)
        words_row.addWidget(self.words_value)
        pp.addLayout(words_row)
        sep_row = QHBoxLayout()
        sep_lbl = QLabel("Separator")
        sep_lbl.setObjectName("Muted")
        self.sep = QComboBox()
        self.sep.addItems(["-", ".", "_", "  (space)"])
        sep_row.addWidget(sep_lbl)
        sep_row.addWidget(self.sep, 1)
        pp.addLayout(sep_row)
        self.cb_cap = QCheckBox("Capitalise words")
        self.cb_cap.setChecked(True)
        self.cb_num = QCheckBox("Add a number")
        self.cb_num.setChecked(True)
        pp.addWidget(self.cb_cap)
        pp.addWidget(self.cb_num)
        self.pp_box.setVisible(False)
        root.addWidget(self.pp_box)

        if show_use_button:
            self.use_btn = components.primary_button("Use this password", "check")
            root.addWidget(self.use_btn)
            self.use_btn.clicked.connect(lambda: self.use_requested.emit(self.output.text()))
        else:
            self.use_btn = None

        # -- Wiring ----------------------------------------------------
        self.mode.changed.connect(self._on_mode)
        self.regen_btn.clicked.connect(self.regenerate)
        self.length.valueChanged.connect(lambda v: (self.len_value.setText(str(v)), self.regenerate()))
        self.words.valueChanged.connect(lambda v: (self.words_value.setText(str(v)), self.regenerate()))
        for cb in (self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols,
                   self.cb_ambig, self.cb_cap, self.cb_num):
            cb.toggled.connect(self.regenerate)
        self.sep.currentIndexChanged.connect(self.regenerate)

        self.regenerate()

    # ------------------------------------------------------------------

    def _on_mode(self, idx: int) -> None:
        self.pw_box.setVisible(idx == 0)
        self.pp_box.setVisible(idx == 1)
        self.regenerate()

    def _ensure_one_class(self) -> None:
        if not any(cb.isChecked() for cb in
                   (self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols)):
            self.cb_lower.blockSignals(True)
            self.cb_lower.setChecked(True)
            self.cb_lower.blockSignals(False)

    def regenerate(self) -> None:
        if self.mode.current() == 0:
            self._ensure_one_class()
            opts = generator.PasswordOptions(
                length=self.length.value(),
                use_upper=self.cb_upper.isChecked(),
                use_lower=self.cb_lower.isChecked(),
                use_digits=self.cb_digits.isChecked(),
                use_symbols=self.cb_symbols.isChecked(),
                avoid_ambiguous=self.cb_ambig.isChecked(),
            )
            secret = generator.generate_password(opts)
        else:
            sep = self.sep.currentText()
            sep = " " if sep.strip() == "(space)" else sep
            secret = generator.generate_passphrase(
                words=self.words.value(),
                separator=sep,
                capitalize=self.cb_cap.isChecked(),
                add_number=self.cb_num.isChecked(),
            )
        self.output.setText(secret)
        self.output.setCursorPosition(0)  # show the start, not the tail, for long values
        result = strength.evaluate(secret)
        self.meter.set_result(result.score, f"{result.label} · cracks in {result.crack_time_display}")
        self.generated.emit(secret)

    def value(self) -> str:
        return self.output.text()
