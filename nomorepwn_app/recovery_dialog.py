"""Recovery-kit dialogs: mint a kit (from Settings) and recover with one
(from the lock screen).

The security-relevant logic lives in plain methods (`build`, `write_kit`,
`recover`) so it can be exercised in tests without driving `exec()`. Nothing
here stores a recovery secret anywhere the core doesn't — the dialogs only
display what `Vault.create_recovery_kit` returns and hand it to the user.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QVBoxLayout, QWidget,
)

from nomorepwn import recovery, vault

from . import components, theme

_ACCEPTED = QDialog.DialogCode.Accepted


def qr_pixmap(data: str, scale: int = 5):
    """Render ``data`` as a scannable QR ``QPixmap``.

    Returns ``None`` if the (offline, pure-Python) ``qrcode`` library is not
    installed, so the dialog degrades to showing the seed text rather than
    breaking. The matrix is painted by hand, so no image backend (PIL) is
    needed.
    """
    try:
        import qrcode
    except ImportError:
        return None
    from PySide6.QtGui import QColor, QImage, QPainter, QPixmap

    qr = qrcode.QRCode(border=2, box_size=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    size = len(matrix) * scale
    img = QImage(size, size, QImage.Format_RGB32)
    img.fill(QColor("white"))
    painter = QPainter(img)
    black = QColor("black")
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if cell:
                painter.fillRect(x * scale, y * scale, scale, scale, black)
    painter.end()
    return QPixmap.fromImage(img)


def offer_recovery_setup(parent, ctx) -> None:
    """First-run nudge: right after the vault is created, offer to make a
    recovery kit so a forgotten password isn't fatal. A no-op if the vault
    isn't unlocked (so it can never block on a modal without one)."""
    from .dialogs import confirm

    if ctx.get_vault() is None:
        return
    if confirm(
        parent, "Set up account recovery?",
        "Right now, if you forget your master password, this vault is gone for "
        "good.\n\nA Recovery Kit prevents that: it escrows your key into a file "
        "you keep yourself — nothing about it is stored in your vault. You can "
        "also require an authenticator app as a second factor. Set one up now?",
        confirm_text="Set up recovery kit", cancel_text="Maybe later",
    ):
        RecoveryKitDialog(parent, ctx.get_vault, ctx).exec()


def _mono(label: QLabel) -> QLabel:
    p = theme.active()
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    label.setStyleSheet(
        f"font-family:'Cascadia Code','Consolas',monospace; font-size:13px;"
        f" padding:8px 12px; background:{p.field};"
        f" border:1px solid {p.border_strong}; border-radius:8px; color:{p.text};"
    )
    return label


class RecoveryKitDialog(QDialog):
    """Create a Recovery Kit for the (unlocked) vault and save it out of band."""

    def __init__(self, parent, get_vault: Callable[[], "vault.Vault | None"], ctx=None):
        super().__init__(parent)
        self.setWindowTitle("Create a recovery kit")
        self.setModal(True)
        self.setMinimumWidth(520)
        self._get_vault = get_vault
        self._ctx = ctx
        self._result: dict | None = None
        p = theme.active()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(12)

        lay.addWidget(components.heading("Create a recovery kit", "H3"))
        lay.addWidget(components.muted(
            "A recovery kit lets you get back into this vault if you forget your "
            "master password. Nothing about it is stored in your vault file — it "
            "works only with the secrets shown below, which you must save yourself."))

        self.mode = QComboBox()
        self.mode.addItem("Standard — kit file + recovery code", recovery.MODE_KIT)
        self.mode.addItem("Extra secure — also an authenticator seed", recovery.MODE_KIT_TOTP)
        lay.addWidget(self.mode)

        self.gen_btn = components.primary_button("Generate recovery kit", "key")
        self.gen_btn.clicked.connect(self._on_generate)
        lay.addWidget(self.gen_btn)

        # Result area (hidden until generated).
        self.result_box = QWidget()
        rlay = QVBoxLayout(self.result_box)
        rlay.setContentsMargins(0, 4, 0, 0)
        rlay.setSpacing(8)
        self.warn = QLabel("Shown once, never stored. Save everything below before you close.")
        self.warn.setWordWrap(True)
        self.warn.setStyleSheet(f"color:{p.warning}; font-weight:600;")
        rlay.addWidget(self.warn)

        self.steps_lbl = QLabel("")
        self.steps_lbl.setWordWrap(True)
        self.steps_lbl.setTextFormat(Qt.RichText)
        rlay.addWidget(self.steps_lbl)

        rlay.addWidget(components.field_label("① Recovery code — write it down, keep it apart from the kit file"))
        self.code_lbl = _mono(QLabel(""))
        rlay.addWidget(self.code_lbl)

        # Authenticator block — only shown for the kit+totp mode.
        self.seed_label = components.field_label("② Authenticator — scan this into your app")
        rlay.addWidget(self.seed_label)
        self.qr_lbl = QLabel()
        self.qr_lbl.setAlignment(Qt.AlignCenter)
        rlay.addWidget(self.qr_lbl)
        self.seed_hint = components.muted(
            "No camera? Type this seed into your authenticator instead. Either way, "
            "save the seed itself somewhere safe — recovery needs the seed, not the "
            "rotating 6-digit code.")
        rlay.addWidget(self.seed_hint)
        self.seed_lbl = _mono(QLabel(""))
        rlay.addWidget(self.seed_lbl)
        self.result_box.setVisible(False)
        lay.addWidget(self.result_box)

        self.error = QLabel("")
        self.error.setStyleSheet(f"color:{p.danger}; font-size:12px; font-weight:600;")
        self.error.setVisible(False)
        lay.addWidget(self.error)

        btns = QHBoxLayout()
        btns.addStretch(1)
        self.close_btn = components.button("Close", object_name="Ghost")
        self.close_btn.clicked.connect(self.accept)
        self.save_btn = components.primary_button("Save kit file…", "download")
        self.save_btn.clicked.connect(self._on_save)
        self.save_btn.setEnabled(False)
        btns.addWidget(self.close_btn)
        btns.addWidget(self.save_btn)
        lay.addLayout(btns)

    # -- testable logic -------------------------------------------------

    def build(self, mode: str) -> dict:
        """Generate the kit for ``mode`` and remember it. Raises on failure."""
        vlt = self._get_vault()
        if vlt is None:
            raise vault.VaultError("Unlock the vault first.")
        self._result = vlt.create_recovery_kit(mode=mode)
        return self._result

    def write_kit(self, path: str | Path) -> Path:
        """Write the generated kit bytes to ``path``."""
        if not self._result:
            raise vault.VaultError("Generate a kit first.")
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self._result["kit_bytes"])
        return dest

    # -- slots ----------------------------------------------------------

    def _on_generate(self) -> None:
        self.error.setVisible(False)
        try:
            result = self.build(self.mode.currentData())
        except (vault.VaultError, recovery.RecoveryError) as exc:
            self.error.setText(str(exc))
            self.error.setVisible(True)
            return
        self.code_lbl.setText(result["recovery_code"])
        is_totp = result["mode"] == recovery.MODE_KIT_TOTP
        for w in (self.seed_label, self.qr_lbl, self.seed_hint, self.seed_lbl):
            w.setVisible(is_totp)
        if is_totp:
            self.seed_lbl.setText(result["totp_secret"])
            pix = qr_pixmap(result["totp_uri"])
            if pix is not None:
                self.qr_lbl.setPixmap(pix)
            else:
                self.qr_lbl.setVisible(False)  # no qrcode lib: seed text still shown
            self.steps_lbl.setText(
                "To get back in later you'll need <b>all three</b>: this kit file, "
                "the recovery code, and the authenticator seed. Store the seed and "
                "the code separately from the kit file — that's what stops a stolen "
                "kit from opening your vault.")
        else:
            self.steps_lbl.setText(
                "To get back in later you'll need <b>both</b> the kit file and the "
                "recovery code. Keep the code somewhere separate from the kit file.")
        self.result_box.setVisible(True)
        self.save_btn.setEnabled(True)
        self.save_btn.setText("③ Save kit file… (do this now)")
        self.gen_btn.setEnabled(False)
        self.mode.setEnabled(False)

    def _on_save(self) -> None:
        default = str(Path.home() / f"nomorepwn-recovery{recovery.KIT_EXTENSION}")
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Save recovery kit", default,
            f"Recovery kit (*{recovery.KIT_EXTENSION})")
        if not chosen:
            return
        try:
            dest = self.write_kit(chosen)
        except OSError as exc:
            self.error.setText(f"Could not write the kit: {exc}")
            self.error.setVisible(True)
            return
        if self._ctx is not None:
            self._ctx.toast.show(f"Recovery kit saved: {dest.name}", "success", 4000)


class RecoverDialog(QDialog):
    """Recover a vault with a kit, then set a new master password."""

    def __init__(self, parent, db_path: str):
        super().__init__(parent)
        self.setWindowTitle("Recover with a recovery kit")
        self.setModal(True)
        self.setMinimumWidth(500)
        self._db_path = db_path
        self._kit_bytes: bytes | None = None
        self.vault: "vault.Vault | None" = None
        p = theme.active()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(10)

        lay.addWidget(components.heading("Recover with a recovery kit", "H3"))
        lay.addWidget(components.muted(
            "Use the recovery kit you saved earlier to get back in, then choose a "
            "new master password. The whole vault is re-encrypted under it (a "
            "pre-recovery copy is kept)."))

        pick = QHBoxLayout()
        self.pick_btn = components.button("Choose kit file…", "external")
        self.pick_btn.clicked.connect(self._browse)
        self.kit_path = QLabel("No kit chosen.")
        self.kit_path.setObjectName("Faint")
        self.kit_path.setWordWrap(True)
        pick.addWidget(self.pick_btn)
        pick.addWidget(self.kit_path, 1)
        lay.addLayout(pick)

        lay.addWidget(components.field_label("Recovery code"))
        self.code = QLineEdit()
        self.code.setPlaceholderText("The code shown when you made the kit")
        components.add_reveal_action(self.code)
        lay.addWidget(self.code)

        self.seed_label = components.field_label("Authenticator seed")
        lay.addWidget(self.seed_label)
        self.seed = QLineEdit()
        self.seed.setPlaceholderText("Only if your kit uses an authenticator")
        components.add_reveal_action(self.seed)
        lay.addWidget(self.seed)
        self._set_seed_visible(False)

        lay.addWidget(components.field_label("New master password"))
        self.new_pw = QLineEdit()
        self.new_pw.setPlaceholderText("At least 10 characters")
        components.add_reveal_action(self.new_pw)
        lay.addWidget(self.new_pw)
        self.new_pw2 = QLineEdit()
        self.new_pw2.setPlaceholderText("Confirm new master password")
        components.add_reveal_action(self.new_pw2)
        lay.addWidget(self.new_pw2)

        self.error = QLabel("")
        self.error.setStyleSheet(f"color:{p.danger}; font-size:12px; font-weight:600;")
        self.error.setVisible(False)
        lay.addWidget(self.error)

        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = components.button("Cancel", object_name="Ghost")
        cancel.clicked.connect(self.reject)
        self.recover_btn = components.primary_button("Recover & set password", "unlock")
        self.recover_btn.clicked.connect(self._on_recover)
        btns.addWidget(cancel)
        btns.addWidget(self.recover_btn)
        lay.addLayout(btns)

    def _set_seed_visible(self, visible: bool) -> None:
        self.seed_label.setVisible(visible)
        self.seed.setVisible(visible)

    # -- testable logic -------------------------------------------------

    def recover(self, kit_bytes: bytes | None, code: str, seed: str,
                new_pw: str, confirm_pw: str) -> "vault.Vault":
        """Validate everything, recover the key, and rekey. Raises on any error."""
        if not kit_bytes:
            raise recovery.RecoveryError("Choose your recovery kit file first.")
        if len(new_pw) < 10:
            raise vault.VaultError("New master password must be at least 10 characters.")
        if new_pw != confirm_pw:
            raise vault.VaultError("The two new passwords don't match.")
        unlocked = vault.Vault.unlock_with_recovery(
            self._db_path, kit_bytes, code, seed or None)
        unlocked.rekey(new_pw)
        return unlocked

    # -- slots ----------------------------------------------------------

    def _browse(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Choose recovery kit", str(Path.home()),
            f"Recovery kit (*{recovery.KIT_EXTENSION});;All files (*)")
        if not chosen:
            return
        self.error.setVisible(False)
        try:
            self._kit_bytes = Path(chosen).read_bytes()
            header = recovery.read_kit_header(self._kit_bytes)
        except (OSError, recovery.RecoveryError) as exc:
            self._kit_bytes = None
            self.kit_path.setText("No kit chosen.")
            self.error.setText(str(exc))
            self.error.setVisible(True)
            return
        self.kit_path.setText(Path(chosen).name)
        self._set_seed_visible(header.get("mode") == recovery.MODE_KIT_TOTP)

    def _on_recover(self) -> None:
        self.error.setVisible(False)
        try:
            self.vault = self.recover(
                self._kit_bytes, self.code.text(), self.seed.text(),
                self.new_pw.text(), self.new_pw2.text())
        except (recovery.RecoveryError, vault.VaultError) as exc:
            self.error.setText(str(exc))
            self.error.setVisible(True)
            return
        self.accept()
