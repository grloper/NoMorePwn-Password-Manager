"""Restore or import passwords from an encrypted backup file."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Callable

from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout,
)

from nomorepwn import backup, vault

from . import components, theme, workers
from .context import AppContext
from .dialogs import _OptionCard, confirm

ACTION_REPLACE = "replace"
ACTION_MERGE = "merge"


class RestoreDialog(QDialog):
    """Two ways in:

    * **Replace** — overwrite the current vault with the backup's contents.
      A safety copy of the current vault is written first.
    * **Merge** — add entries from the backup that this vault doesn't have,
      keeping everything you already store. Never overwrites.
    """

    def __init__(self, parent, db_path: str, get_vault: Callable[[], "vault.Vault | None"],
                 ctx: AppContext):
        super().__init__(parent)
        self._db_path = db_path
        self._get_vault = get_vault
        self._ctx = ctx
        self._header: dict | None = None
        self.outcome: str | None = None
        self.summary: str = ""

        self.setWindowTitle("Restore from backup")
        self.setModal(True)
        self.setMinimumWidth(520)
        p = theme.active()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(12)

        lay.addWidget(components.heading("Restore from backup", "H2"))
        lay.addWidget(components.muted(
            "Pick a .nmpbak file. It stays encrypted until you enter the "
            "secret that protects it."))

        # -- File picker ------------------------------------------------
        lay.addWidget(components.field_label("Backup file"))
        file_row = QHBoxLayout()
        file_row.setSpacing(8)
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("…\\NoMorePwn\\backups\\vault-backup.nmpbak")
        file_row.addWidget(self.file_edit, 1)
        browse = components.button("Browse…", "download")
        browse.clicked.connect(self._browse)
        file_row.addWidget(browse)
        lay.addLayout(file_row)

        self.info = QLabel("")
        self.info.setObjectName("Faint")
        self.info.setWordWrap(True)
        lay.addWidget(self.info)

        # -- Secret -----------------------------------------------------
        self.secret_label = components.field_label("Master password")
        lay.addWidget(self.secret_label)
        self.secret = QLineEdit()
        components.add_reveal_action(self.secret)
        lay.addWidget(self.secret)

        # Only needed when merging from a passphrase-protected backup.
        self.master_label = components.field_label("Master password of that backup")
        self.master_pw = QLineEdit()
        components.add_reveal_action(self.master_pw)
        self.master_label.setVisible(False)
        self.master_pw.setVisible(False)
        lay.addWidget(self.master_label)
        lay.addWidget(self.master_pw)

        # -- Action -----------------------------------------------------
        lay.addWidget(components.field_label("What should happen"))
        self.merge_card = _OptionCard(
            "plus", "Import missing items (recommended)",
            "Adds entries from the backup that aren't in your vault. Nothing is overwritten.",
            p.primary)
        self.replace_card = _OptionCard(
            "refresh", "Replace my whole vault",
            "Discards the current vault and restores the backup exactly. A safety copy is saved first.",
            p.warning)
        self.merge_card.setChecked(True)
        self.merge_card.clicked.connect(lambda: self._choose(ACTION_MERGE))
        self.replace_card.clicked.connect(lambda: self._choose(ACTION_REPLACE))
        lay.addWidget(self.merge_card)
        lay.addWidget(self.replace_card)
        self._action = ACTION_MERGE

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = components.button("Cancel", object_name="Ghost")
        cancel.clicked.connect(self.reject)
        btns.addWidget(cancel)
        self.go = components.primary_button("Restore", "check")
        self.go.clicked.connect(self._start)
        btns.addWidget(self.go)
        lay.addLayout(btns)

        self.file_edit.textChanged.connect(self._inspect)
        default = Path(ctx.settings.backup_directory()) / ("vault-backup" + backup.BACKUP_EXTENSION)
        if default.exists():
            self.file_edit.setText(str(default))

    # ------------------------------------------------------------------

    def _choose(self, action: str) -> None:
        self._action = action
        self.merge_card.setChecked(action == ACTION_MERGE)
        self.replace_card.setChecked(action == ACTION_REPLACE)
        self._sync_fields()

    def _browse(self) -> None:
        start = str(self._ctx.settings.backup_directory())
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a backup file", start,
            f"NoMorePwn backups (*{backup.BACKUP_EXTENSION} *{backup.BACKUP_EXTENSION}.*);;All files (*)")
        if path:
            self.file_edit.setText(path)

    def _inspect(self) -> None:
        p = theme.active()
        self._header = None
        path = Path(self.file_edit.text().strip())
        if not path.is_file():
            self.info.setText("")
            self._sync_fields()
            return
        try:
            self._header = backup.read_header(path.read_bytes())
        except backup.BackupError as exc:
            self.info.setText(str(exc))
            self.info.setStyleSheet(f"color:{p.danger};")
            self._sync_fields()
            return
        self.info.setText(backup.describe(self._header))
        self.info.setStyleSheet(f"color:{p.text_muted};")
        self._sync_fields()

    def _sync_fields(self) -> None:
        mode = (self._header or {}).get("mode", backup.MODE_MASTER)
        if mode == backup.MODE_PASSPHRASE:
            self.secret_label.setText("BACKUP PASSPHRASE")
            need_master = self._action == ACTION_MERGE
        else:
            self.secret_label.setText("MASTER PASSWORD")
            need_master = False
        self.master_label.setVisible(need_master)
        self.master_pw.setVisible(need_master)

    # ------------------------------------------------------------------

    def _start(self) -> None:
        path = Path(self.file_edit.text().strip())
        if not path.is_file():
            self._fail("Choose a backup file first.")
            return
        secret = self.secret.text()
        if not secret:
            self._fail("Enter the password that protects this backup.")
            return

        if self._action == ACTION_REPLACE:
            if not confirm(
                self, "Replace your entire vault?",
                "Every item currently in your vault will be discarded and replaced "
                "by the contents of this backup. A safety copy of the current vault "
                "is saved first, but this cannot be undone from the app.",
                confirm_text="Replace vault", danger=True,
            ):
                return

        blob = path.read_bytes()
        mode = (self._header or {}).get("mode", backup.MODE_MASTER)
        inner_pw = self.master_pw.text() if (
            mode == backup.MODE_PASSPHRASE and self._action == ACTION_MERGE) else secret
        action = self._action
        db_path = self._db_path
        current = self._get_vault()

        self.go.setEnabled(False)
        self.go.setText("Working…")
        self.status.setText("Decrypting backup…")
        self.status.setStyleSheet(f"color:{theme.active().text_muted};")

        def work():
            if action == ACTION_REPLACE:
                # Safety copy of the CURRENT vault before overwriting it.
                if current is not None:
                    safety = Path(db_path).with_name("vault-before-restore" + backup.BACKUP_EXTENSION)
                    try:
                        current.write_backup(safety)
                    except Exception:
                        pass  # never block a restore on the safety copy
                backup.restore_to_path(blob, secret, db_path)
                return ("replaced", 0, 0)

            # Merge: decrypt into a temp vault, then copy missing entries.
            vault_bytes = backup.open_blob(blob, secret)
            with tempfile.TemporaryDirectory() as tmp:
                temp_db = Path(tmp) / "restore.db"
                temp_db.write_bytes(vault_bytes)
                try:
                    source = vault.Vault.unlock(temp_db, inner_pw)
                except vault.InvalidMasterPasswordError:
                    raise backup.BackupPasswordError(
                        "That opened the backup file, but its vault master password is different. "
                        "Enter the master password this backup was created with.")
                if current is None:
                    raise backup.BackupError("Unlock your vault before importing.")
                imported, skipped = current.merge_from(source)
                source.lock()
            return ("merged", imported, skipped)

        workers.run_async(work, self._done, self._error)

    def _done(self, result) -> None:
        kind, imported, skipped = result
        self.outcome = kind
        if kind == "replaced":
            self.summary = "Vault restored from backup. Unlock it with that backup's master password."
        else:
            self.summary = f"Imported {imported} item(s)" + (
                f", skipped {skipped} already present." if skipped else ".")
            self._ctx.request_backup()
        self.accept()

    def _error(self, exc: Exception) -> None:
        self.go.setEnabled(True)
        self.go.setText("Restore")
        self._fail(str(exc))

    def _fail(self, message: str) -> None:
        self.status.setText(message)
        self.status.setStyleSheet(f"color:{theme.active().danger}; font-weight:600;")
