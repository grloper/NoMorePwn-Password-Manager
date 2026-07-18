"""Security dashboard: a health score plus actionable issue lists."""

from __future__ import annotations

from PySide6.QtCore import Q_ARG, QMetaObject, QRectF, Qt, Slot
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from nomorepwn import config, leakcheck, strength, vault

from . import components, icons, theme, workers
from .components import Avatar, Card
from .context import AppContext
from .util import human_age, initials


class ScoreRing(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self.setFixedSize(150, 150)

    def set_score(self, score: int) -> None:
        self._score = max(0, min(100, int(score)))
        self.update()

    def _color(self) -> str:
        if self._score >= 80:
            return "#22C55E"
        if self._score >= 55:
            return "#F59E0B"
        return "#F04438"

    def paintEvent(self, event) -> None:
        p = theme.active()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(12, 12, self.width() - 24, self.height() - 24)
        pen_bg = QPen(QColor(p.surface_alt), 12)
        pen_bg.setCapStyle(Qt.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(rect, 0, 360 * 16)
        pen_fg = QPen(QColor(self._color()), 12)
        pen_fg.setCapStyle(Qt.RoundCap)
        painter.setPen(pen_fg)
        span = int(-360 * 16 * (self._score / 100.0))
        painter.drawArc(rect, 90 * 16, span)
        painter.setPen(QColor(p.text))
        f = QFont(self.font())
        f.setPixelSize(34)
        f.setBold(True)
        painter.setFont(f)
        painter.drawText(rect, Qt.AlignCenter, str(self._score))
        painter.setPen(QColor(p.text_muted))
        f2 = QFont(self.font())
        f2.setPixelSize(11)
        painter.setFont(f2)
        painter.drawText(QRectF(rect.x(), rect.center().y() + 22, rect.width(), 20),
                         Qt.AlignHCenter, "SECURITY SCORE")
        painter.end()


class _StatCard(Card):
    def __init__(self, label: str, icon_name: str, accent: str):
        super().__init__(padding=16)
        self.body.setSpacing(6)
        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, accent, 18))
        top.addWidget(ic)
        top.addStretch(1)
        self.body.addLayout(top)
        self.value = QLabel("—")
        self.value.setStyleSheet(f"font-size:26px; font-weight:800; color:{theme.active().text};")
        self.body.addWidget(self.value)
        lab = QLabel(label)
        lab.setObjectName("Muted")
        self.body.addWidget(lab)

    def set_value(self, v) -> None:
        self.value.setText(str(v))


class AuditView(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self._ctx = ctx
        self._vault: vault.Vault | None = None
        self._report: dict | None = None
        # Bumped per scan so a stale worker can't clobber a newer one's results.
        self._scan_seq = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        self._lay = QVBoxLayout(body)
        self._lay.setContentsMargins(28, 26, 28, 26)
        self._lay.setSpacing(18)
        scroll.setWidget(body)
        root.addWidget(scroll)

        header = QHBoxLayout()
        header.addWidget(components.heading("Security dashboard", "H1"))
        header.addStretch(1)
        self.breach_btn = components.button("Scan all for breaches", "globe")
        self.breach_btn.clicked.connect(self._scan_breaches)
        header.addWidget(self.breach_btn)
        self._lay.addLayout(header)

        # Score + stats
        overview = QHBoxLayout()
        overview.setSpacing(18)
        ring_card = Card(padding=16)
        self.ring = ScoreRing()
        ring_card.body.setAlignment(Qt.AlignCenter)
        ring_card.add(self.ring)
        overview.addWidget(ring_card)

        stats_grid = QGridLayout()
        stats_grid.setSpacing(14)
        p = theme.active()
        self.card_total = _StatCard("Total items", "grid", p.primary)
        self.card_weak = _StatCard("Weak passwords", "alert-triangle", p.warning)
        self.card_reused = _StatCard("Reused passwords", "refresh", p.danger)
        self.card_mfa = _StatCard("Missing MFA", "shield", p.warning)
        self.card_stale = _StatCard("Stale (>180d)", "clock", p.text_muted)
        self.card_breached = _StatCard("Breached", "alert-circle", p.danger)
        for i, c in enumerate((self.card_total, self.card_weak, self.card_reused,
                               self.card_mfa, self.card_stale, self.card_breached)):
            stats_grid.addWidget(c, i // 3, i % 3)
        overview.addLayout(stats_grid, 1)
        self._lay.addLayout(overview)

        # Issues container
        self.issues_host = QWidget()
        self.issues_lay = QVBoxLayout(self.issues_host)
        self.issues_lay.setContentsMargins(0, 0, 0, 0)
        self.issues_lay.setSpacing(14)
        self._lay.addWidget(self.issues_host)
        self._lay.addStretch(1)

    # ------------------------------------------------------------------

    def set_vault(self, vlt: "vault.Vault | None") -> None:
        self._vault = vlt

    def refresh(self) -> None:
        if self._vault is None:
            return
        vlt = self._vault
        self.breach_btn.setEnabled(True)

        def work():
            creds = vlt.list_credentials()
            report = {
                "total": len(creds), "no_mfa": [], "stale": [], "weak": [],
                "reused": [], "strengths": {}, "breached": [],
            }
            seen: dict[str, list] = {}
            for c in creds:
                try:
                    pw = vlt.reveal_password(c["id"])
                except Exception:
                    continue
                res = strength.evaluate(pw)
                report["strengths"][c["id"]] = res
                if res.score <= 1:
                    report["weak"].append((c, res))
                if not c["mfa_enabled"]:
                    report["no_mfa"].append(c)
                if (c.get("age_days") or 0) >= config.PASSWORD_AGE_WARN_DAYS:
                    report["stale"].append(c)
                seen.setdefault(pw, []).append(c)
            for pw, group in seen.items():
                if len(group) > 1:
                    for c in group:
                        report["reused"].append(c)
            return report

        workers.run_async(work, self._render_report)

    def _score(self, r: dict) -> int:
        if r["total"] == 0:
            return 100
        score = 100
        score -= min(40, len(r["weak"]) * 10)
        score -= min(30, len(set(c["id"] for c in r["reused"])) * 8)
        score -= min(20, len(r["no_mfa"]) * 4)
        score -= min(15, len(r["stale"]) * 3)
        score -= min(50, len(r["breached"]) * 15)
        return max(0, score)

    def _render_report(self, r: dict) -> None:
        self._report = r
        self.card_total.set_value(r["total"])
        self.card_weak.set_value(len(r["weak"]))
        self.card_reused.set_value(len(set(c["id"] for c in r["reused"])))
        self.card_mfa.set_value(len(r["no_mfa"]))
        self.card_stale.set_value(len(r["stale"]))
        self.card_breached.set_value(len(r["breached"]))
        self.ring.set_score(self._score(r))
        self._render_issues(r)

    def _render_issues(self, r: dict) -> None:
        while self.issues_lay.count():
            item = self.issues_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        p = theme.active()
        any_issue = False
        if r["breached"]:
            any_issue = True
            self.issues_lay.addWidget(self._issue_card(
                "Found in known breaches", "alert-circle", p.danger,
                [(c, f"{c['_breach_count']:,} breaches") for c in r["breached"]]))
        if r["weak"]:
            any_issue = True
            self.issues_lay.addWidget(self._issue_card(
                "Weak passwords", "alert-triangle", p.warning,
                [(c, res.label) for c, res in r["weak"]]))
        if r["reused"]:
            any_issue = True
            uniq = {c["id"]: c for c in r["reused"]}.values()
            self.issues_lay.addWidget(self._issue_card(
                "Reused passwords", "refresh", p.danger,
                [(c, "used elsewhere too") for c in uniq]))
        if r["no_mfa"]:
            any_issue = True
            self.issues_lay.addWidget(self._issue_card(
                "Accounts without MFA", "shield", p.warning,
                [(c, "no two-factor") for c in r["no_mfa"]]))
        if r["stale"]:
            any_issue = True
            self.issues_lay.addWidget(self._issue_card(
                "Stale passwords", "clock", p.text_muted,
                [(c, f"changed {human_age(c.get('age_days'))}") for c in r["stale"]]))

        if not any_issue and r["total"] > 0:
            card = Card()
            row = QHBoxLayout()
            ic = QLabel()
            ic.setPixmap(icons.pixmap("shield-check", p.success, 26))
            row.addWidget(ic)
            col = QVBoxLayout()
            col.addWidget(components.heading("Everything looks healthy", "H3"))
            col.addWidget(components.muted("No weak, reused, stale, or breached passwords, and MFA is on everywhere."))
            row.addLayout(col, 1)
            card.body.addLayout(row)
            self.issues_lay.addWidget(card)
        elif r["total"] == 0:
            self.issues_lay.addWidget(components.muted("Add some items to see your security report."))

    def _issue_card(self, title: str, icon_name: str, accent: str, entries: list) -> Card:
        card = Card()
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, accent, 18))
        head.addWidget(ic)
        t = components.heading(f"{title} ({len(entries)})", "H3")
        head.addWidget(t)
        head.addStretch(1)
        card.body.addLayout(head)
        for cred, detail in entries[:25]:
            row = QHBoxLayout()
            row.setSpacing(10)
            row.addWidget(Avatar(cred["service_name"], initials(cred["service_name"]), 30))
            col = QVBoxLayout()
            col.setSpacing(0)
            n = QLabel(cred["service_name"])
            n.setStyleSheet(f"color:{theme.active().text}; font-weight:600;")
            col.addWidget(n)
            u = QLabel(cred["username"])
            u.setObjectName("Faint")
            col.addWidget(u)
            row.addLayout(col, 1)
            d = QLabel(detail)
            d.setStyleSheet(f"color:{accent}; font-weight:600; font-size:12px;")
            row.addWidget(d)
            card.body.addLayout(row)
        return card

    def _scan_breaches(self) -> None:
        if self._vault is None:
            return
        vlt = self._vault
        creds = vlt.list_credentials()
        if not creds:
            self._ctx.toast.show("Nothing to scan yet.", "info")
            return

        self.breach_btn.setEnabled(False)
        self._scan_seq += 1
        seq = self._scan_seq

        def work():
            by_password: dict[str, list[dict]] = {}
            unreadable = 0
            for c in creds:
                try:
                    by_password.setdefault(vlt.reveal_password(c["id"]), []).append(c)
                except Exception:
                    unreadable += 1

            def report(done_count: int, total: int) -> None:
                QMetaObject.invokeMethod(
                    self, "_scan_progress", Qt.QueuedConnection,
                    Q_ARG(int, done_count), Q_ARG(int, total))

            outcome = leakcheck.check_many(by_password, on_progress=report)

            breached: list[dict] = []
            for pw, count in outcome.breached.items():
                for c in by_password[pw]:
                    c = dict(c)
                    c["_breach_count"] = count
                    breached.append(c)

            # A password we couldn't check is not a password we cleared.
            failed = sum(len(by_password[pw]) for pw in outcome.failed) + unreadable
            return {"breached": breached, "failed": failed,
                    "checked": len(creds) - failed}

        def done(result):
            self._reset_scan_button()
            if seq != self._scan_seq or self._vault is None:
                return  # superseded, or the vault locked while we scanned

            if self._report is not None:
                self._report["breached"] = result["breached"]
                self._render_report(self._report)

            n = len(result["breached"])
            failed = result["failed"]
            if failed and not result["checked"]:
                self._ctx.toast.show(
                    "Couldn't reach the breach service — nothing was checked.", "error", 4000)
            elif failed:
                self._ctx.toast.show(
                    f"Checked {result['checked']} of {len(creds)} — "
                    f"{n} breached, {failed} couldn't be checked.", "error", 4600)
            else:
                self._ctx.toast.show(
                    f"{n} breached password{'s' if n != 1 else ''} found" if n
                    else "No breached passwords found",
                    "error" if n else "success", 3200)

        def err(exc):
            self._reset_scan_button()
            if seq == self._scan_seq:
                self._ctx.toast.show("Breach scan failed (offline?)", "error")

        self.breach_btn.setText("Scanning… 0/—")
        workers.run_async(work, done, err)

    def _reset_scan_button(self) -> None:
        self.breach_btn.setEnabled(True)
        self.breach_btn.setText("Scan all for breaches")

    @Slot(int, int)
    def _scan_progress(self, done_count: int, total: int) -> None:
        self.breach_btn.setText(f"Scanning… {done_count}/{total}")
