"""Route 2 of 2: full analysis report, mirroring the sections of the
original CLI's console/docx output (summary, email details, header/sender
analysis, indicators, threat intel enrichment, reasons, body preview).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from frontend.services.theme_manager import ThemeManager
from frontend.widgets.kv_table import KeyValueTable
from frontend.widgets.verdict_badge import VerdictBadge
from shared.schemas import EmailDetail


class ReportPage(QWidget):
    backRequested = Signal()
    downloadRequested = Signal(int)
    deleteRequested = Signal(int)

    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._analysis_id: int | None = None

        back_button = QPushButton("← Back to Upload")
        back_button.clicked.connect(self.backRequested)

        self._title_label = QLabel("")
        self._title_label.setStyleSheet("font-size: 16px; font-weight: 600;")

        self._verdict_badge = VerdictBadge(None, theme_manager, self)
        self._score_label = QLabel("")

        download_button = QPushButton("Export DOCX")
        download_button.clicked.connect(self._emit_download)

        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self._emit_delete)

        header_row = QHBoxLayout()
        header_row.addWidget(back_button)
        header_row.addStretch(1)
        header_row.addWidget(self._verdict_badge)
        header_row.addWidget(self._score_label)
        header_row.addWidget(download_button)
        header_row.addWidget(delete_button)

        self._email_details = KeyValueTable(self)
        self._header_analysis = KeyValueTable(self)
        self._issues_label = self._make_wrapping_label()
        self._urls_label = self._make_wrapping_label()
        self._attachments_label = self._make_wrapping_label()
        self._enrichment_label = self._make_wrapping_label()
        self._urgency_label = self._make_wrapping_label()
        self._reasons_label = self._make_wrapping_label()
        self._body_preview_label = self._make_wrapping_label()

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.addWidget(self._section("Summary", self._title_label))
        content_layout.addWidget(self._section("Email Details", self._email_details))
        content_layout.addWidget(self._section("Header & Sender Analysis", self._header_analysis))
        content_layout.addWidget(self._section("Header Issues", self._issues_label))
        content_layout.addWidget(self._section("URLs", self._urls_label))
        content_layout.addWidget(self._section("Attachments", self._attachments_label))
        content_layout.addWidget(self._section("Threat Intel Enrichment", self._enrichment_label))
        content_layout.addWidget(
            self._section("Urgency / Pressure Language", self._urgency_label)
        )
        content_layout.addWidget(self._section("Reasons for Verdict", self._reasons_label))
        content_layout.addWidget(self._section("Body Preview", self._body_preview_label))
        content_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)

        layout = QVBoxLayout(self)
        layout.addLayout(header_row)
        layout.addWidget(scroll, 1)

    @staticmethod
    def _make_wrapping_label() -> QLabel:
        label = QLabel("")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label

    @staticmethod
    def _section(title: str, widget: QWidget) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        label = QLabel(title)
        label.setStyleSheet("font-weight: 600; margin-top: 6px;")
        layout.addWidget(label)
        layout.addWidget(widget)
        return container

    def _emit_download(self) -> None:
        if self._analysis_id is not None:
            self.downloadRequested.emit(self._analysis_id)

    def _emit_delete(self) -> None:
        if self._analysis_id is not None:
            self.deleteRequested.emit(self._analysis_id)

    def display(self, detail: EmailDetail) -> None:
        self._analysis_id = detail.id
        self._title_label.setText(f"{detail.filename} — {detail.subject or '(no subject)'}")
        self._verdict_badge.set_verdict(detail.verdict.value if detail.verdict else None)
        self._score_label.setText(f"Score: {detail.score if detail.score is not None else 'N/A'}")

        self._email_details.set_rows(
            [
                ("From", detail.from_addr),
                ("Subject", detail.subject),
                ("Message-ID", detail.message_id),
                ("Uploaded", detail.created_at.strftime("%Y-%m-%d %H:%M:%S")),
            ]
        )

        h = detail.header_info
        header_rows = [
            ("From domain", h.from_domain),
            ("Reply-To domain", h.reply_domain),
            ("Return-Path domain", h.return_domain),
            ("Sender IP", h.sender_ip),
            (
                "SPF / DKIM / DMARC",
                f"SPF={h.auth.spf}, DKIM={h.auth.dkim}, DMARC={h.auth.dmarc}",
            ),
        ]
        if h.is_lookalike_domain:
            header_rows.append(("Lookalike domain", f"Resembles {h.lookalike_of}"))
        if h.is_punycode_domain:
            header_rows.append(("Punycode domain", "Yes (possible IDN homograph)"))
        if h.is_suspicious_sender_tld:
            header_rows.append(("Suspicious sender TLD", "Yes"))
        self._header_analysis.set_rows(header_rows)

        self._issues_label.setText("\n".join(h.issues) if h.issues else "None")

        if detail.urls:
            self._urls_label.setText("\n".join(u.url for u in detail.urls))
        else:
            self._urls_label.setText("None found")

        if detail.attachments:
            self._attachments_label.setText(
                "\n".join(
                    f"{a.filename} ({a.content_type}), sha256={a.sha256 or 'N/A'}"
                    for a in detail.attachments
                )
            )
        else:
            self._attachments_label.setText("None")

        enrichment_lines = []

        # ── VirusTotal ────────────────────────────────────────────────────
        vt_status = detail.vt_enrichment_status
        if vt_status == "no_key":
            enrichment_lines.append(
                "⚠ VirusTotal: No API key configured — go to Settings to add one."
            )
        elif vt_status == "rate_limit":
            err = detail.vt_enrichment_error or "quota exceeded"
            enrichment_lines.append(f"⚠ VirusTotal: Daily quota / rate limit reached ({err})")
        elif vt_status == "error":
            err = detail.vt_enrichment_error or "unknown error"
            enrichment_lines.append(f"✗ VirusTotal: API error — {err}")
        elif vt_status in ("ok", "no_data", None):
            # Show per-URL results if any engines flagged anything
            vt_hits = [
                u for u in detail.urls
                if (u.vt_malicious or 0) > 0 or (u.vt_suspicious or 0) > 0
            ]
            if vt_hits:
                for u in vt_hits:
                    enrichment_lines.append(
                        f"VT: {u.url}\n"
                        f"    malicious={u.vt_malicious}, "
                        f"suspicious={u.vt_suspicious}, "
                        f"harmless={u.vt_harmless}"
                    )
            elif detail.urls and vt_status == "ok":
                enrichment_lines.append(
                    "✓ VirusTotal: All URLs checked — no malicious detections."
                )
            elif detail.urls and vt_status == "no_data":
                enrichment_lines.append(
                    "ℹ VirusTotal: Checked but no results returned (URLs may be unrated)."
                )
            elif not detail.urls:
                enrichment_lines.append("ℹ VirusTotal: No URLs in this email to scan.")
            else:
                # vt_status is None — analysis was run before this feature
                enrichment_lines.append(
                    "ℹ VirusTotal: Status unknown (analysis predates this feature)."
                )

        # ── AbuseIPDB ─────────────────────────────────────────────────────
        abuse_status = detail.abuse_enrichment_status
        sender_ip = detail.header_info.sender_ip
        if abuse_status == "no_key":
            enrichment_lines.append(
                "⚠ AbuseIPDB: No API key configured — go to Settings to add one."
            )
        elif abuse_status == "rate_limit":
            err = detail.abuse_enrichment_error or "quota exceeded"
            enrichment_lines.append(f"⚠ AbuseIPDB: Daily quota / rate limit reached ({err})")
        elif abuse_status == "error":
            err = detail.abuse_enrichment_error or "unknown error"
            enrichment_lines.append(f"✗ AbuseIPDB: API error — {err}")
        elif abuse_status == "no_data":
            enrichment_lines.append(
                "ℹ AbuseIPDB: No sender IP found in email headers — nothing to check."
            )
        elif detail.abuse_result:
            ab = detail.abuse_result
            enrichment_lines.append(
                f"AbuseIPDB: {sender_ip}\n"
                f"    score={ab.abuse_score}, reports={ab.total_reports}, "
                f"country={ab.country_code}, ISP={ab.isp}"
            )
        elif abuse_status in ("ok", None) and not detail.abuse_result:
            if sender_ip:
                enrichment_lines.append(
                    f"✓ AbuseIPDB: {sender_ip} — no abuse reports found."
                )
            elif abuse_status is None:
                enrichment_lines.append(
                    "ℹ AbuseIPDB: Status unknown (analysis predates this feature)."
                )

        self._enrichment_label.setText(
            "\n".join(enrichment_lines) if enrichment_lines else "No enrichment data available."
        )

        self._urgency_label.setText(
            ", ".join(detail.urgency_keywords_found)
            if detail.urgency_keywords_found
            else "None detected"
        )

        self._reasons_label.setText(
            "\n".join(detail.reasons)
            if detail.reasons
            else "No specific red flags triggered by current rules."
        )

        self._body_preview_label.setText(detail.body_preview or "[no body content]")
