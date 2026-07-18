"""Route 2 of 2: full analysis report.

Layout
------
Top bar   : back · title · verdict badge · score ring · action buttons
Tab bar   : Overview | Headers | URLs | Attachments | Intel | Body
Each tab  : one or more Card widgets with structured content
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.services.theme_manager import ThemeManager
from frontend.widgets.kv_table import KeyValueTable
from frontend.widgets.report_widgets import (
    Card,
    Chip,
    ScoreRing,
    auth_chip,
    body_label,
    h_separator,
    muted_label,
)
from frontend.widgets.verdict_badge import VerdictBadge
from shared.schemas import AnalysisStatus, EmailDetail


# ── Small internal helpers ────────────────────────────────────────────────────

def _scroll(widget: QWidget) -> QScrollArea:
    """Wrap a widget in a scroll area — vertical only, no horizontal bar."""
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    sa.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    sa.setWidget(widget)
    return sa


def _padded(widget: QWidget, margins=(20, 16, 20, 20)) -> QWidget:
    """Wrap widget with outer padding for use inside a scroll area."""
    outer = QWidget()
    outer.setStyleSheet("background: transparent;")
    lyt = QVBoxLayout(outer)
    lyt.setContentsMargins(*margins)
    lyt.setSpacing(12)
    lyt.addWidget(widget)
    lyt.addStretch(1)
    return outer


def _secondary(text: str, tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("secondary", "true")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def _danger(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("danger", "true")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


# ── ReportPage ────────────────────────────────────────────────────────────────

class ReportPage(QWidget):
    backRequested    = Signal()
    downloadRequested = Signal(int)
    deleteRequested   = Signal(int)
    reEnrichRequested = Signal(int)

    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme_manager
        self._analysis_id: int | None = None
        self._current_status: AnalysisStatus | None = None

        # ── Top bar ───────────────────────────────────────────────────────
        back_btn = _secondary("← Back")
        back_btn.clicked.connect(self.backRequested)

        self._title_label = QLabel("—")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setWeight(QFont.Weight.DemiBold)
        self._title_label.setFont(title_font)
        self._title_label.setStyleSheet("color:#1E3A5F; background:transparent;")
        self._title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._title_label.setWordWrap(False)

        self._verdict_badge = VerdictBadge(None, theme_manager, self)

        self._score_ring = ScoreRing(self)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(
            "color: #64748B; background: transparent; font-size: 12px; padding: 0 4px;"
        )
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._re_enrich_btn = _secondary("🔄 Re-enrich")
        self._re_enrich_btn.setToolTip(
            "Re-run VirusTotal, AbuseIPDB and Shodan with the keys currently in Settings."
        )
        self._re_enrich_btn.clicked.connect(self._emit_re_enrich)

        self._download_btn = QPushButton("↓ Export DOCX")
        self._download_btn.clicked.connect(self._emit_download)
        self._download_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        self._delete_btn = _danger("🗑 Delete")
        self._delete_btn.clicked.connect(self._emit_delete)

        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(20, 14, 20, 0)
        top_bar.setSpacing(10)
        top_bar.addWidget(back_btn)
        top_bar.addWidget(self._title_label, 1)
        top_bar.addWidget(self._status_label)
        top_bar.addWidget(self._verdict_badge)
        top_bar.addWidget(self._score_ring)
        top_bar.addWidget(self._re_enrich_btn)
        top_bar.addWidget(self._download_btn)
        top_bar.addWidget(self._delete_btn)

        # ── Tab widget ────────────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        # Build one content widget per tab
        self._tab_overview    = QWidget(); self._tab_overview.setStyleSheet("background:transparent;")
        self._tab_headers     = QWidget(); self._tab_headers.setStyleSheet("background:transparent;")
        self._tab_urls        = QWidget(); self._tab_urls.setStyleSheet("background:transparent;")
        self._tab_attachments = QWidget(); self._tab_attachments.setStyleSheet("background:transparent;")
        self._tab_intel       = QWidget(); self._tab_intel.setStyleSheet("background:transparent;")
        self._tab_body        = QWidget(); self._tab_body.setStyleSheet("background:transparent;")

        # Each tab: a VBoxLayout inside a scroll area
        self._ov_lyt  = self._tab_layout(self._tab_overview)
        self._hd_lyt  = self._tab_layout(self._tab_headers)
        self._url_lyt = self._tab_layout(self._tab_urls)
        self._att_lyt = self._tab_layout(self._tab_attachments)
        self._int_lyt = self._tab_layout(self._tab_intel)
        self._bd_lyt  = self._tab_layout(self._tab_body)

        self._tabs.addTab(_scroll(self._tab_overview),    "📋  Overview")
        self._tabs.addTab(_scroll(self._tab_headers),     "🔍  Headers")
        self._tabs.addTab(_scroll(self._tab_urls),        "🔗  URLs")
        self._tabs.addTab(_scroll(self._tab_attachments), "📎  Attachments")
        self._tabs.addTab(_scroll(self._tab_intel),       "🛡  Intel")
        self._tabs.addTab(_scroll(self._tab_body),        "📄  Body")

        # ── Loading overlay (shown when status is PENDING/RUNNING) ────────
        self._loading_widget = self._build_loading_widget()

        # ── Stacked content: index 0 = loading, index 1 = tabs ───────────
        self._content_stack = QStackedWidget()
        self._content_stack.addWidget(self._loading_widget)  # index 0
        self._content_stack.addWidget(self._tabs)            # index 1
        self._content_stack.setCurrentIndex(1)               # default: show tabs

        # ── Page layout ───────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addLayout(top_bar)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color:#E2E8F0; background:#E2E8F0; margin: 10px 0 0 0;")
        divider.setFixedHeight(1)
        root.addWidget(divider)
        root.addWidget(self._content_stack, 1)

        # ── Persistent section widgets (populated in display()) ───────────
        self._build_section_widgets()

    # ── Layout helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _tab_layout(tab: QWidget) -> QVBoxLayout:
        lyt = QVBoxLayout(tab)
        lyt.setContentsMargins(20, 16, 20, 20)
        lyt.setSpacing(12)
        lyt.addStretch(1)           # stretch at end; content inserted before it
        return lyt

    def _insert(self, layout: QVBoxLayout, widget: QWidget) -> None:
        """Insert before the trailing stretch."""
        layout.insertWidget(layout.count() - 1, widget)

    @staticmethod
    def _build_loading_widget() -> QWidget:
        """Centered loading message shown while analysis is PENDING/RUNNING."""
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        lyt = QVBoxLayout(container)
        lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        spinner_lbl = QLabel("⏳")
        spinner_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        spinner_lbl.setStyleSheet("font-size: 48px; background: transparent; border: none;")

        msg_lbl = QLabel("Analysis in progress…")
        msg_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg_font = QFont()
        msg_font.setPointSize(14)
        msg_font.setWeight(QFont.Weight.DemiBold)
        msg_lbl.setFont(msg_font)
        msg_lbl.setStyleSheet("background: transparent; border: none; color: #64748B;")

        sub_lbl = QLabel("Results will appear automatically when the analysis is complete.")
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet(
            "background: transparent; border: none; "
            "color: #94A3B8; font-size: 12px;"
        )

        lyt.addStretch(1)
        lyt.addWidget(spinner_lbl)
        lyt.addSpacing(12)
        lyt.addWidget(msg_lbl)
        lyt.addSpacing(6)
        lyt.addWidget(sub_lbl)
        lyt.addStretch(1)
        return container

    # ── Section widget construction ───────────────────────────────────────────

    def _build_section_widgets(self) -> None:
        """Create all cards and labels once; display() just populates them."""

        # ── Overview tab ──────────────────────────────────────────────────
        self._card_summary   = Card("Summary")
        self._lbl_narrative  = body_label()   # narrative story — inserted first
        self._kv_summary     = KeyValueTable()
        self._card_summary.add_widget(self._lbl_narrative)
        self._card_summary.add_widget(h_separator())
        self._card_summary.add_widget(self._kv_summary)

        self._card_auth      = Card("Authentication")
        self._auth_body      = QWidget(); self._auth_body.setStyleSheet("background:transparent;")
        self._auth_lyt       = QVBoxLayout(self._auth_body)
        self._auth_lyt.setContentsMargins(0,0,0,0); self._auth_lyt.setSpacing(4)
        self._card_auth.add_widget(self._auth_body)

        self._card_reasons   = Card("Why this verdict?")
        self._lbl_reasons    = body_label()
        self._card_reasons.add_widget(self._lbl_reasons)

        self._card_lures     = Card("Social Engineering Signals")
        self._lbl_lures      = body_label()
        self._card_lures.add_widget(self._lbl_lures)

        self._card_urgency   = Card("Urgency / Pressure Language")
        self._lbl_urgency    = body_label()
        self._card_urgency.add_widget(self._lbl_urgency)

        for w in (self._card_summary, self._card_auth,
                  self._card_reasons, self._card_lures, self._card_urgency):
            self._insert(self._ov_lyt, w)

        # ── Headers tab ───────────────────────────────────────────────────
        self._card_hdr_details = Card("Sender & Routing")
        self._kv_headers       = KeyValueTable()
        self._card_hdr_details.add_widget(self._kv_headers)

        self._card_hdr_issues  = Card("Header Issues")
        self._lbl_hdr_issues   = body_label()
        self._card_hdr_issues.add_widget(self._lbl_hdr_issues)

        self._card_mime        = Card("MIME Structure")
        self._lbl_mime         = body_label()
        self._card_mime.add_widget(self._lbl_mime)

        self._card_anchors     = Card("Anchor Text / Href Mismatches")
        self._lbl_anchors      = body_label()
        self._card_anchors.add_widget(self._lbl_anchors)

        for w in (self._card_hdr_details, self._card_hdr_issues,
                  self._card_mime, self._card_anchors):
            self._insert(self._hd_lyt, w)

        # ── URLs tab ──────────────────────────────────────────────────────
        self._card_urls      = Card("Extracted URLs")
        self._lbl_urls       = body_label()
        self._card_urls.add_widget(self._lbl_urls)

        self._card_url_intel = Card("URL Intelligence (Redirect Chains · Page Titles)")
        self._lbl_url_intel  = body_label()
        self._card_url_intel.add_widget(self._lbl_url_intel)

        for w in (self._card_urls, self._card_url_intel):
            self._insert(self._url_lyt, w)

        # ── Attachments tab ───────────────────────────────────────────────
        self._card_att_list  = Card("Attachments")
        self._lbl_att_list   = body_label()
        self._card_att_list.add_widget(self._lbl_att_list)

        self._card_att_intel = Card("Static Analysis")
        self._lbl_att_intel  = body_label()
        self._card_att_intel.add_widget(self._lbl_att_intel)

        for w in (self._card_att_list, self._card_att_intel):
            self._insert(self._att_lyt, w)

        # ── Intel tab ─────────────────────────────────────────────────────
        self._card_vt        = Card("VirusTotal — URL Scan")
        self._lbl_vt         = body_label()
        self._card_vt.add_widget(self._lbl_vt)

        self._card_abuse     = Card("AbuseIPDB — Sender IP Reputation")
        self._lbl_abuse      = body_label()
        self._card_abuse.add_widget(self._lbl_abuse)

        self._card_shodan    = Card("Shodan — IP Intelligence")
        self._lbl_shodan     = body_label()
        self._card_shodan.add_widget(self._lbl_shodan)

        for w in (self._card_vt, self._card_abuse, self._card_shodan):
            self._insert(self._int_lyt, w)

        # ── Body tab ──────────────────────────────────────────────────────
        self._card_body      = Card("Email Body Preview")
        self._lbl_body       = body_label()
        self._lbl_body.setStyleSheet(
            "font-size:13px; border:1px solid #E2E8F0; border-radius:6px;"
            "padding:12px; font-family: 'Consolas','Courier New',monospace;"
            "background: transparent;"
        )
        self._card_body.add_widget(self._lbl_body)
        self._insert(self._bd_lyt, self._card_body)

    # ── Signal emitters ───────────────────────────────────────────────────────

    def _emit_download(self) -> None:
        if self._analysis_id is not None:
            self.downloadRequested.emit(self._analysis_id)

    def _emit_delete(self) -> None:
        if self._analysis_id is not None:
            self.deleteRequested.emit(self._analysis_id)

    def _emit_re_enrich(self) -> None:
        if self._analysis_id is not None:
            self._re_enrich_btn.setEnabled(False)
            self._re_enrich_btn.setText("⏳ Running…")
            self.reEnrichRequested.emit(self._analysis_id)

    def set_re_enrich_idle(self) -> None:
        self._re_enrich_btn.setEnabled(True)
        self._re_enrich_btn.setText("🔄 Re-enrich")

    # ── Status helpers ────────────────────────────────────────────────────────

    def update_status(self, status) -> None:
        """Update the status label without a full display() call (used by polling ticks)."""
        self._current_status = status
        _status_val = status.value if hasattr(status, "value") else str(status)
        if _status_val in ("PENDING", "RUNNING"):
            dots = "." * ((getattr(self, "_dot_count", 0) % 3) + 1)
            self._dot_count = getattr(self, "_dot_count", 0) + 1
            self._status_label.setText(f"⏳ Analyzing{dots}")
            # Show loading view when no results yet
            self._content_stack.setCurrentIndex(0)
            self._re_enrich_btn.setEnabled(False)
            self._re_enrich_btn.setToolTip("Cannot re-enrich while analysis is in progress.")
        elif _status_val == "FAILED":
            self._status_label.setText("✗ Failed")
            self._content_stack.setCurrentIndex(1)
            self.set_re_enrich_idle()
        else:
            self._status_label.setText("")
            self._content_stack.setCurrentIndex(1)
            self.set_re_enrich_idle()

    # ── display() ─────────────────────────────────────────────────────────────

    def display(self, detail: EmailDetail) -> None:
        """Populate all cards with data from `detail`."""
        self._analysis_id = detail.id
        _status_val = detail.status.value if detail.status else ""

        # Update top-bar widgets
        self._title_label.setText(
            f"{detail.filename}  —  {detail.subject or '(no subject)'}"
        )
        self._verdict_badge.set_verdict(
            detail.verdict.value if detail.verdict else None
        )
        self._score_ring.set_score(
            detail.score, detail.verdict.value if detail.verdict else None
        )

        if _status_val in ("PENDING", "RUNNING"):
            # Show loading screen — no card data available yet
            self.update_status(detail.status)
            # Still set the title so users know which analysis this is
            return

        # Completed (DONE or FAILED) — show the tabs
        self._content_stack.setCurrentIndex(1)
        self._status_label.setText("✗ Failed" if _status_val == "FAILED" else "")
        # Re-enrich only makes sense on completed analyses
        self._re_enrich_btn.setEnabled(True)
        self._re_enrich_btn.setToolTip(
            "Re-run VirusTotal, AbuseIPDB and Shodan with the keys currently in Settings."
        )
        self._re_enrich_btn.setText("🔄 Re-enrich")

        from frontend.views._report_display import populate
        populate(self, detail)
