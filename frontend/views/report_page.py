"""Route 2 of 2: full analysis report — three-pane triage view.

Layout
──────────────────────────────────────────────────────────────────────────────
┌──────────────────┬────────────────────────────────┬──────────────────────┐
│  LEFT (240px)    │  CENTER (expands)               │  RIGHT (220px)       │
│                  │                                 │                      │
│  Email queue     │  Anchor-nav tab row             │  Score breakdown     │
│  • Search box    │  ─────────────────              │  Static  ░░░░░  4    │
│  • List of all   │  Content cards for the          │  Dynamic ░░░░░  2    │
│    analyses with │  selected section               │  Behav.  ░░░░░  N/A  │
│    colored dots  │                                 │  BEC     ░░░░░  N/A  │
│                  │  Clicking a queue item          │  ─────────────────── │
│  Click = update  │  updates this pane in-place     │  Identifiers         │
│  center in place │                                 │  SPF/DKIM/DMARC      │
│                  │                                 │  SHA-256 (att[0])    │
└──────────────────┴────────────────────────────────┴──────────────────────┘

Design rules respected:
  - All colors via tokens.py / QSS rules — zero inline hex.
  - Tabler outline SVGs for all icons (assets/icons/*.svg).
  - No emoji in nav or buttons.
  - Clicking a queue item calls show_analysis() — no page navigation.
  - Score bars always visible; None scores show greyed-out "N/A" bar.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.services.theme_manager import ThemeManager
from frontend.services.tokens import (
    Dark,
    Light,
    arc_color,
    score_bar_color,
    stage_colors,
    status_dot_color,
    svg_icon,
    verdict_colors,
)
from frontend.widgets.kv_table import KeyValueTable
from frontend.widgets.pipeline_stages_widget import PipelineStagesWidget
from frontend.widgets.report_widgets import (
    Card,
    Chip,
    ScoreRing,
    auth_chip,
    body_label,
    h_separator,
)
from frontend.widgets.verdict_badge import VerdictBadge
from shared.schemas import AnalysisStatus, EmailDetail, EmailSummary


# ─────────────────────────────────────────────────────────────────────────────
# Anchor-nav section definitions
# ─────────────────────────────────────────────────────────────────────────────

_SECTIONS: list[tuple[str, str, str]] = [
    # (id,           label,         icon-name)
    ("overview",    "Overview",    "layout-list"),
    ("headers",     "Headers",     "list-details"),
    ("urls",        "URLs",        "link"),
    ("attachments", "Attachments", "paperclip"),
    ("intel",       "Intel",       "shield"),
    ("body",        "Body",        "file-text"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────────────────────

def _labeled_btn(icon_name: str, label: str, tooltip: str, style: str = "secondary") -> QPushButton:
    """Icon + text labeled button. style: 'secondary', 'primary', or 'danger'."""
    btn = QPushButton(label)
    btn.setToolTip(tooltip)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setFixedHeight(32)
    btn._icon_name = icon_name
    btn._btn_style = style
    # setAutoFillBackground(False) prevents QWindowsVistaStyle from painting a
    # native button frame (dark tile) behind the SVG icon on Windows while still
    # respecting the QSS background-color rules for hover/pressed states.
    btn.setAutoFillBackground(False)
    if style == "danger":
        btn.setProperty("danger", "true")
        btn.setObjectName("DangerButton")
    elif style == "secondary":
        btn.setProperty("secondary", "true")
        btn.setObjectName("SecondaryButton")
    # primary uses default QPushButton styling
    return btn


def _apply_icon(btn: QPushButton, color: str) -> None:
    icon = svg_icon(getattr(btn, "_icon_name", ""), color, size=14)
    if icon:
        btn.setIcon(icon)


def _make_scroll_page() -> tuple[QScrollArea, QVBoxLayout]:
    """Scrollable section page with a VBoxLayout for card insertion.

    Word-wrap fix: the content widget must be constrained to the scroll area's
    viewport width so that QLabel text wraps at the pane edge rather than
    extending beyond it.  Three settings work together:
      1. setWidgetResizable(True)  — keeps the widget width equal to viewport.
      2. ScrollBarAlwaysOff        — removes the horizontal scrollbar.
      3. content.setSizePolicy(Expanding, Preferred) — lets Qt shrink it.
    Without (3) the content widget's sizeHint can exceed the viewport and Qt
    draws a horizontal scrollbar even with AlwaysOff (it just hides it while
    letting content overflow and clip).
    """
    content = QWidget()
    content.setObjectName("SectionContent")
    content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    lyt = QVBoxLayout(content)
    lyt.setContentsMargins(20, 16, 20, 20)
    lyt.setSpacing(12)
    lyt.addStretch(1)

    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    sa.setWidget(content)
    return sa, lyt


def _insert(layout: QVBoxLayout, widget: QWidget) -> None:
    layout.insertWidget(layout.count() - 1, widget)


# ─────────────────────────────────────────────────────────────────────────────
# QueueItem — one row in the left-pane email list
# ─────────────────────────────────────────────────────────────────────────────

class _QueueItem(QWidget):
    """One clickable row in the left-pane email queue."""

    clicked = Signal(int)  # analysis_id

    def __init__(self, summary: EmailSummary, is_dark: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._analysis_id = summary.id
        self._active = False
        self._is_dark = is_dark
        self._dot_color = Light.dot_pending   # safe default until update_data() runs
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("QueueItem")

        # Status dot
        self._dot = QLabel("●")
        self._dot.setFixedWidth(12)
        self._dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._dot.setStyleSheet("font-size: 9px; background: transparent; border: none;")

        # Filename / subject
        self._title_lbl = QLabel()
        self._title_lbl.setObjectName("QueueItemTitle")
        self._title_lbl.setWordWrap(False)
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)  # SECURITY
        self._title_lbl.setStyleSheet("background: transparent; border: none; font-size: 12px; font-weight: 600;")

        # Sender / score sub-line
        self._sub_lbl = QLabel()
        self._sub_lbl.setObjectName("QueueItemSub")
        self._sub_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._sub_lbl.setStyleSheet("background: transparent; border: none; font-size: 11px;")

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        text_col.addWidget(self._title_lbl)
        text_col.addWidget(self._sub_lbl)

        row = QHBoxLayout(self)
        row.setContentsMargins(10, 7, 10, 7)
        row.setSpacing(8)
        row.addWidget(self._dot)
        row.addLayout(text_col, 1)

        self.update_data(summary, is_dark)

    def update_data(self, summary: EmailSummary, is_dark: bool) -> None:
        self._is_dark = is_dark
        status_str = summary.status.value if summary.status else "PENDING"
        verdict_str = summary.verdict.value if summary.verdict else None

        self._dot_color = status_dot_color(status_str, verdict_str, is_dark)
        self._apply_dot_color()

        # Title: filename (truncated)
        fname = summary.filename or "unknown"
        if len(fname) > 28:
            fname = fname[:25] + "…"
        self._title_lbl.setText(fname)

        # Sub-line: score + sender
        score_part = f"{summary.score}" if summary.score is not None else "—"
        sender = summary.from_addr or ""
        if len(sender) > 24:
            sender = sender[:21] + "…"
        self._sub_lbl.setText(f"{score_part}  {sender}" if sender else score_part)

        self._refresh_bg()

    def _apply_dot_color(self) -> None:
        """Set the dot label color. Called from update_data() and showEvent()
        so that Qt's re-polish cycle after widget insertion cannot reset it."""
        self._dot.setStyleSheet(
            f"color: {self._dot_color}; font-size: 10px; "
            "background: transparent; border: none;"
        )

    def showEvent(self, event) -> None:
        """Re-apply dot color after the widget is fully parented and polished."""
        super().showEvent(event)
        if hasattr(self, "_dot_color"):
            self._apply_dot_color()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._refresh_bg()

    def _refresh_bg(self) -> None:
        t = Dark if self._is_dark else Light
        if self._active:
            self.setStyleSheet(
                f"QWidget#QueueItem {{ background: {t.queue_item_bg_active};"
                f"  border-left: 3px solid {t.queue_item_border_active}; border-radius: 4px; }}"
            )
        else:
            self.setStyleSheet(
                f"QWidget#QueueItem {{ background: {t.queue_item_bg}; border-left: 3px solid transparent; border-radius: 4px; }}"
                f"QWidget#QueueItem:hover {{ background: {t.queue_item_bg_hover}; }}"
            )

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._analysis_id)
        super().mousePressEvent(event)


# ─────────────────────────────────────────────────────────────────────────────
# ScoreBar — one horizontal fill bar for the right panel
# ─────────────────────────────────────────────────────────────────────────────

class _ScoreBar(QWidget):
    """Label + fill bar + monospace value for one score category."""

    _BAR_MAX = 20   # score of 20 = full bar

    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int | None = None
        self._is_dark = False
        self.setObjectName("ScoreBar")

        self._label = QLabel(label)
        self._label.setObjectName("ScoreBarLabel")
        self._label.setFixedWidth(68)
        self._label.setStyleSheet("font-size: 11px; font-weight: 600; background: transparent; border: none;")

        # Custom-drawn fill bar
        self._bar = _FillBar(self)
        self._bar.setFixedHeight(8)
        self._bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._value_lbl = QLabel("—")
        self._value_lbl.setObjectName("ScoreBarValue")
        self._value_lbl.setFixedWidth(32)
        self._value_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._value_lbl.setStyleSheet(
            "font-family: 'Consolas','Courier New',monospace; font-size: 12px; font-weight: 700; background: transparent; border: none;"
        )

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(8)
        row.addWidget(self._label)
        row.addWidget(self._bar, 1)
        row.addWidget(self._value_lbl)

    def set_score(self, score: int | None, is_dark: bool) -> None:
        self._score = score
        self._is_dark = is_dark
        t = Dark if is_dark else Light

        fill_color = score_bar_color(score, is_dark)
        pct = min((score or 0) / self._BAR_MAX, 1.0) if score is not None else 0.0
        self._bar.set_fill(pct, fill_color, t.score_bar_track)

        if score is None:
            self._value_lbl.setText("N/A")
            self._value_lbl.setStyleSheet(
                f"font-family: 'Consolas','Courier New',monospace; font-size: 12px; font-weight: 700; "
                f"color: {t.score_bar_na_text}; background: transparent; border: none;"
            )
        else:
            self._value_lbl.setText(str(score))
            self._value_lbl.setStyleSheet(
                f"font-family: 'Consolas','Courier New',monospace; font-size: 12px; font-weight: 700; "
                f"color: {fill_color}; background: transparent; border: none;"
            )


class _FillBar(QWidget):
    """Custom-painted horizontal fill bar."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pct = 0.0
        self._fill_color = Light.score_bar_na
        self._track_color = Light.score_bar_track

    def set_fill(self, pct: float, fill_color: str, track_color: str) -> None:
        self._pct = max(0.0, min(pct, 1.0))
        self._fill_color = fill_color
        self._track_color = track_color
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect()
        radius = r.height() / 2

        # Track
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._track_color))
        painter.drawRoundedRect(r, radius, radius)

        # Fill
        if self._pct > 0:
            fill_w = max(int(r.width() * self._pct), int(radius * 2))
            from PySide6.QtCore import QRect
            fill_rect = QRect(r.left(), r.top(), fill_w, r.height())
            painter.setBrush(QColor(self._fill_color))
            painter.drawRoundedRect(fill_rect, radius, radius)

        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# AnchorNavBar — slim tab row at the top of the center pane
# ─────────────────────────────────────────────────────────────────────────────

class _AnchorTab(QPushButton):
    """One tab in the center-pane anchor-nav row. Uses SVG icon + label."""

    def __init__(self, section_id: str, label: str, icon_name: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.section_id = section_id
        self._icon_name = icon_name
        self.setCheckable(True)
        self.setFlat(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("AnchorTab")
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setToolTip(label)
        # setAutoFillBackground(False) prevents QWindowsVistaStyle from painting
        # a native button chrome (dark tile) behind the SVG icon on Windows.
        self.setAutoFillBackground(False)
        self.setStyleSheet(
            "QPushButton#AnchorTab {"
            "  text-align: center;"
            "  padding: 6px 14px;"
            "  border: none;"
            "  border-bottom: 2px solid transparent;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "  border-radius: 0;"
            "}"
        )
        # Start with text; icons applied after theme is known
        self.setText(label)

    def apply_icon(self, color: str) -> None:
        icon = svg_icon(self._icon_name, color, size=14)
        if icon:
            self.setIcon(icon)
            self.setText(f"  {self.toolTip()}")


# ─────────────────────────────────────────────────────────────────────────────
# Stage reason helper
# ─────────────────────────────────────────────────────────────────────────────

def _build_stage_reasons(detail: EmailDetail) -> dict[str, str | None]:
    """Build a {stage_key: error_text} dict from a completed EmailDetail.

    Only failed/timeout rows need a reason; all others are left as None so
    PipelineStagesWidget can clear any previously shown reason text.
    """
    return {
        "static":     None,
        "enrichment": (
            detail.vt_enrichment_error
            or detail.abuse_enrichment_error
            or detail.shodan_enrichment_error
        ),
        "urlscan":    getattr(detail, "urlscan_error", None),
        "sandbox":    getattr(detail, "sandbox_error", None),
        "behavioral": None,
    }


# Phrases from sandbox_error that indicate there was simply nothing to
# detonate (no qualifying attachment and URL submission not supported).
# When these appear on a "failed" stage row we reclassify it to "skipped"
# in the UI so the analyst sees accurate status for old DB rows that were
# analyzed before the backend fix was deployed.
_NOTHING_TO_DETONATE_PHRASES = (
    "file payload required",
    "url submission not supported",
)


def _maybe_reclassify_stages(
    stages: dict[str, str],
    detail: EmailDetail,
) -> dict[str, str]:
    """Return a copy of stages with UI-level reclassifications applied.

    Currently handles one case: sandbox stage = "failed" when the sandbox_error
    indicates there was nothing to submit (no qualifying attachment, URL
    submission not supported).  Pre-fix DB rows stored "failed" for this case;
    new rows correctly store "skipped".  We reclassify at display time so old
    rows show the correct status without requiring a DB migration.
    """
    sandbox_error = (getattr(detail, "sandbox_error", None) or "").lower()
    if (
        stages.get("sandbox") == "failed"
        and any(p in sandbox_error for p in _NOTHING_TO_DETONATE_PHRASES)
    ):
        stages = dict(stages)   # shallow copy — don't mutate the original
        stages["sandbox"] = "skipped"
    return stages


# ─────────────────────────────────────────────────────────────────────────────
# ReportPage
# ─────────────────────────────────────────────────────────────────────────────

class ReportPage(QWidget):
    # Emitted when a queue item is clicked — report_controller handles the fetch
    queueItemRequested = Signal(int)      # analysis_id
    downloadRequested  = Signal(int)
    deleteRequested    = Signal(int)
    reEnrichRequested  = Signal(int)
    # Emitted by the ← Back button and on delete — main_window switches to upload page
    backRequested      = Signal()

    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme_manager
        self._analysis_id: int | None = None
        self._current_status: AnalysisStatus | None = None
        self._current_section: str = "overview"
        self._queue_items: dict[int, _QueueItem] = {}   # analysis_id → widget

        is_dark = theme_manager.current == "dark"

        # ── Top bar ───────────────────────────────────────────────────────
        self._title_label = QLabel("—")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setWeight(QFont.Weight.DemiBold)
        self._title_label.setFont(title_font)
        self._title_label.setTextFormat(Qt.TextFormat.PlainText)  # SECURITY
        self._title_label.setObjectName("ReportTitle")
        self._title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._title_label.setWordWrap(False)

        self._status_label = QLabel("")
        self._status_label.setObjectName("ReportStatus")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._re_enrich_btn = _labeled_btn("refresh", "Re-enrich", "Re-run VirusTotal, AbuseIPDB, Shodan", "secondary")
        self._re_enrich_btn.clicked.connect(self._emit_re_enrich)

        # Inline error label shown when re-enrich is rejected (e.g. HTTP 409)
        self._re_enrich_error_lbl = QLabel("")
        self._re_enrich_error_lbl.setObjectName("ReEnrichError")
        self._re_enrich_error_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._re_enrich_error_lbl.setWordWrap(False)
        self._re_enrich_error_lbl.setStyleSheet(
            "font-size: 11px; background: transparent; border: none;"
        )
        self._re_enrich_error_lbl.hide()

        self._download_btn = _labeled_btn("download", "Export DOCX", "Export DOCX report", "primary")
        self._download_btn.clicked.connect(self._emit_download)

        self._delete_btn = _labeled_btn("trash", "Delete", "Delete this analysis", "danger")
        self._delete_btn.clicked.connect(self._emit_delete)

        # "Back" — returns to upload/queue page
        self._back_btn = QPushButton("Back")
        self._back_btn.setToolTip("Return to upload page")
        self._back_btn.setObjectName("BackButton")
        self._back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._back_btn.setFixedHeight(32)
        self._back_btn.setAutoFillBackground(False)
        self._back_btn._icon_name = "arrow-left"
        self._back_btn.clicked.connect(self.backRequested)

        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(16, 10, 16, 0)
        top_bar.setSpacing(8)
        top_bar.addWidget(self._back_btn)
        top_bar.addSpacing(4)
        top_bar.addWidget(self._title_label, 1)
        top_bar.addWidget(self._status_label)
        top_bar.addSpacing(4)
        top_bar.addWidget(self._re_enrich_error_lbl)
        top_bar.addWidget(self._re_enrich_btn)
        top_bar.addWidget(self._download_btn)
        top_bar.addWidget(self._delete_btn)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setObjectName("TopDivider")
        divider.setFixedHeight(1)

        # ── LEFT PANE — email queue ───────────────────────────────────────
        self._left_panel = QWidget()
        self._left_panel.setObjectName("QueuePanel")
        left_lyt = QVBoxLayout(self._left_panel)
        left_lyt.setContentsMargins(0, 0, 0, 0)
        left_lyt.setSpacing(0)

        # Search box — contained inside a padding wrapper so borders aren't clipped
        search_wrapper = QWidget()
        search_wrapper.setObjectName("QueueSearchWrapper")
        search_wrapper.setStyleSheet("background: transparent;")
        search_w_lyt = QHBoxLayout(search_wrapper)
        search_w_lyt.setContentsMargins(10, 8, 10, 8)
        search_w_lyt.setSpacing(0)

        self._queue_search = QLineEdit()
        self._queue_search.setPlaceholderText("Search…")
        self._queue_search.setObjectName("QueueSearch")
        self._queue_search.setClearButtonEnabled(True)
        self._queue_search.setFixedHeight(28)
        self._queue_search.textChanged.connect(self._filter_queue)
        search_w_lyt.addWidget(self._queue_search)
        left_lyt.addWidget(search_wrapper)

        sep_line = QFrame()
        sep_line.setFrameShape(QFrame.Shape.HLine)
        sep_line.setObjectName("QueueDivider")
        sep_line.setFixedHeight(1)
        left_lyt.addWidget(sep_line)

        # Scrollable list of queue items
        self._queue_scroll_content = QWidget()
        self._queue_scroll_content.setObjectName("QueueScrollContent")
        self._queue_list_lyt = QVBoxLayout(self._queue_scroll_content)
        self._queue_list_lyt.setContentsMargins(8, 6, 8, 6)
        self._queue_list_lyt.setSpacing(2)
        self._queue_list_lyt.addStretch(1)

        queue_scroll = QScrollArea()
        queue_scroll.setWidgetResizable(True)
        queue_scroll.setFrameShape(QFrame.Shape.NoFrame)
        queue_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        queue_scroll.setWidget(self._queue_scroll_content)
        left_lyt.addWidget(queue_scroll, 1)

        # ── CENTER PANE ───────────────────────────────────────────────────
        self._center_widget = QWidget()
        center_outer = QVBoxLayout(self._center_widget)
        center_outer.setContentsMargins(0, 0, 0, 0)
        center_outer.setSpacing(0)

        # Anchor-nav tab row
        self._anchor_bar = QWidget()
        self._anchor_bar.setObjectName("AnchorBar")
        self._anchor_bar.setFixedHeight(40)
        anchor_row = QHBoxLayout(self._anchor_bar)
        anchor_row.setContentsMargins(12, 0, 12, 0)
        anchor_row.setSpacing(0)

        self._anchor_tabs: dict[str, _AnchorTab] = {}
        for sid, label, icon_name in _SECTIONS:
            tab = _AnchorTab(sid, label, icon_name)
            tab.clicked.connect(lambda checked, s=sid: self._navigate_to(s))
            anchor_row.addWidget(tab)
            self._anchor_tabs[sid] = tab
        anchor_row.addStretch(1)

        center_outer.addWidget(self._anchor_bar)

        anchor_div = QFrame()
        anchor_div.setObjectName("AnchorDivider")
        anchor_div.setFrameShape(QFrame.Shape.HLine)
        anchor_div.setFixedHeight(1)
        center_outer.addWidget(anchor_div)

        # Stacked: loading (0) / section pages (1)
        self._center_stack = QStackedWidget()
        self._loading_widget = self._build_loading_widget()
        self._center_stack.addWidget(self._loading_widget)

        self._section_stack = QStackedWidget()
        self._center_stack.addWidget(self._section_stack)

        center_outer.addWidget(self._center_stack, 1)

        # Section pages
        self._section_pages: dict[str, tuple[QScrollArea, QVBoxLayout]] = {}
        for sid, _label, _icon in _SECTIONS:
            scroll, lyt = _make_scroll_page()
            self._section_pages[sid] = (scroll, lyt)
            self._section_stack.addWidget(scroll)

        # ── RIGHT PANE — score bars + identifiers ─────────────────────────
        self._right_panel = QWidget()
        self._right_panel.setObjectName("MetaPanel")
        right_lyt = QVBoxLayout(self._right_panel)
        right_lyt.setContentsMargins(12, 14, 12, 14)
        right_lyt.setSpacing(12)

        # Score ring + verdict badge at the very top of right panel
        self._score_ring = ScoreRing(self)
        self._verdict_badge = VerdictBadge(None, theme_manager, self)
        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(8)
        verdict_row.addWidget(self._score_ring)
        verdict_row.addWidget(self._verdict_badge, 1, Qt.AlignmentFlag.AlignVCenter)
        right_lyt.addLayout(verdict_row)

        # Score breakdown section header
        scores_hdr = QLabel("Score Breakdown")
        scores_hdr.setObjectName("MetaSectionHeader")
        right_lyt.addWidget(scores_hdr)

        # Four score bars
        self._bar_static   = _ScoreBar("Static")
        self._bar_dynamic  = _ScoreBar("Dynamic")
        self._bar_behav    = _ScoreBar("Behavioral")
        self._bar_bec      = _ScoreBar("BEC")

        for bar in (self._bar_static, self._bar_dynamic, self._bar_behav, self._bar_bec):
            right_lyt.addWidget(bar)

        # Divider
        bar_div = QFrame()
        bar_div.setFrameShape(QFrame.Shape.HLine)
        bar_div.setObjectName("MetaDivider")
        bar_div.setFixedHeight(1)
        right_lyt.addWidget(bar_div)

        # Identifiers section header
        ids_hdr = QLabel("Identifiers")
        ids_hdr.setObjectName("MetaSectionHeader")
        right_lyt.addWidget(ids_hdr)

        # SPF / DKIM / DMARC auth chips inline
        self._auth_row = QWidget()
        self._auth_row.setStyleSheet("background: transparent;")
        auth_hl = QHBoxLayout(self._auth_row)
        auth_hl.setContentsMargins(0, 0, 0, 0)
        auth_hl.setSpacing(6)
        self._chip_spf   = Chip("SPF ?",   "unknown")
        self._chip_dkim  = Chip("DKIM ?",  "unknown")
        self._chip_dmarc = Chip("DMARC ?", "unknown")
        auth_hl.addWidget(self._chip_spf)
        auth_hl.addWidget(self._chip_dkim)
        auth_hl.addWidget(self._chip_dmarc)
        auth_hl.addStretch()
        right_lyt.addWidget(self._auth_row)

        # SHA-256 of first attachment
        sha_hdr = QLabel("SHA-256 (att. 0)")
        sha_hdr.setObjectName("MetaSubHeader")
        sha_hdr.setStyleSheet("font-size: 10px; font-weight: 600; background: transparent; border: none;")
        self._sha256_lbl = QLabel("—")
        self._sha256_lbl.setObjectName("SHA256Value")
        self._sha256_lbl.setWordWrap(True)
        self._sha256_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._sha256_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._sha256_lbl.setStyleSheet(
            "font-family: 'Consolas','Courier New',monospace; font-size: 10px; "
            "background: transparent; border: none;"
        )
        right_lyt.addWidget(sha_hdr)
        right_lyt.addWidget(self._sha256_lbl)

        right_lyt.addStretch(1)

        # ── Three-pane splitter ───────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self._left_panel)
        splitter.addWidget(self._center_widget)
        splitter.addWidget(self._right_panel)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        splitter.setSizes([240, 9999, 220])

        # ── Page root ─────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addLayout(top_bar)
        root.addWidget(divider)
        root.addWidget(splitter, 1)

        # ── Persistent section widgets ────────────────────────────────────
        self._build_section_widgets()

        # ── Apply initial icons and navigate to overview ──────────────────
        self._refresh_icons()
        self._navigate_to("overview")

        # Refresh icons on theme change
        theme_manager.themeChanged.connect(lambda _: self._refresh_icons())

    # ─────────────────────────────────────────────────────────────────────
    # Icon refresh
    # ─────────────────────────────────────────────────────────────────────

    def _refresh_icons(self) -> None:
        is_dark = self._theme.current == "dark"
        t = Dark if is_dark else Light
        muted = t.text_muted
        primary = t.primary
        white = "#FFFFFF"

        for sid, tab in self._anchor_tabs.items():
            color = primary if tab.isChecked() else muted
            tab.apply_icon(color)

        # Back button — secondary color
        _apply_icon(self._back_btn, muted)

        # Re-enrich — secondary (muted icon on ghost button)
        _apply_icon(self._re_enrich_btn, muted)

        # Export DOCX — primary (white icon on blue button)
        _apply_icon(self._download_btn, white)

        # Delete — danger color
        _apply_icon(self._delete_btn, t.phishing_fg)

    # ─────────────────────────────────────────────────────────────────────
    # Queue management — called by report_controller / analyses_controller
    # ─────────────────────────────────────────────────────────────────────

    def populate_queue(self, summaries: list[EmailSummary]) -> None:
        """Replace the full queue contents with the given list of summaries."""
        is_dark = self._theme.current == "dark"

        # Remove all existing items (keep stretch at end)
        while self._queue_list_lyt.count() > 1:
            item = self._queue_list_lyt.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._queue_items.clear()

        for summary in summaries:
            qi = _QueueItem(summary, is_dark)
            qi.clicked.connect(self._on_queue_item_clicked)
            # Insert before the trailing stretch
            self._queue_list_lyt.insertWidget(
                self._queue_list_lyt.count() - 1, qi
            )
            self._queue_items[summary.id] = qi

        # Re-apply active state
        if self._analysis_id is not None and self._analysis_id in self._queue_items:
            self._queue_items[self._analysis_id].set_active(True)

    def update_queue_item(self, summary: EmailSummary) -> None:
        """Update a single queue item (e.g. after polling completes)."""
        is_dark = self._theme.current == "dark"
        if summary.id in self._queue_items:
            self._queue_items[summary.id].update_data(summary, is_dark)

    def _on_queue_item_clicked(self, analysis_id: int) -> None:
        # Deactivate previous
        if self._analysis_id is not None and self._analysis_id in self._queue_items:
            self._queue_items[self._analysis_id].set_active(False)
        self.queueItemRequested.emit(analysis_id)

    def _filter_queue(self, text: str) -> None:
        """Show/hide queue items based on search text."""
        text_lower = text.lower()
        for qi in self._queue_items.values():
            title = qi._title_lbl.text().lower()
            sub = qi._sub_lbl.text().lower()
            qi.setVisible(not text_lower or text_lower in title or text_lower in sub)

    # ─────────────────────────────────────────────────────────────────────
    # Anchor-nav
    # ─────────────────────────────────────────────────────────────────────

    def _navigate_to(self, section_id: str) -> None:
        self._current_section = section_id
        scroll, _ = self._section_pages[section_id]
        self._section_stack.setCurrentWidget(scroll)
        for sid, tab in self._anchor_tabs.items():
            tab.setChecked(sid == section_id)
        self._refresh_icons()

    # ─────────────────────────────────────────────────────────────────────
    # Loading widget
    # ─────────────────────────────────────────────────────────────────────

    def _build_loading_widget(self) -> QWidget:
        """Build the center loading view with a PipelineStagesWidget.

        Shown while the analysis is PENDING / RUNNING.  The pipeline rows
        update in-place on every poll tick — this widget is never rebuilt.

        NULL pipeline_stages handling:
          - If pipeline_stages is NULL (pre-Phase-B row or not yet written)
            and the analysis is still running, we show "Queued" text only.
          - The PipelineStagesWidget is hidden until real stage data arrives.
        """
        is_dark = self._theme.current == "dark"

        container = QWidget()
        container.setObjectName("LoadingView")
        lyt = QVBoxLayout(container)
        lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Heading
        msg_lbl = QLabel("Analysis in progress")
        msg_lbl.setObjectName("LoadingTitle")
        msg_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg_font = QFont()
        msg_font.setPointSize(14)
        msg_font.setWeight(QFont.Weight.DemiBold)
        msg_lbl.setFont(msg_font)
        msg_lbl.setStyleSheet("background: transparent; border: none;")

        # Queued fallback label — visible only when pipeline_stages is NULL
        self._queued_lbl = QLabel("Queued — waiting for pipeline to start")
        self._queued_lbl.setObjectName("LoadingSubtitle")
        self._queued_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._queued_lbl.setWordWrap(True)
        self._queued_lbl.setStyleSheet(
            "background: transparent; border: none; font-size: 12px;"
        )

        # Pipeline stages widget (5 rows) — hidden until stage data arrives
        self._pipeline_widget = PipelineStagesWidget(is_dark=is_dark, compact=False)
        self._pipeline_widget.setFixedWidth(420)
        self._pipeline_widget.hide()

        sub_lbl = QLabel("Results appear automatically when the analysis completes.")
        sub_lbl.setObjectName("LoadingSubHint")
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet(
            "background: transparent; border: none; font-size: 11px;"
        )

        lyt.addStretch(1)
        lyt.addWidget(msg_lbl)
        lyt.addSpacing(12)
        lyt.addWidget(self._queued_lbl, 0, Qt.AlignmentFlag.AlignCenter)
        lyt.addWidget(self._pipeline_widget, 0, Qt.AlignmentFlag.AlignCenter)
        lyt.addSpacing(12)
        lyt.addWidget(sub_lbl)
        lyt.addStretch(1)
        return container

    def update_pipeline_stages(self, detail: EmailDetail) -> None:
        """Update the loading view's stage rows from the latest poll result.

        Called by the report_controller on every PENDING/RUNNING poll tick.
        Updates in-place — the widget is never rebuilt between ticks.

        NULL pipeline_stages:
          - If None (pre-Phase-B row or not yet written), shows the Queued
            label and hides the stage rows.
          - If non-None, hides the Queued label and shows/updates the rows.
        """
        is_dark = self._theme.current == "dark"
        stages = detail.pipeline_stages

        if stages is None:
            # No stage data yet — show "Queued" fallback
            self._queued_lbl.show()
            self._pipeline_widget.hide()
        else:
            # Build per-stage failure reasons from the available error fields so
            # failed/timeout rows can show a short explanation to the analyst.
            reasons = _build_stage_reasons(detail)
            # Reclassify "nothing to detonate" sandbox failures as skipped so
            # pre-fix DB rows show the correct status without a DB migration.
            stages = _maybe_reclassify_stages(stages, detail)
            # Real stage data — show the rows, hide the fallback label
            self._queued_lbl.hide()
            self._pipeline_widget.set_stages(stages, is_dark=is_dark, reasons=reasons)
            self._pipeline_widget.show()

    # ─────────────────────────────────────────────────────────────────────
    # Section widget construction
    # ─────────────────────────────────────────────────────────────────────

    def _build_section_widgets(self) -> None:
        """Create all cards and labels once. display() populates content."""

        ov_scroll, ov_lyt = self._section_pages["overview"]
        hd_scroll, hd_lyt = self._section_pages["headers"]
        url_scroll, url_lyt = self._section_pages["urls"]
        att_scroll, att_lyt = self._section_pages["attachments"]
        int_scroll, int_lyt = self._section_pages["intel"]
        bd_scroll, bd_lyt = self._section_pages["body"]

        # Overview
        self._card_summary   = Card("Summary")
        self._lbl_narrative  = body_label()
        self._kv_summary     = KeyValueTable()
        self._card_summary.add_widget(self._lbl_narrative)
        self._card_summary.add_widget(h_separator())
        self._card_summary.add_widget(self._kv_summary)

        self._card_auth      = Card("Authentication")
        self._auth_body      = QWidget()
        self._auth_body.setStyleSheet("background:transparent;")
        self._auth_lyt       = QVBoxLayout(self._auth_body)
        self._auth_lyt.setContentsMargins(0, 0, 0, 0)
        self._auth_lyt.setSpacing(4)
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

        self._card_behavioral = Card("Behavioral Analysis")
        self._lbl_behavioral  = body_label()
        self._card_behavioral.add_widget(self._lbl_behavioral)

        self._card_bec = Card("BEC Detection")
        self._lbl_bec  = body_label()
        self._card_bec.add_widget(self._lbl_bec)

        # Phase B: compact pipeline card — shown only for completed analyses
        # with non-NULL pipeline_stages.  Hidden by default; display() shows it.
        self._card_pipeline = Card("Analysis Pipeline")
        is_dark = self._theme.current == "dark"
        self._pipeline_card_widget = PipelineStagesWidget(is_dark=is_dark, compact=True)
        self._card_pipeline.add_widget(self._pipeline_card_widget)
        self._card_pipeline.hide()

        for w in (self._card_summary, self._card_auth, self._card_reasons,
                  self._card_lures, self._card_urgency, self._card_behavioral,
                  self._card_bec, self._card_pipeline):
            _insert(ov_lyt, w)

        # Headers
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
            _insert(hd_lyt, w)

        # URLs
        self._card_urls      = Card("Extracted URLs")
        self._lbl_urls       = body_label()
        self._card_urls.add_widget(self._lbl_urls)

        self._card_url_intel = Card("URL Intelligence")
        self._lbl_url_intel  = body_label()
        self._card_url_intel.add_widget(self._lbl_url_intel)

        for w in (self._card_urls, self._card_url_intel):
            _insert(url_lyt, w)

        # Attachments
        self._card_att_list  = Card("Attachments")
        self._lbl_att_list   = body_label()
        self._card_att_list.add_widget(self._lbl_att_list)

        self._card_att_intel = Card("Static Analysis")
        self._lbl_att_intel  = body_label()
        self._card_att_intel.add_widget(self._lbl_att_intel)

        for w in (self._card_att_list, self._card_att_intel):
            _insert(att_lyt, w)

        # Intel
        self._card_vt        = Card("VirusTotal — URL Scan")
        self._lbl_vt         = body_label()
        self._card_vt.add_widget(self._lbl_vt)

        self._card_abuse     = Card("AbuseIPDB — Sender IP")
        self._lbl_abuse      = body_label()
        self._card_abuse.add_widget(self._lbl_abuse)

        self._card_shodan    = Card("Shodan — IP Intelligence")
        self._lbl_shodan     = body_label()
        self._card_shodan.add_widget(self._lbl_shodan)

        for w in (self._card_vt, self._card_abuse, self._card_shodan):
            _insert(int_lyt, w)

        # Body
        self._card_body = Card("Email Body Preview")
        self._lbl_body  = body_label()
        self._lbl_body.setObjectName("BodyPreview")
        self._lbl_body.setStyleSheet(
            "font-size:13px; border-radius:6px; padding:12px;"
            "font-family: 'Consolas','Courier New',monospace; background: transparent;"
        )
        self._card_body.add_widget(self._lbl_body)
        _insert(bd_lyt, self._card_body)

    # ─────────────────────────────────────────────────────────────────────
    # Signal emitters
    # ─────────────────────────────────────────────────────────────────────

    def _emit_download(self) -> None:
        if self._analysis_id is not None:
            self.downloadRequested.emit(self._analysis_id)

    def _emit_delete(self) -> None:
        if self._analysis_id is not None:
            self.deleteRequested.emit(self._analysis_id)

    def _emit_re_enrich(self) -> None:
        if self._analysis_id is not None:
            self._re_enrich_btn.setEnabled(False)
            self.reEnrichRequested.emit(self._analysis_id)

    def set_re_enrich_idle(self) -> None:
        """Re-enable the re-enrich button (called after success or error).

        Only re-enables when the current analysis is DONE.  If the status
        changed to something else during the request, leave it disabled.
        """
        if self._current_status == AnalysisStatus.DONE:
            self._re_enrich_btn.setEnabled(True)

    def show_re_enrich_error(self, message: str) -> None:
        """Show an inline error label under the re-enrich button."""
        self._re_enrich_error_lbl.setText(message)
        self._re_enrich_error_lbl.show()

    # ─────────────────────────────────────────────────────────────────────
    # Status helpers
    # ─────────────────────────────────────────────────────────────────────

    def update_status(self, status) -> None:
        _val = status.value if hasattr(status, "value") else str(status)
        if _val in ("PENDING", "RUNNING"):
            dots = "." * ((getattr(self, "_dot_count", 0) % 3) + 1)
            self._dot_count = getattr(self, "_dot_count", 0) + 1
            self._status_label.setText(f"Analyzing{dots}")
            self._center_stack.setCurrentIndex(0)
            self._re_enrich_btn.setEnabled(False)
            self._re_enrich_btn.setToolTip("Re-enrich is only available once the analysis is complete")
        elif _val == "FAILED":
            self._status_label.setText("Failed")
            self._center_stack.setCurrentIndex(1)
            self._re_enrich_btn.setEnabled(False)
            self._re_enrich_btn.setToolTip("Re-enrich is not available for failed analyses")
        else:
            self._status_label.setText("")
            self._center_stack.setCurrentIndex(1)
            self._re_enrich_btn.setEnabled(True)
            self._re_enrich_btn.setToolTip("Re-run VirusTotal, AbuseIPDB, Shodan")

    # ─────────────────────────────────────────────────────────────────────
    # display() — main entry point called by report_controller
    # ─────────────────────────────────────────────────────────────────────

    def display(self, detail: EmailDetail) -> None:
        """Populate all cards and right-panel with data from `detail`."""
        self._analysis_id = detail.id
        self._current_status = detail.status
        _status_val = detail.status.value if detail.status else ""
        is_dark = self._theme.current == "dark"

        # Clear any stale inline error from a previous re-enrich attempt
        self._re_enrich_error_lbl.hide()
        self._re_enrich_error_lbl.setText("")

        # Mark active queue item
        for aid, qi in self._queue_items.items():
            qi.set_active(aid == detail.id)

        # Top bar title
        self._title_label.setText(
            f"{detail.filename}  —  {detail.subject or '(no subject)'}"
        )

        # Right panel — verdict + score ring
        self._verdict_badge.set_verdict(
            detail.verdict.value if detail.verdict else None
        )
        self._score_ring.set_score(
            detail.score, detail.verdict.value if detail.verdict else None
        )

        # Right panel — score bars (always shown; None = greyed N/A)
        self._bar_static.set_score(detail.static_score, is_dark)
        self._bar_dynamic.set_score(detail.dynamic_score, is_dark)
        self._bar_behav.set_score(detail.behavioral_score, is_dark)
        self._bar_bec.set_score(detail.bec_score, is_dark)

        # Right panel — auth chips
        h = detail.header_info
        def _preset(v: str) -> str:
            return v if v in ("pass", "fail", "softfail") else "unknown"
        self._chip_spf.setText(f"SPF {h.auth.spf.upper()}")
        self._chip_spf._preset = _preset(h.auth.spf)
        self._chip_spf._apply_style()
        self._chip_dkim.setText(f"DKIM {h.auth.dkim.upper()}")
        self._chip_dkim._preset = _preset(h.auth.dkim)
        self._chip_dkim._apply_style()
        self._chip_dmarc.setText(f"DMARC {h.auth.dmarc.upper()}")
        self._chip_dmarc._preset = _preset(h.auth.dmarc)
        self._chip_dmarc._apply_style()

        # Right panel — SHA-256
        if detail.attachments:
            sha = detail.attachments[0].sha256 or "—"
            # Show first 16 + "…" + last 8 for readability
            self._sha256_lbl.setText(
                f"{sha[:16]}…{sha[-8:]}" if len(sha) > 26 else sha
            )
        else:
            self._sha256_lbl.setText("no attachments")

        if _status_val in ("PENDING", "RUNNING"):
            self.update_status(detail.status)
            # Update the loading view stage rows from the latest poll data
            self.update_pipeline_stages(detail)
            return

        # Show section content — update_status handles center stack + re-enrich state
        self.update_status(detail.status)

        # Phase B: populate or hide the compact pipeline card on Overview tab.
        # Show it only when pipeline_stages is non-NULL — NULL means pre-Phase-B
        # data where no stage info was recorded, so the card would be meaningless.
        is_dark = self._theme.current == "dark"
        stages = detail.pipeline_stages
        if stages is not None:
            reasons = _build_stage_reasons(detail)
            stages = _maybe_reclassify_stages(stages, detail)
            self._pipeline_card_widget.set_stages(stages, is_dark=is_dark, reasons=reasons)
            self._card_pipeline.show()
        else:
            self._card_pipeline.hide()

        from frontend.views._report_display import populate
        populate(self, detail)
