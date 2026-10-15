"""PipelineStagesWidget — five-row live stage-status display.

Used in two contexts:

  1. Loading view (analysis PENDING / RUNNING): shown in the center pane
     while the pipeline runs.  Rows update in-place on each poll; the widget
     is never rebuilt, so scroll position is preserved.

  2. Compact read-only card on the Overview tab (analysis DONE / FAILED):
     a smaller variant (``compact=True``) used inside a Card widget to show
     the final pipeline outcome for completed analyses.

Design rules
────────────
- Five independent rows: one per stage key in order.
- Each row: Tabler SVG icon  ·  stage label  ·  status text  ·  colored dot.
- Status dot is a ``●`` QLabel whose color comes exclusively from
  ``tokens.stage_colors()`` — zero inline hex literals here.
- Running state uses a static ``›`` indicator (no animation) to respect
  the one-animation-per-app rule (Phase I already owns the progress bar).
- All six status values (pending/running/done/skipped/failed/timeout) have
  a distinct visual treatment; failed ≠ timeout ≠ pending ≠ skipped.
- Colors are re-applied in ``showEvent`` to survive Qt's re-polish cycle
  after widget insertion.
- NULL ``pipeline_stages`` is never passed here; callers handle the NULL
  guard and show "Queued" text or no widget instead.

API
───
    w = PipelineStagesWidget(is_dark=False)
    w.set_stages({"static": "done", "enrichment": "running", ...})
    # subsequent calls update in-place:
    w.set_stages({"static": "done", "enrichment": "done", ...})
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from frontend.services.tokens import Dark, Light, stage_colors, svg_icon

# ── Stage metadata ─────────────────────────────────────────────────────────────
# (stage_key, display_label, icon_name)
_STAGES: list[tuple[str, str, str]] = [
    ("static",     "Parsing & static analysis", "file-text"),
    ("enrichment", "Threat intel",               "shield"),
    ("urlscan",    "URL detonation",             "link"),
    ("sandbox",    "Sandbox detonation",         "dna"),
    ("behavioral", "Behavioral & BEC",           "id-badge"),
]

# ── Status display text ────────────────────────────────────────────────────────
_STATUS_LABEL: dict[str, str] = {
    "pending": "Pending",
    "running": "› Running",   # static triangle — no animation
    "done":    "Done",
    "skipped": "Skipped",
    "failed":  "Failed",
    "timeout": "Timed out",
}


class _StageRow(QWidget):
    """One row: icon · label · (spacer) · status text · dot.

    When the status is ``failed`` or ``timeout``, an optional short reason
    string is shown as a dimmed subtitle line beneath the stage name and as
    a tooltip on the whole row.
    """

    def __init__(
        self,
        stage_key: str,
        label: str,
        icon_name: str,
        is_dark: bool,
        compact: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._stage_key = stage_key
        self._icon_name = icon_name
        self._is_dark = is_dark
        self._compact = compact
        self._status = "pending"
        self._reason: str | None = None

        # ── Icon ──────────────────────────────────────────────────────────
        self._icon_lbl = QLabel()
        self._icon_lbl.setFixedWidth(20 if not compact else 16)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setStyleSheet("background: transparent; border: none;")
        self._icon_lbl.setAutoFillBackground(False)

        # ── Label + optional reason subtitle ──────────────────────────────
        self._name_lbl = QLabel(label)
        font_size = "12px" if compact else "13px"
        self._name_lbl.setStyleSheet(
            f"font-size: {font_size}; background: transparent; border: none;"
        )
        self._name_lbl.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        # Reason subtitle — hidden until a failed/timeout reason is set
        self._reason_lbl = QLabel()
        reason_font_size = "10px" if compact else "11px"
        self._reason_lbl.setStyleSheet(
            f"font-size: {reason_font_size}; font-style: italic; "
            "background: transparent; border: none;"
        )
        self._reason_lbl.setWordWrap(True)
        self._reason_lbl.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self._reason_lbl.hide()

        label_col = QVBoxLayout()
        label_col.setContentsMargins(0, 0, 0, 0)
        label_col.setSpacing(1)
        label_col.addWidget(self._name_lbl)
        label_col.addWidget(self._reason_lbl)

        # ── Status text ────────────────────────────────────────────────────
        self._status_lbl = QLabel(_STATUS_LABEL.get("pending", "Pending"))
        status_font_size = "11px" if compact else "12px"
        self._status_lbl.setStyleSheet(
            f"font-size: {status_font_size}; font-weight: 600; "
            "background: transparent; border: none;"
        )
        self._status_lbl.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )

        # ── Dot ────────────────────────────────────────────────────────────
        self._dot_lbl = QLabel("●")
        dot_size = "8px" if compact else "9px"
        self._dot_lbl.setFixedWidth(16)
        self._dot_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Base style — color applied via _apply_colors()
        self._dot_lbl.setStyleSheet(
            f"font-size: {dot_size}; background: transparent; border: none;"
        )

        # ── Layout ─────────────────────────────────────────────────────────
        v_pad = 5 if compact else 8
        row = QHBoxLayout(self)
        row.setContentsMargins(0, v_pad, 0, v_pad)
        row.setSpacing(8)
        row.addWidget(self._icon_lbl)
        row.addLayout(label_col, 1)
        row.addWidget(self._status_lbl)
        row.addWidget(self._dot_lbl)

        self._apply_colors()
        self._apply_icon()

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_status(self, status: str, is_dark: bool) -> None:
        """Update status text and colors for this row."""
        self._status = status
        self._is_dark = is_dark
        self._status_lbl.setText(_STATUS_LABEL.get(status, status.capitalize()))
        self._apply_colors()
        self._apply_icon()

    def set_reason(self, reason: str | None) -> None:
        """Set or clear the failure reason subtitle shown on failed/timeout rows."""
        self._reason = reason
        if reason and self._status in ("failed", "timeout"):
            # Truncate long error strings for the subtitle; full text in tooltip
            short = reason if len(reason) <= 80 else reason[:77] + "…"
            self._reason_lbl.setText(short)
            self._reason_lbl.show()
            self.setToolTip(reason)
        else:
            self._reason_lbl.hide()
            self._reason_lbl.setText("")
            self.setToolTip("")

    # ── Internal ───────────────────────────────────────────────────────────────

    def _apply_colors(self) -> None:
        """Set dot and text colors from stage_colors() tokens. Called on
        every status change and in showEvent() so Qt re-polish cannot reset them."""
        dot_color, text_color = stage_colors(self._status, self._is_dark)
        t = Dark if self._is_dark else Light
        font_size = "11px" if self._compact else "12px"
        self._dot_lbl.setStyleSheet(
            f"color: {dot_color}; font-size: 9px; background: transparent; border: none;"
        )
        self._status_lbl.setStyleSheet(
            f"color: {text_color}; font-size: {font_size}; font-weight: 600; "
            "background: transparent; border: none;"
        )
        # Skipped rows: dim the stage name too
        name_color = t.text_muted if self._status == "skipped" else t.text
        name_size = "12px" if self._compact else "13px"
        name_style = "italic " if self._status == "skipped" else ""
        self._name_lbl.setStyleSheet(
            f"font-size: {name_size}; font-style: {name_style.strip() or 'normal'}; "
            f"color: {name_color}; background: transparent; border: none;"
        )
        # Reason subtitle color — use the same muted text color
        reason_font_size = "10px" if self._compact else "11px"
        self._reason_lbl.setStyleSheet(
            f"font-size: {reason_font_size}; font-style: italic; "
            f"color: {t.text_muted}; background: transparent; border: none;"
        )
        # Re-apply reason visibility in case status just changed to failed/timeout
        if self._reason and self._status in ("failed", "timeout"):
            short = self._reason if len(self._reason) <= 80 else self._reason[:77] + "…"
            self._reason_lbl.setText(short)
            self._reason_lbl.show()
            self.setToolTip(self._reason)
        else:
            self._reason_lbl.hide()
            self.setToolTip("")

    def _apply_icon(self) -> None:
        """Load SVG icon tinted with the current status dot color."""
        dot_color, _ = stage_colors(self._status, self._is_dark)
        size = 14 if self._compact else 16
        icon = svg_icon(self._icon_name, dot_color, size=size)
        if icon:
            self._icon_lbl.setPixmap(icon.pixmap(size, size))

    def showEvent(self, event) -> None:
        """Re-apply colors after the widget is fully parented and polished
        to survive Qt's re-polish cycle on widget insertion."""
        super().showEvent(event)
        self._apply_colors()
        self._apply_icon()


class PipelineStagesWidget(QWidget):
    """Five-row pipeline stage status display.

    Parameters
    ----------
    is_dark:  Initial theme state.
    compact:  If True, reduced padding and font size for the card variant.
    parent:   Optional parent widget.
    """

    def __init__(
        self,
        is_dark: bool = False,
        compact: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._is_dark = is_dark
        self._compact = compact

        outer = QVBoxLayout(self)
        spacing = 0 if compact else 2
        v_margin = 4 if compact else 8
        h_margin = 0 if compact else 4
        outer.setContentsMargins(h_margin, v_margin, h_margin, v_margin)
        outer.setSpacing(spacing)

        # Build one _StageRow per stage, in canonical order.
        self._rows: dict[str, _StageRow] = {}
        for key, label, icon_name in _STAGES:
            row = _StageRow(key, label, icon_name, is_dark, compact)
            self._rows[key] = row
            outer.addWidget(row)

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_stages(
        self,
        stages: dict[str, str],
        is_dark: bool | None = None,
        reasons: dict[str, str | None] | None = None,
    ) -> None:
        """Update rows in-place from a pipeline_stages dict.

        Only rows whose status has changed are touched, keeping Qt's paint
        work minimal.  The ``is_dark`` argument can be omitted when the theme
        has not changed since the last call.

        Parameters
        ----------
        stages:  ``{stage_key: status}`` dict from ``EmailDetail.pipeline_stages``.
        is_dark: Current theme state.  Omit to keep the previous value.
        reasons: Optional ``{stage_key: error_text}`` dict.  When present,
                 sets the failure-reason subtitle on failed/timeout rows.
                 Pass ``None`` values to clear a previously set reason.
        """
        if is_dark is not None:
            self._is_dark = is_dark
        for key, row in self._rows.items():
            new_status = stages.get(key, "pending")
            if new_status != row._status or is_dark is not None:
                row.set_status(new_status, self._is_dark)
            if reasons is not None and key in reasons:
                row.set_reason(reasons[key])

    def showEvent(self, event) -> None:
        """Re-apply colors in all rows after widget insertion."""
        super().showEvent(event)
        for row in self._rows.values():
            row._apply_colors()
            row._apply_icon()
