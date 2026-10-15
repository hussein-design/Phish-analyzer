"""Reusable visual components for the Report page.

All colors are sourced from frontend.services.tokens — no inline hex values.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from frontend.services.tokens import RADIUS_CARD, arc_color, chip_colors


# ── Card ──────────────────────────────────────────────────────────────────────

class Card(QWidget):
    """Rounded card that inherits surface color from the active QSS theme.

    The #Card and #CardTitleBar rules in light.qss / dark.qss control all colors;
    this widget sets only the structural geometry/radius properties inline.
    """

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        # Structural geometry only — no hardcoded colors. Color is in QSS.
        self.setStyleSheet(
            "#Card { border-radius: %dpx; }" % RADIUS_CARD
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        if title:
            title_bar = QWidget()
            title_bar.setObjectName("CardTitleBar")
            # Structural only — QSS controls bg, border, color.
            title_bar.setStyleSheet(
                "#CardTitleBar {"
                "  border-top-left-radius: %dpx;"
                "  border-top-right-radius: %dpx;"
                "}" % (RADIUS_CARD, RADIUS_CARD)
            )
            tb_layout = QHBoxLayout(title_bar)
            tb_layout.setContentsMargins(16, 10, 16, 10)
            lbl = QLabel(title)
            # font properties only — color is driven by QSS #CardTitleBar QLabel rule
            lbl.setStyleSheet(
                "font-size: 11px; font-weight: 700;"
                "text-transform: uppercase; letter-spacing: 0.5px;"
                "background: transparent; border: none;"
            )
            tb_layout.addWidget(lbl)
            tb_layout.addStretch()
            outer.addWidget(title_bar)

        self.body = QWidget()
        self.body.setStyleSheet("background: transparent; border: none;")
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(16, 12, 16, 14)
        self.body_layout.setSpacing(6)
        outer.addWidget(self.body)

    def add_widget(self, w: QWidget) -> None:
        self.body_layout.addWidget(w)

    def add_layout(self, layout) -> None:
        self.body_layout.addLayout(layout)


# ── Chip ──────────────────────────────────────────────────────────────────────

class Chip(QLabel):
    """Small colored pill — theme-aware via tokens module."""

    def __init__(
        self,
        text: str,
        preset: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self._preset = preset
        self._apply_style()
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)

    def _apply_style(self) -> None:
        bg_color = self.palette().window().color()
        is_dark = bg_color.lightness() < 128
        bg, fg, border = chip_colors(self._preset, is_dark)
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border:1px solid {border};"
            f"border-radius:8px; padding:2px 10px;"
            "font-size:11px; font-weight:700;"
        )

    def showEvent(self, event) -> None:
        self._apply_style()
        super().showEvent(event)


def auth_chip(label: str, value: str) -> QWidget:
    """Returns a  LABEL [VALUE]  chip row."""
    row = QWidget()
    row.setStyleSheet("background: transparent;")
    hl = QHBoxLayout(row)
    hl.setContentsMargins(0, 0, 0, 0)
    hl.setSpacing(6)
    lbl = QLabel(label)
    lbl.setStyleSheet(
        "font-size:11px; font-weight:700; background:transparent; border:none;"
    )
    preset = (
        "pass"     if value == "pass"     else
        "fail"     if value == "fail"     else
        "softfail" if value == "softfail" else
        "neutral"  if value == "neutral"  else
        "unknown"
    )
    chip = Chip(value.upper(), preset)
    hl.addWidget(lbl)
    hl.addWidget(chip)
    hl.addStretch()
    return row


# ── ScoreRing ─────────────────────────────────────────────────────────────────

class ScoreRing(QWidget):
    """Custom-painted circular score dial. All colors from tokens module."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int | None = None
        self._verdict: str | None = None
        self.setFixedSize(100, 100)

    def set_score(self, score: int | None, verdict: str | None) -> None:
        self._score = score
        self._verdict = verdict
        self.update()

    def paintEvent(self, _event) -> None:
        from frontend.services.tokens import Dark, Light

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        m = 10
        rect = QRectF(m, m, w - m * 2, h - m * 2)

        bg = self.palette().window().color()
        is_dark = bg.lightness() < 128
        t = Dark if is_dark else Light

        track_pen = QPen(QColor(t.arc_track))
        track_pen.setWidth(8)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawEllipse(rect)

        score = self._score or 0
        max_score = 20
        pct = min(score / max_score, 1.0)
        span = int(pct * 270)

        color_str = arc_color(self._verdict, is_dark)

        if span > 0:
            arc_pen = QPen(QColor(color_str))
            arc_pen.setWidth(8)
            arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(arc_pen)
            painter.drawArc(rect, 225 * 16, -span * 16)

        painter.setPen(QColor(color_str))
        font = QFont("Segoe UI", 18, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            rect.adjusted(0, 4, 0, 0),
            Qt.AlignmentFlag.AlignCenter,
            str(score) if self._score is not None else "—",
        )

        painter.setPen(QColor(t.text_muted))
        font2 = QFont("Segoe UI", 8)
        painter.setFont(font2)
        painter.drawText(
            rect.adjusted(0, 28, 0, 0),
            Qt.AlignmentFlag.AlignCenter,
            "SCORE",
        )
        painter.end()


# ── Helpers ───────────────────────────────────────────────────────────────────

def h_separator() -> QFrame:
    """Horizontal divider — color is driven by QSS (border/divider token)."""
    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setObjectName("HSeparator")
    # No hardcoded color — the QSS #HSeparator rule (or QFrame default) handles it.
    # Fallback transparent keeps it from looking wrong if QSS doesn't match.
    sep.setStyleSheet("QFrame#HSeparator { background: transparent; border: none; border-top: 1px solid; }")
    sep.setFixedHeight(1)
    return sep


def body_label(text: str = "") -> QLabel:
    """Standard readable label — inherits theme text color, word-wraps.

    Text format is forced to PlainText so that attacker-controlled content
    (From addresses, subjects, email bodies) is never interpreted as HTML
    by Qt's AutoText detection — preventing XSS-equivalent rendering of
    crafted HTML tags in the desktop UI.
    """
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.PlainText)  # SECURITY: never render attacker HTML
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    # Expanding horizontal so it always fills the card width and word-wraps
    # rather than extending beyond the card edge and being clipped.
    lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    # Font/spacing only — color inherits from QSS QLabel rule.
    lbl.setStyleSheet(
        "font-size:13px; background:transparent; border:none; padding:2px 0;"
    )
    return lbl


def muted_label(text: str) -> QLabel:
    """Muted-color label. Uses the QSS class selector .MutedLabel for color."""
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setProperty("muted", "true")
    # font-size only; color is set by QSS QPushButton[muted="true"] or
    # the .MutedLabel selector. Fallback set here for safety.
    lbl.setStyleSheet(
        "font-size:12px; background:transparent; border:none;"
    )
    return lbl
