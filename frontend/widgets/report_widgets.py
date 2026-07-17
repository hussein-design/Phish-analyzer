"""Reusable visual components for the Report page.

All colors use CSS variables resolved at paint time so they work in both
light and dark themes without hardcoding hex values.
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


# ── Card ──────────────────────────────────────────────────────────────────────

class Card(QWidget):
    """Rounded card that inherits surface color from the active QSS theme."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        # Let the QSS theme control background/border via QGroupBox-style rule.
        # We use a plain border + radius here; QSS dark.qss / light.qss can
        # override #Card if needed, but the fallback already looks correct.
        self.setStyleSheet(
            "#Card {"
            "  border: 1px solid #E2E8F0;"
            "  border-radius: 10px;"
            "}"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        if title:
            title_bar = QWidget()
            title_bar.setObjectName("CardTitleBar")
            title_bar.setStyleSheet(
                "#CardTitleBar {"
                "  border-bottom: 1px solid #E2E8F0;"
                "  border-top-left-radius: 10px;"
                "  border-top-right-radius: 10px;"
                "}"
            )
            tb_layout = QHBoxLayout(title_bar)
            tb_layout.setContentsMargins(16, 10, 16, 10)
            lbl = QLabel(title)
            # Color will be overridden by the active QSS theme's QLabel rule,
            # but we set a sensible default anyway.
            lbl.setStyleSheet(
                "font-size: 11px; font-weight: 700;"
                "text-transform: uppercase; letter-spacing: 0.5px;"
                "background: transparent; border: none;"
                "color: #2563EB;"          # blue title in light; dark QSS inherits #60A5FA
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

# Both light and dark variants per preset: (light_bg, light_fg, dark_bg, dark_fg, border)
_CHIP_PRESETS = {
    "pass":     ("#F0FDF4", "#16A34A", "#052E16", "#86EFAC", "#BBF7D0"),
    "fail":     ("#FEF2F2", "#DC2626", "#450A0A", "#FCA5A5", "#FECACA"),
    "softfail": ("#FFF7ED", "#C2410C", "#431407", "#FDBA74", "#FED7AA"),
    "neutral":  ("#F1F5F9", "#475569", "#1E293B", "#94A3B8", "#334155"),
    "unknown":  ("#F1F5F9", "#64748B", "#1E293B", "#64748B", "#334155"),
    "warn":     ("#FFFBEB", "#B45309", "#451A03", "#FCD34D", "#78350F"),
    "info":     ("#EFF6FF", "#2563EB", "#172554", "#93C5FD", "#1E40AF"),
    "ok":       ("#F0FDF4", "#16A34A", "#052E16", "#86EFAC", "#BBF7D0"),
    "none":     ("#F1F5F9", "#64748B", "#1E293B", "#64748B", "#334155"),
}


class Chip(QLabel):
    """Small colored pill — theme-aware."""

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
        vals = _CHIP_PRESETS.get(self._preset, _CHIP_PRESETS["neutral"])
        l_bg, l_fg, d_bg, d_fg, border = vals
        # Detect theme from palette
        bg_color = self.palette().window().color()
        is_dark = bg_color.lightness() < 128
        bg = d_bg if is_dark else l_bg
        fg = d_fg if is_dark else l_fg
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border:1px solid {border};"
            "border-radius:8px; padding:2px 10px;"
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
    """Custom-painted circular score dial."""

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
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        m = 10
        rect = QRectF(m, m, w - m * 2, h - m * 2)

        # Detect dark mode
        bg = self.palette().window().color()
        is_dark = bg.lightness() < 128
        track_color = "#334155" if is_dark else "#E2E8F0"
        text_sub_color = "#64748B"

        track_pen = QPen(QColor(track_color))
        track_pen.setWidth(8)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawEllipse(rect)

        score = self._score or 0
        max_score = 20
        pct = min(score / max_score, 1.0)
        span = int(pct * 270)

        arc_color = (
            "#EF4444" if self._verdict == "phishing"   else
            "#F59E0B" if self._verdict == "suspicious" else
            "#22C55E"
        )

        if span > 0:
            arc_pen = QPen(QColor(arc_color))
            arc_pen.setWidth(8)
            arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(arc_pen)
            painter.drawArc(rect, 225 * 16, -span * 16)

        painter.setPen(QColor(arc_color))
        font = QFont("Segoe UI", 18, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            rect.adjusted(0, 4, 0, 0),
            Qt.AlignmentFlag.AlignCenter,
            str(score) if self._score is not None else "—",
        )

        painter.setPen(QColor(text_sub_color))
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
    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet("border: none; background: #E2E8F0;")
    sep.setFixedHeight(1)
    return sep


def body_label(text: str = "") -> QLabel:
    """Standard readable label — inherits theme text color, word-wraps."""
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    # No hardcoded color — let QSS QLabel rule set the correct light/dark color.
    lbl.setStyleSheet(
        "font-size:13px; background:transparent; border:none; padding:2px 0;"
    )
    return lbl


def muted_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(
        "font-size:12px; color:#64748B; background:transparent; border:none;"
    )
    return lbl
