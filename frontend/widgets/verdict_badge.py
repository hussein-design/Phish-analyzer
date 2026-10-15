"""Verdict colored pill — standalone widget for the Report page + a
QStyledItemDelegate reusing the same color logic for the table, so the
badge appearance only exists in one place.

All colors sourced from frontend.services.tokens — no inline hex values.
"""

from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QLabel, QStyledItemDelegate, QStyleOptionViewItem, QWidget

from frontend.services.theme_manager import ThemeManager
from frontend.services.tokens import verdict_colors

_LABELS = {
    "phishing":   "⚠  Phishing",
    "suspicious": "⚡  Suspicious",
    "benign":     "✓  Benign",
}


def verdict_label(verdict: str | None) -> str:
    if not verdict:
        return "Pending"
    return _LABELS.get(verdict, verdict.title())


def verdict_color(verdict: str | None, palette: dict) -> str:
    """Compatibility helper used by other modules."""
    if not verdict:
        return palette.get("text_muted", "#888888")
    return palette.get(verdict, palette.get("text_muted", "#888888"))


class VerdictBadge(QLabel):
    def __init__(
        self,
        verdict: str | None,
        theme_manager: ThemeManager,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._theme_manager = theme_manager
        self._verdict = verdict
        self.set_verdict(verdict)
        theme_manager.themeChanged.connect(lambda _name: self.set_verdict(self._verdict))

    def set_verdict(self, verdict: str | None) -> None:
        self._verdict = verdict
        is_dark = self._theme_manager.current == "dark"
        bg, fg, border = verdict_colors(verdict, is_dark)
        self.setText(verdict_label(verdict))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"background-color: {bg}; color: {fg}; border: 1px solid {border}; "
            f"border-radius: 10px; padding: 3px 12px; font-weight: 700; font-size: 12px;"
        )


class VerdictColorDelegate(QStyledItemDelegate):
    def __init__(self, theme_manager: ThemeManager, parent=None) -> None:
        super().__init__(parent)
        self._theme_manager = theme_manager

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        verdict = index.data(Qt.ItemDataRole.DisplayRole)
        if not verdict:
            super().paint(painter, option, index)
            return

        is_dark = self._theme_manager.current == "dark"
        bg_str, fg_str, border_str = verdict_colors(verdict, is_dark)

        # Draw row background/selection first
        super().paint(painter, option, index)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect: QRect = option.rect.adjusted(8, 7, -8, -7)

        painter.setBrush(QColor(bg_str))
        painter.setPen(QColor(border_str))
        painter.drawRoundedRect(rect, 10, 10)

        font = QFont("Segoe UI", 11, QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QColor(fg_str))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, verdict_label(verdict))

        painter.restore()

    def sizeHint(self, option, index):
        hint = super().sizeHint(option, index)
        hint.setHeight(max(hint.height(), 40))
        return hint
