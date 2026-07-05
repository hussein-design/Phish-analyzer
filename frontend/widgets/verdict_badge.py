"""Verdict colored pill -- a standalone widget for the Report page and a
QStyledItemDelegate reusing the same color logic for the analyses table, so
the badge look only exists once.
"""

from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QLabel, QStyledItemDelegate, QWidget

from frontend.services.theme_manager import ThemeManager

_LABELS = {"phishing": "Phishing", "suspicious": "Suspicious", "benign": "Benign"}


def verdict_color(verdict: str | None, palette: dict) -> str:
    if not verdict:
        return palette.get("text_muted", "#888888")
    return palette.get(verdict, palette.get("text_muted", "#888888"))


def verdict_label(verdict: str | None) -> str:
    if not verdict:
        return "Pending"
    return _LABELS.get(verdict, verdict.title())


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
        color = verdict_color(verdict, self._theme_manager.current_palette)
        self.setText(verdict_label(verdict))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"background-color: {color}; color: white; border-radius: 8px; "
            f"padding: 2px 10px; font-weight: 600;"
        )


class VerdictColorDelegate(QStyledItemDelegate):
    def __init__(self, theme_manager: ThemeManager, parent=None) -> None:
        super().__init__(parent)
        self._theme_manager = theme_manager

    def paint(self, painter: QPainter, option, index) -> None:
        verdict = index.data(Qt.ItemDataRole.DisplayRole)
        if not verdict:
            super().paint(painter, option, index)
            return

        color = QColor(verdict_color(verdict, self._theme_manager.current_palette))

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect: QRect = option.rect.adjusted(4, 6, -4, -6)
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(rect, 8, 8)
        painter.setPen(QColor("white"))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, verdict_label(verdict))
        painter.restore()
