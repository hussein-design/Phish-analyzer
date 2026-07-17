"""Drag/drop .eml widget — also clickable to open the standard file picker.
Custom-painted so it looks polished in both themes without relying on
platform-native widget chrome.
"""

from __future__ import annotations

from PySide6.QtCore import QPropertyAnimation, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDropEvent,
    QFont,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QFileDialog, QSizePolicy, QWidget


class DropZone(QWidget):
    filesDropped = Signal(list)
    fileSelected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("DropZone")
        self.setMinimumHeight(160)
        self.setMaximumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._hovered = False       # drag-hover state
        self._mouse_hover = False   # mouse-over state

        # Track mouse to paint hover effect on mouse-over (not just drag-over)
        self.setMouseTracking(True)

    # ── Painting ──────────────────────────────────────────────────────────────

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(2, 2, -2, -2)
        radius = 14.0

        # Detect theme from parent window background
        bg = self.palette().window().color()
        is_dark = bg.lightness() < 128

        if is_dark:
            base_bg      = QColor("#1E293B")
            hover_bg     = QColor("#1A2F52")
            border_idle  = QColor("#334155")
            border_hover = QColor("#3B82F6")
            title_color  = QColor("#CBD5E1")
            sub_color    = QColor("#64748B")
            icon_color   = QColor("#3B82F6")
        else:
            base_bg      = QColor("#FFFFFF")
            hover_bg     = QColor("#EFF6FF")
            border_idle  = QColor("#CBD5E1")
            border_hover = QColor("#2563EB")
            title_color  = QColor("#1E3A5F")
            sub_color    = QColor("#64748B")
            icon_color   = QColor("#2563EB")

        active = self._hovered or self._mouse_hover

        # Background fill
        path = QPainterPath()
        path.addRoundedRect(rect.toRectF() if hasattr(rect, "toRectF") else rect.__class__(rect), radius, radius)
        painter.fillPath(path, hover_bg if active else base_bg)

        # Dashed border
        pen = QPen(border_hover if active else border_idle)
        pen.setWidth(2)
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setDashPattern([6, 4])
        painter.setPen(pen)
        painter.drawRoundedRect(rect, radius, radius)

        # Center content
        cx = rect.center().x()
        cy = rect.center().y()

        # Upload cloud icon (drawn as simple shapes)
        self._draw_upload_icon(painter, cx, cy - 28, icon_color)

        # Primary text
        font = QFont("Segoe UI", 13, QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.setPen(title_color)
        title = "Drop a .eml file here  or  click to browse"
        painter.drawText(
            rect.adjusted(0, 30, 0, 0),
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter,
            title,
        )

        # Subtitle text
        font2 = QFont("Segoe UI", 11)
        painter.setFont(font2)
        painter.setPen(sub_color)
        painter.drawText(
            rect.adjusted(0, 56, 0, 0),
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter,
            "Supported format: RFC 822 .eml  •  Max 25 MB",
        )

        painter.end()

    def _draw_upload_icon(self, painter: QPainter, cx: int, cy: int, color: QColor) -> None:
        """Draw a simple upward-arrow-with-base upload icon."""
        painter.save()
        pen = QPen(color)
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        # Arrow shaft + head
        painter.drawLine(cx, cy + 14, cx, cy - 8)                  # shaft
        painter.drawLine(cx - 10, cy + 2, cx, cy - 10)             # left arrow head
        painter.drawLine(cx + 10, cy + 2, cx, cy - 10)             # right arrow head

        # Base tray
        painter.drawLine(cx - 16, cy + 14, cx + 16, cy + 14)       # tray top
        painter.drawLine(cx - 16, cy + 14, cx - 16, cy + 20)       # tray left
        painter.drawLine(cx + 16, cy + 14, cx + 16, cy + 20)       # tray right
        painter.drawLine(cx - 16, cy + 20, cx + 16, cy + 20)       # tray bottom

        painter.restore()

    # ── Drag-and-drop events ──────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._has_eml_url(event.mimeData()):
            self._hovered = True
            self.update()
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._hovered = False
        self.update()
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        self._hovered = False
        self.update()
        paths = [
            url.toLocalFile()
            for url in event.mimeData().urls()
            if url.isLocalFile() and url.toLocalFile().lower().endswith(".eml")
        ]
        if paths:
            self.filesDropped.emit(paths)
            event.acceptProposedAction()
        else:
            event.ignore()

    # ── Mouse events ─────────────────────────────────────────────────────────

    def enterEvent(self, event) -> None:
        self._mouse_hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._mouse_hover = False
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select .eml file", "", "Email files (*.eml)"
        )
        if path:
            self.fileSelected.emit(path)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _has_eml_url(mime_data) -> bool:
        if not mime_data.hasUrls():
            return False
        return any(
            url.isLocalFile() and url.toLocalFile().lower().endswith(".eml")
            for url in mime_data.urls()
        )
