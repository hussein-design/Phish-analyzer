"""Drag/drop .eml widget — also clickable to open the standard file picker.
Custom-painted so it looks polished in both themes without relying on
platform-native widget chrome.

All colors sourced from frontend.services.tokens — no inline hex values.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
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

from frontend.services.tokens import Dark, Light


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

        self.setMouseTracking(True)

    # ── Painting ──────────────────────────────────────────────────────────────

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(2, 2, -2, -2)
        radius = 14.0

        bg = self.palette().window().color()
        is_dark = bg.lightness() < 128
        t = Dark if is_dark else Light

        active = self._hovered or self._mouse_hover

        # Background fill
        path = QPainterPath()
        path.addRoundedRect(
            rect.toRectF() if hasattr(rect, "toRectF") else rect.__class__(rect),
            radius, radius
        )
        bg_fill = QColor(t.dropzone_bg_hover if active else t.dropzone_bg)
        painter.fillPath(path, bg_fill)

        # Dashed border
        pen = QPen(QColor(t.dropzone_border_hover if active else t.dropzone_border))
        pen.setWidth(2)
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setDashPattern([6, 4])
        painter.setPen(pen)
        painter.drawRoundedRect(rect, radius, radius)

        # Center content — all offsets are relative to cy so the layout is
        # consistent at any widget height and nothing overlaps.
        cx = rect.center().x()
        cy = rect.center().y()

        # Icon:  top of arrow at cy-30, bottom of base at cy+6  (36px total)
        self._draw_upload_icon(painter, cx, cy - 18, QColor(t.dropzone_icon))

        # Primary text: 14px gap below icon base
        font = QFont("Segoe UI", 13, QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor(t.dropzone_title))
        title = "Drop a .eml file here  or  click to browse"
        from PySide6.QtCore import QRect as _QRect
        title_rect = _QRect(rect.left(), cy + 16, rect.width(), 24)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter, title)

        # Subtitle: 6px below title
        font2 = QFont("Segoe UI", 11)
        painter.setFont(font2)
        painter.setPen(QColor(t.dropzone_subtitle))
        sub_rect = _QRect(rect.left(), cy + 42, rect.width(), 20)
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter,
                         "Supported format: RFC 822 .eml  •  Max 25 MB")

        painter.end()

    def _draw_upload_icon(self, painter: QPainter, cx: int, cy: int, color: QColor) -> None:
        """Draw a simple upward-arrow-with-base upload icon centered at (cx, cy).

        Total height: arrow tip at cy-12 to tray bottom at cy+12  (24px).
        """
        painter.save()
        pen = QPen(color)
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        # Arrow shaft
        painter.drawLine(cx, cy + 6, cx, cy - 8)
        # Arrow head
        painter.drawLine(cx - 8, cy - 2, cx, cy - 10)
        painter.drawLine(cx + 8, cy - 2, cx, cy - 10)
        # Tray (horizontal base with two short side walls)
        painter.drawLine(cx - 12, cy + 6, cx + 12, cy + 6)
        painter.drawLine(cx - 12, cy + 6, cx - 12, cy + 12)
        painter.drawLine(cx + 12, cy + 6, cx + 12, cy + 12)
        painter.drawLine(cx - 12, cy + 12, cx + 12, cy + 12)

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
