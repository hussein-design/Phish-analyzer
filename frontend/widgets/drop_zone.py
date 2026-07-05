"""Drag/drop .eml widget -- also clickable to open the standard file picker
for non-drag / accessibility use. Only narrows to .eml files; the real
validation (looks_like_eml) happens in the controller before upload.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent, QMouseEvent
from PySide6.QtWidgets import QFileDialog, QLabel, QVBoxLayout, QWidget


class DropZone(QWidget):
    filesDropped = Signal(list)
    fileSelected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("DropZone")
        self.setMinimumHeight(160)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_label = QLabel("📧")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("font-size: 32px; border: none;")

        self._text_label = QLabel("Drag & drop a .eml file here, or click to browse")
        self._text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._text_label.setStyleSheet("border: none;")

        layout.addWidget(icon_label)
        layout.addWidget(self._text_label)

        self._set_active(False)

    def _set_active(self, active: bool) -> None:
        border_color = "#2D6CDF" if active else "#888888"
        self.setStyleSheet(
            f"#DropZone {{ border: 2px dashed {border_color}; border-radius: 10px; }}"
        )

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._has_eml_url(event.mimeData()):
            self._set_active(True)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._set_active(False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_active(False)
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

    def mousePressEvent(self, event: QMouseEvent) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select .eml file", "", "Email files (*.eml)"
        )
        if path:
            self.fileSelected.emit(path)

    @staticmethod
    def _has_eml_url(mime_data) -> bool:
        if not mime_data.hasUrls():
            return False
        return any(
            url.isLocalFile() and url.toLocalFile().lower().endswith(".eml")
            for url in mime_data.urls()
        )
