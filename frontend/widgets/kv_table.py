"""Reusable label:value grid used by the Report page's Email Details and
Header & Sender Analysis sections."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFormLayout, QLabel, QWidget


class KeyValueTable(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QFormLayout(self)
        self._layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

    def clear(self) -> None:
        while self._layout.rowCount():
            self._layout.removeRow(0)

    def set_rows(self, rows: list[tuple[str, str | None]]) -> None:
        self.clear()
        for label, value in rows:
            label_widget = QLabel(f"{label}:")
            label_widget.setStyleSheet("font-weight: 600;")
            value_widget = QLabel(value if value else "—")
            value_widget.setWordWrap(True)
            value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._layout.addRow(label_widget, value_widget)
