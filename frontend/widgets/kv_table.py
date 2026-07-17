"""Reusable key→value grid used by the Report page sections.
Renders each row as a muted label on the left and a readable value on the
right, with a subtle separator between rows.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QSizePolicy,
    QWidget,
)


class KeyValueTable(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(16)
        self._grid.setVerticalSpacing(0)
        self._grid.setColumnStretch(1, 1)
        self._rows: list[QWidget] = []

    def clear(self) -> None:
        for w in self._rows:
            self._grid.removeWidget(w)
            w.deleteLater()
        self._rows.clear()

    def set_rows(self, rows: list[tuple[str, str | None]]) -> None:
        self.clear()
        for i, (label_text, value_text) in enumerate(rows):
            # Muted label
            lbl = QLabel(label_text)
            lbl.setStyleSheet(
                "color: #64748B; font-size: 12px; font-weight: 600; "
                "text-transform: uppercase; letter-spacing: 0.4px; "
                "padding: 8px 0 8px 12px; background: transparent;"
            )
            lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            lbl.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
            lbl.setMinimumWidth(140)

            # Value
            val = QLabel(value_text if value_text else "—")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setStyleSheet(
                "font-size: 13px; padding: 8px 12px 8px 0; background: transparent;"
            )
            val.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

            self._grid.addWidget(lbl, i * 2, 0)
            self._grid.addWidget(val, i * 2, 1)
            self._rows.extend([lbl, val])

            # Separator line (skip after last row)
            if i < len(rows) - 1:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                sep.setStyleSheet("color: #F1F5F9; background-color: #F1F5F9; margin: 0 12px;")
                sep.setFixedHeight(1)
                self._grid.addWidget(sep, i * 2 + 1, 0, 1, 2)
                self._rows.append(sep)
