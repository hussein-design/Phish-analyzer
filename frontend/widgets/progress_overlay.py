"""Semi-transparent busy overlay with an indeterminate progress bar, shown
over a page during upload/analysis so the UI never appears frozen."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget


class ProgressOverlay(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("background-color: rgba(15, 23, 42, 0.70);")
        self.setGeometry(parent.rect())
        parent.installEventFilter(self)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._label = QLabel("")
        self._label.setStyleSheet(
            "color: #F1F5F9; font-size: 14px; font-weight: 600; "
            "background: transparent; padding-bottom: 12px;"
        )
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setFixedWidth(280)
        self._bar.setFixedHeight(6)
        self._bar.setStyleSheet(
            "QProgressBar { background-color: #334155; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { background-color: #3B82F6; border-radius: 3px; }"
        )

        layout.addWidget(self._label)
        layout.addWidget(self._bar)

        self.hide()

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parent() and event.type() == QEvent.Type.Resize:
            self.setGeometry(self.parent().rect())
        return super().eventFilter(watched, event)

    def start(self, message: str = "Working…") -> None:
        self._label.setText(message)
        self.setGeometry(self.parent().rect())
        self.show()
        self.raise_()

    def stop(self) -> None:
        self.hide()
