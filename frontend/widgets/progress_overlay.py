"""Semi-transparent busy overlay with an indeterminate progress bar, shown
over a page during upload/analysis so the UI never appears frozen."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget


class ProgressOverlay(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 120);")
        self.setGeometry(parent.rect())
        parent.installEventFilter(self)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._label = QLabel("")
        self._label.setStyleSheet("color: white; font-weight: 600;")
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setFixedWidth(240)

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
