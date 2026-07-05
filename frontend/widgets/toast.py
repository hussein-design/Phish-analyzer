"""Snackbar-style toast notifications. Constructed once in MainWindow and
injected by constructor into every controller -- this is the one shared
piece of UI state controllers reach for on error/success, not a global
singleton.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

_COLORS = {"info": "#2D6CDF", "success": "#2E9E5B", "error": "#D64545", "warning": "#C98A1E"}


class Toast(QLabel):
    def __init__(self, message: str, level: str, parent: QWidget) -> None:
        super().__init__(message, parent)
        color = _COLORS.get(level, _COLORS["info"])
        self.setStyleSheet(
            f"background-color: {color}; color: white; padding: 10px 16px; "
            f"border-radius: 6px; font-weight: 500;"
        )
        self.setWordWrap(True)
        self.setMaximumWidth(360)
        self.adjustSize()


class NotificationCenter(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._layout = QVBoxLayout(self)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignRight)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self.setGeometry(parent.rect())
        parent.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parent() and event.type() == QEvent.Type.Resize:
            self.setGeometry(self.parent().rect())
        return super().eventFilter(watched, event)

    def show_toast(self, message: str, level: str = "info", duration_ms: int = 3500) -> None:
        toast = Toast(message, level, self)
        self._layout.addWidget(toast)
        toast.show()
        self.raise_()

        def remove() -> None:
            self._layout.removeWidget(toast)
            toast.deleteLater()

        QTimer.singleShot(duration_ms, remove)
