"""Snackbar-style toast notifications with icon prefixes.
Constructed once in MainWindow and injected into every controller.

All colors sourced from frontend.services.tokens.TOAST_STYLES.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from frontend.services.tokens import TOAST_STYLES


class Toast(QLabel):
    def __init__(self, message: str, level: str, parent: QWidget) -> None:
        super().__init__(parent)

        # Pick style based on parent window brightness
        bg = parent.palette().window().color()
        is_dark = bg.lightness() < 128
        style_key = "dark" if is_dark else "light"
        styles = TOAST_STYLES[style_key]

        bg_col, fg_col, accent_col, icon = styles.get(level, styles["info"])

        self.setText(f"{icon}  {message}")
        self.setWordWrap(True)
        self.setMaximumWidth(380)
        self.setMinimumWidth(260)
        self.setStyleSheet(
            f"""
            QLabel {{
                background-color: {bg_col};
                color: {fg_col};
                border: 1px solid {accent_col};
                border-left: 4px solid {accent_col};
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
                font-weight: 500;
            }}
            """
        )
        self.adjustSize()


class NotificationCenter(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._layout = QVBoxLayout(self)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignRight)
        self._layout.setContentsMargins(16, 16, 20, 20)
        self._layout.setSpacing(8)
        self.setGeometry(parent.rect())
        parent.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parent() and event.type() == QEvent.Type.Resize:
            self.setGeometry(self.parent().rect())
        return super().eventFilter(watched, event)

    def show_toast(self, message: str, level: str = "info", duration_ms: int = 4000) -> None:
        toast = Toast(message, level, self)
        self._layout.addWidget(toast)
        toast.show()
        self.raise_()

        def remove() -> None:
            self._layout.removeWidget(toast)
            toast.deleteLater()

        QTimer.singleShot(duration_ms, remove)
