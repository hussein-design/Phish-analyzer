"""Snackbar-style toast notifications with icon prefixes.
Constructed once in MainWindow and injected into every controller.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

# (background, text color, left-accent color, icon)
_STYLES: dict[str, tuple[str, str, str, str]] = {
    "info":    ("#EFF6FF", "#1E40AF", "#2563EB", "ℹ"),
    "success": ("#F0FDF4", "#14532D", "#16A34A", "✓"),
    "error":   ("#FEF2F2", "#7F1D1D", "#DC2626", "✕"),
    "warning": ("#FFFBEB", "#78350F", "#D97706", "⚠"),
}

_DARK_STYLES: dict[str, tuple[str, str, str, str]] = {
    "info":    ("#1E293B", "#93C5FD", "#3B82F6", "ℹ"),
    "success": ("#052E16", "#86EFAC", "#22C55E", "✓"),
    "error":   ("#450A0A", "#FCA5A5", "#EF4444", "✕"),
    "warning": ("#451A03", "#FCD34D", "#F59E0B", "⚠"),
}


class Toast(QLabel):
    def __init__(self, message: str, level: str, parent: QWidget) -> None:
        super().__init__(parent)

        # Pick style based on parent window brightness
        bg = parent.palette().window().color()
        is_dark = bg.lightness() < 128
        styles = _DARK_STYLES if is_dark else _STYLES

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
