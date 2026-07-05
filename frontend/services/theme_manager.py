"""QSS-file-based theming. Chosen over manual QPalette code because several
custom-painted widgets (verdict badge, drop zone, toast) need declarative,
designer-editable styling that QPalette alone can't express well.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from shared.paths import assets_dir

LIGHT = "light"
DARK = "dark"

PALETTES = {
    LIGHT: {
        "phishing": "#D64545",
        "suspicious": "#C98A1E",
        "benign": "#2E9E5B",
        "surface": "#FFFFFF",
        "surface_alt": "#F5F5F7",
        "text": "#1A1A1A",
        "text_muted": "#5A5A5A",
        "border": "#D0D0D0",
    },
    DARK: {
        "phishing": "#FF6B6B",
        "suspicious": "#F2C14E",
        "benign": "#4CD787",
        "surface": "#1E1E1E",
        "surface_alt": "#2A2A2A",
        "text": "#F0F0F0",
        "text_muted": "#AAAAAA",
        "border": "#3A3A3A",
    },
}


class ThemeManager(QObject):
    themeChanged = Signal(str)

    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self._app = app
        self._current = LIGHT

    @property
    def current(self) -> str:
        return self._current

    @property
    def current_palette(self) -> dict:
        return PALETTES[self._current]

    def apply_theme(self, name: str) -> None:
        if name not in PALETTES:
            name = LIGHT
        qss_path = assets_dir() / "themes" / f"{name}.qss"
        text = qss_path.read_text(encoding="utf-8") if qss_path.exists() else ""
        self._app.setStyleSheet(text)
        self._current = name
        self.themeChanged.emit(name)

    def toggle(self) -> None:
        self.apply_theme(DARK if self._current == LIGHT else LIGHT)

    @staticmethod
    def detect_system_theme() -> str:
        try:
            hints = QGuiApplication.styleHints()
            if hints.colorScheme() == Qt.ColorScheme.Dark:
                return DARK
        except Exception:
            pass
        return LIGHT
