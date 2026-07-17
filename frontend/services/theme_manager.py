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
        "phishing":   "#DC2626",
        "suspicious": "#B45309",
        "benign":     "#16A34A",
        "surface":    "#FFFFFF",
        "surface_alt": "#F8FAFC",
        "text":       "#0F172A",
        "text_muted": "#64748B",
        "border":     "#CBD5E1",
        "primary":    "#2563EB",
    },
    DARK: {
        "phishing":   "#FCA5A5",
        "suspicious": "#FCD34D",
        "benign":     "#86EFAC",
        "surface":    "#1E293B",
        "surface_alt": "#162032",
        "text":       "#F1F5F9",
        "text_muted": "#64748B",
        "border":     "#334155",
        "primary":    "#3B82F6",
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
