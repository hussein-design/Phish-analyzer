"""Local Qt-native UI preferences only: window geometry, theme choice,
backend port. Never API keys or scoring config -- those are server-side,
edited through the Settings dialog via /settings.
"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QSettings

_ORG = "PhishAnalyzer"
_APP = "PhishAnalyzerDesktop"


class SettingsStore:
    def __init__(self) -> None:
        self._qsettings = QSettings(_ORG, _APP)

    def get_theme(self, default: str = "light") -> str:
        return str(self._qsettings.value("ui/theme", default))

    def set_theme(self, name: str) -> None:
        self._qsettings.setValue("ui/theme", name)

    def get_window_geometry(self) -> QByteArray | None:
        return self._qsettings.value("ui/window_geometry")

    def set_window_geometry(self, geometry: QByteArray) -> None:
        self._qsettings.setValue("ui/window_geometry", geometry)

    def get_backend_port(self, default: int = 8756) -> int:
        return int(self._qsettings.value("backend/port", default))

    def set_backend_port(self, port: int) -> None:
        self._qsettings.setValue("backend/port", port)
