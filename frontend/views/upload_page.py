"""Route 1 of 2: drop zone + browse + the embedded analyses history table
(search/sort/filter). This also satisfies the "history/list" requirement
without a separate route, per the simplified two-page navigation."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from frontend.services.theme_manager import ThemeManager
from frontend.widgets.analyses_table import AnalysesTableWidget
from frontend.widgets.drop_zone import DropZone
from frontend.widgets.progress_overlay import ProgressOverlay


class UploadPage(QWidget):
    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.drop_zone = DropZone(self)
        self.table = AnalysesTableWidget(theme_manager, self)

        section_label = QLabel("Analysis history")
        section_label.setStyleSheet("font-weight: 600; font-size: 14px; margin-top: 8px;")

        layout = QVBoxLayout(self)
        layout.addWidget(self.drop_zone)
        layout.addWidget(section_label)
        layout.addWidget(self.table, 1)

        self._overlay = ProgressOverlay(self)

    def set_uploading(self, uploading: bool, message: str = "Working…") -> None:
        if uploading:
            self._overlay.start(message)
        else:
            self._overlay.stop()
