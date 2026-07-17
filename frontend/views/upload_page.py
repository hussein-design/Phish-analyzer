"""Route 1 of 2: drop zone + browse + the embedded analyses history table."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from frontend.services.theme_manager import ThemeManager
from frontend.widgets.analyses_table import AnalysesTableWidget
from frontend.widgets.drop_zone import DropZone
from frontend.widgets.progress_overlay import ProgressOverlay


class UploadPage(QWidget):
    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        # ── Drop zone ──────────────────────────────────────────────────────
        self.drop_zone = DropZone(self)

        # ── History section header ─────────────────────────────────────────
        self._history_label = QLabel("Analysis History")
        history_font = QFont()
        history_font.setPointSize(12)
        history_font.setWeight(QFont.Weight.DemiBold)
        self._history_label.setFont(history_font)
        self._history_label.setStyleSheet("color: #1E3A5F;")

        self._count_badge = QLabel()
        self._count_badge.setStyleSheet(
            "background-color: #EFF6FF; color: #2563EB; "
            "border: 1px solid #BFDBFE; border-radius: 10px; "
            "padding: 1px 8px; font-size: 11px; font-weight: 700;"
        )
        self._count_badge.setVisible(False)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(2, 0, 0, 0)
        header_row.addWidget(self._history_label)
        header_row.addWidget(self._count_badge)
        header_row.addStretch()

        # ── Analyses table ─────────────────────────────────────────────────
        self.table = AnalysesTableWidget(theme_manager, self)
        # Forward total-count updates to the badge
        self.table.model.totalCountChanged.connect(self._update_count_badge)

        # ── Page layout ────────────────────────────────────────────────────
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        layout.addWidget(self.drop_zone)
        layout.addLayout(header_row)
        layout.addWidget(self.table, 1)

        self._overlay = ProgressOverlay(self)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _update_count_badge(self, total: int) -> None:
        if total > 0:
            self._count_badge.setText(str(total))
            self._count_badge.setVisible(True)
        else:
            self._count_badge.setVisible(False)

    def set_uploading(self, uploading: bool, message: str = "Analyzing…") -> None:
        if uploading:
            self._overlay.start(message)
        else:
            self._overlay.stop()
