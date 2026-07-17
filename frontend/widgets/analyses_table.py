"""Embedded history table widget for UploadPage: QTableView + search bar +
verdict filter toolbar. Views never network -- every user action here is
just a signal for AnalysesController to act on.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from frontend.models.analyses_filter_proxy import AnalysesFilterProxyModel
from frontend.models.analyses_table_model import AnalysesTableModel
from frontend.services.theme_manager import ThemeManager
from frontend.widgets.verdict_badge import VerdictColorDelegate

_VERDICT_OPTIONS = [
    ("All verdicts", None),
    ("Phishing", "phishing"),
    ("Suspicious", "suspicious"),
    ("Benign", "benign"),
]

_VERDICT_COLUMN = 4


def _secondary_btn(text: str, tooltip: str = "") -> QPushButton:
    """Create a ghost/secondary-style button."""
    btn = QPushButton(text)
    btn.setProperty("secondary", "true")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def _danger_btn(text: str, tooltip: str = "") -> QPushButton:
    """Create a danger-style button."""
    btn = QPushButton(text)
    btn.setProperty("danger", "true")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


class AnalysesTableWidget(QWidget):
    rowActivated = Signal(int)
    deleteRequested = Signal(int)
    downloadRequested = Signal(int)
    refreshRequested = Signal()
    searchChanged = Signal(str)
    verdictFilterChanged = Signal(object)
    moreDataRequested = Signal()
    clearHistoryRequested = Signal()

    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.model = AnalysesTableModel(self)
        self.proxy = AnalysesFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.model.moreDataRequested.connect(self.moreDataRequested)

        # ── Search + filter bar ────────────────────────────────────────────
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("🔍  Search filename, subject, sender…")
        self._search_box.setClearButtonEnabled(True)
        self._search_box.textChanged.connect(self._on_search_text_changed)
        self._search_box.setMinimumWidth(280)

        self._verdict_combo = QComboBox()
        self._verdict_combo.setToolTip("Filter by verdict")
        for label, _value in _VERDICT_OPTIONS:
            self._verdict_combo.addItem(label)
        self._verdict_combo.currentIndexChanged.connect(self._on_verdict_changed)

        # ── Action buttons ─────────────────────────────────────────────────
        self._refresh_button = _secondary_btn("↻  Refresh", "Refresh analysis list")
        self._refresh_button.clicked.connect(self.refreshRequested)

        self._delete_button = _secondary_btn("✕  Delete", "Delete selected analysis")
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._emit_delete)

        self._download_button = _secondary_btn("↓  Report", "Download .docx report")
        self._download_button.setEnabled(False)
        self._download_button.clicked.connect(self._emit_download)

        self._clear_button = _danger_btn("🗑  Clear all", "Permanently delete all analyses")
        self._clear_button.clicked.connect(self.clearHistoryRequested)

        # ── Toolbar layout ─────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(8)
        toolbar.addWidget(self._search_box, 1)
        toolbar.addWidget(self._verdict_combo)

        # Thin separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("color: #CBD5E1;")
        toolbar.addWidget(sep)

        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._delete_button)
        toolbar.addWidget(self._download_button)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setStyleSheet("color: #CBD5E1;")
        toolbar.addWidget(sep2)

        toolbar.addWidget(self._clear_button)

        # ── Table ──────────────────────────────────────────────────────────
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setFrameShape(QFrame.Shape.NoFrame)
        self.table.doubleClicked.connect(self._on_row_activated)
        self.table.verticalScrollBar().valueChanged.connect(self._maybe_fetch_more)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self._verdict_delegate = VerdictColorDelegate(theme_manager, self.table)
        self.table.setItemDelegateForColumn(_VERDICT_COLUMN, self._verdict_delegate)

        # ── Page layout ────────────────────────────────────────────────────
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addLayout(toolbar)
        layout.addWidget(self.table)

    # ── Event handlers ────────────────────────────────────────────────────

    def _on_search_text_changed(self, text: str) -> None:
        self.proxy.set_search_text(text)
        self.searchChanged.emit(text)

    def _on_verdict_changed(self, index: int) -> None:
        _label, value = _VERDICT_OPTIONS[index]
        self.proxy.set_verdict_filter(value)
        self.verdictFilterChanged.emit(value)

    def _on_selection_changed(self, _selected, _deselected) -> None:
        has_sel = bool(self.table.selectionModel().selectedRows())
        self._delete_button.setEnabled(has_sel)
        self._download_button.setEnabled(has_sel)

    def _selected_analysis_id(self) -> int | None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return None
        source_index = self.proxy.mapToSource(indexes[0])
        return self.model.row_at(source_index.row()).id

    def _on_row_activated(self, proxy_index) -> None:
        source_index = self.proxy.mapToSource(proxy_index)
        analysis_id = self.model.row_at(source_index.row()).id
        self.rowActivated.emit(analysis_id)

    def _emit_delete(self) -> None:
        analysis_id = self._selected_analysis_id()
        if analysis_id is not None:
            self.deleteRequested.emit(analysis_id)

    def _emit_download(self) -> None:
        analysis_id = self._selected_analysis_id()
        if analysis_id is not None:
            self.downloadRequested.emit(analysis_id)

    def _maybe_fetch_more(self, value: int) -> None:
        bar = self.table.verticalScrollBar()
        if bar.maximum() > 0 and value >= bar.maximum() - 2 and self.model.canFetchMore():
            self.model.fetchMore()
