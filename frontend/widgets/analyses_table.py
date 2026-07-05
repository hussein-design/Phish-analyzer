"""Embedded history table widget for UploadPage: QTableView + search bar +
verdict filter toolbar. Views never network -- every user action here is
just a signal for AnalysesController to act on.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
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


class AnalysesTableWidget(QWidget):
    rowActivated = Signal(int)
    deleteRequested = Signal(int)
    downloadRequested = Signal(int)
    refreshRequested = Signal()
    searchChanged = Signal(str)
    verdictFilterChanged = Signal(object)
    moreDataRequested = Signal()

    def __init__(self, theme_manager: ThemeManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.model = AnalysesTableModel(self)
        self.proxy = AnalysesFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.model.moreDataRequested.connect(self.moreDataRequested)

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("Search filename, subject, sender…")
        self._search_box.textChanged.connect(self._on_search_text_changed)

        self._verdict_combo = QComboBox()
        for label, _value in _VERDICT_OPTIONS:
            self._verdict_combo.addItem(label)
        self._verdict_combo.currentIndexChanged.connect(self._on_verdict_changed)

        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.clicked.connect(self.refreshRequested)

        self._delete_button = QPushButton("Delete")
        self._delete_button.clicked.connect(self._emit_delete)

        self._download_button = QPushButton("Download report")
        self._download_button.clicked.connect(self._emit_download)

        toolbar = QHBoxLayout()
        toolbar.addWidget(self._search_box, 1)
        toolbar.addWidget(self._verdict_combo)
        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._delete_button)
        toolbar.addWidget(self._download_button)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)  # server is authoritative for sort
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(self._on_row_activated)
        self.table.verticalScrollBar().valueChanged.connect(self._maybe_fetch_more)

        self._verdict_delegate = VerdictColorDelegate(theme_manager, self.table)
        self.table.setItemDelegateForColumn(_VERDICT_COLUMN, self._verdict_delegate)

        layout = QVBoxLayout(self)
        layout.addLayout(toolbar)
        layout.addWidget(self.table)

    def _on_search_text_changed(self, text: str) -> None:
        self.proxy.set_search_text(text)
        self.searchChanged.emit(text)

    def _on_verdict_changed(self, index: int) -> None:
        _label, value = _VERDICT_OPTIONS[index]
        self.proxy.set_verdict_filter(value)
        self.verdictFilterChanged.emit(value)

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
