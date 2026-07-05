"""Pure data model over the analyses history table -- no networking here.
fetchMore() only emits a signal; the controller performs the actual API call
and pushes results back in via append_page(), keeping Views/Models network-
agnostic per the MVC split.
"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal

from shared.schemas import EmailSummary

COLUMNS = ["Filename", "Subject", "From", "Status", "Verdict", "Score", "Uploaded"]


class AnalysesTableModel(QAbstractTableModel):
    moreDataRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[EmailSummary] = []
        self._has_more = False
        self._total = 0
        self._fetching = False

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole.value):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.UserRole:
            return row

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if col == 0:
            return row.filename
        if col == 1:
            return row.subject or ""
        if col == 2:
            return row.from_addr or ""
        if col == 3:
            return row.status.value
        if col == 4:
            return row.verdict.value if row.verdict else ""
        if col == 5:
            return row.score if row.score is not None else ""
        if col == 6:
            return row.created_at.strftime("%Y-%m-%d %H:%M")
        return None

    def row_at(self, row_index: int) -> EmailSummary:
        return self._rows[row_index]

    def set_page(self, items: list[EmailSummary], total: int) -> None:
        """Replace all rows -- used for a fresh query, page 1, or refresh."""
        self.beginResetModel()
        self._rows = list(items)
        self._total = total
        self._has_more = len(self._rows) < total
        self.endResetModel()

    def append_page(self, items: list[EmailSummary], total: int) -> None:
        self._fetching = False
        if not items:
            self._has_more = False
            return
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(items) - 1)
        self._rows.extend(items)
        self._total = total
        self.endInsertRows()
        self._has_more = len(self._rows) < total

    def upsert_row(self, item: EmailSummary) -> None:
        for i, row in enumerate(self._rows):
            if row.id == item.id:
                self._rows[i] = item
                top_left = self.index(i, 0)
                bottom_right = self.index(i, self.columnCount() - 1)
                self.dataChanged.emit(top_left, bottom_right)
                return
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._rows.insert(0, item)
        self._total += 1
        self.endInsertRows()

    def remove_row_by_id(self, analysis_id: int) -> None:
        for i, row in enumerate(self._rows):
            if row.id == analysis_id:
                self.beginRemoveRows(QModelIndex(), i, i)
                del self._rows[i]
                self._total = max(0, self._total - 1)
                self.endRemoveRows()
                return

    def set_fetching(self, value: bool) -> None:
        self._fetching = value

    def canFetchMore(self, parent: QModelIndex = QModelIndex()) -> bool:
        if parent.isValid():
            return False
        return self._has_more and not self._fetching

    def fetchMore(self, parent: QModelIndex = QModelIndex()) -> None:
        if parent.isValid() or self._fetching:
            return
        self._fetching = True
        self.moreDataRequested.emit()
