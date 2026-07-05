"""Instant re-filtering of the already-loaded page between debounced server
round-trips. The server remains authoritative for sort/search/verdict once a
new query actually fires (see AnalysesController) -- this proxy only smooths
out the gap so typing feels immediate, and never claims to sort/filter rows
that haven't been fetched yet.
"""

from __future__ import annotations

from PySide6.QtCore import QSortFilterProxyModel, Qt


class AnalysesFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._search_text = ""
        self._verdict_filter: str | None = None
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_search_text(self, text: str) -> None:
        self._search_text = text.lower().strip()
        self.invalidateRowsFilter()

    def set_verdict_filter(self, verdict: str | None) -> None:
        self._verdict_filter = verdict
        self.invalidateRowsFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:
        model = self.sourceModel()
        index = model.index(source_row, 0, source_parent)
        row = model.data(index, Qt.ItemDataRole.UserRole)
        if row is None:
            return True

        if self._verdict_filter and (not row.verdict or row.verdict.value != self._verdict_filter):
            return False

        if self._search_text:
            haystack = " ".join(filter(None, [row.filename, row.subject, row.from_addr])).lower()
            if self._search_text not in haystack:
                return False

        return True
