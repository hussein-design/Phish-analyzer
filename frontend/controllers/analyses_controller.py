"""Drives the analyses history table embedded in UploadPage: list/page/sort/
filter/delete/download. Server is authoritative for sort/filter/search
(paginated query params); the table's proxy model only does instant
re-filtering of the already-loaded page between debounced server queries.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFileDialog

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.confirm_delete_dialog import confirm_delete
from shared.schemas import AnalysesListResponse, EmailSummary

logger = logging.getLogger(__name__)

_SEARCH_DEBOUNCE_MS = 300
_PAGE_SIZE = 25


class AnalysesController(BaseController):
    def __init__(self, api_client, notification_center, table_widget, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.table_widget = table_widget

        self._search_text = ""
        self._verdict_filter: str | None = None

        self._search_debounce = QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.timeout.connect(self._reload_from_start)

        table_widget.refreshRequested.connect(self._reload_from_start)
        table_widget.searchChanged.connect(self._on_search_changed)
        table_widget.verdictFilterChanged.connect(self._on_verdict_changed)
        table_widget.moreDataRequested.connect(self._load_next_page)
        table_widget.deleteRequested.connect(self._on_delete_requested)
        table_widget.downloadRequested.connect(self._on_download_requested)

    def load_initial(self) -> None:
        self._reload_from_start()

    def refresh_after_upload(self) -> None:
        self._reload_from_start()

    def _on_search_changed(self, text: str) -> None:
        self._search_text = text
        self._search_debounce.start(_SEARCH_DEBOUNCE_MS)

    def _on_verdict_changed(self, verdict) -> None:
        self._verdict_filter = verdict
        self._reload_from_start()

    def _reload_from_start(self) -> None:
        self.run_async(
            self.api_client.list_emails,
            page=1,
            page_size=_PAGE_SIZE,
            search=self._search_text or None,
            verdict=self._verdict_filter,
            on_success=self._on_first_page_loaded,
        )

    def _on_first_page_loaded(self, data: dict) -> None:
        response = AnalysesListResponse.model_validate(data)
        self.table_widget.model.set_page(response.items, response.total)

    def _load_next_page(self) -> None:
        current_count = self.table_widget.model.rowCount()
        next_page = (current_count // _PAGE_SIZE) + 1
        self.run_async(
            self.api_client.list_emails,
            page=next_page,
            page_size=_PAGE_SIZE,
            search=self._search_text or None,
            verdict=self._verdict_filter,
            on_success=self._on_next_page_loaded,
            on_error=self._on_next_page_error,
        )

    def _on_next_page_loaded(self, data: dict) -> None:
        response = AnalysesListResponse.model_validate(data)
        self.table_widget.model.append_page(response.items, response.total)

    def _on_next_page_error(self, error) -> None:
        self.table_widget.model.set_fetching(False)
        self._default_error_handler(error)

    def _find_row(self, analysis_id: int) -> EmailSummary | None:
        for i in range(self.table_widget.model.rowCount()):
            row = self.table_widget.model.row_at(i)
            if row.id == analysis_id:
                return row
        return None

    def _on_delete_requested(self, analysis_id: int) -> None:
        row = self._find_row(analysis_id)
        filename = row.filename if row else f"#{analysis_id}"
        if not confirm_delete(self.table_widget, filename):
            return
        self.run_async(
            self.api_client.delete_email,
            analysis_id,
            on_success=lambda _r: self._on_deleted(analysis_id),
        )

    def _on_deleted(self, analysis_id: int) -> None:
        self.table_widget.model.remove_row_by_id(analysis_id)
        self.notification_center.show_toast("Analysis deleted", level="success")

    def _on_download_requested(self, analysis_id: int) -> None:
        row = self._find_row(analysis_id)
        base_name = row.filename.rsplit(".", 1)[0] if row else f"analysis-{analysis_id}"
        dest_path, _ = QFileDialog.getSaveFileName(
            self.table_widget, "Save report", f"{base_name}.docx", "Word Document (*.docx)"
        )
        if not dest_path:
            return
        self.run_async(
            self.api_client.download_report,
            analysis_id,
            dest_path,
            on_success=lambda path: self.notification_center.show_toast(
                f"Saved to {path}", level="success"
            ),
        )
