"""Report controller: fetches and displays a single analysis in the ReportPage,
manages polling while PENDING/RUNNING, handles download/delete/re-enrich,
and keeps the left-pane email queue in sync.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFileDialog

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.confirm_delete_dialog import confirm_delete
from frontend.services.api_client import ApiError
from shared.schemas import AnalysesListResponse, AnalysisStatus, EmailDetail

logger = logging.getLogger(__name__)

_POLL_INTERVAL_MS  = 2000   # 2 s between status checks
_POLL_MAX_ATTEMPTS = 90     # ~3 minutes total
_QUEUE_PAGE_SIZE   = 50     # summaries fetched for the left-pane queue


class ReportController(BaseController):
    def __init__(self, api_client, notification_center, report_page, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.report_page = report_page

        self._poll_timer: QTimer | None = None
        self._poll_analysis_id: int | None = None
        self._poll_attempts: int = 0

        # Wire report-page signals
        report_page.downloadRequested.connect(self._on_download_requested)
        report_page.deleteRequested.connect(self._on_delete_requested)
        report_page.reEnrichRequested.connect(self._on_re_enrich_requested)

        # Clicking a queue item updates the center pane in-place — no page navigation
        report_page.queueItemRequested.connect(self.show_analysis)

    # ── Public API ────────────────────────────────────────────────────────────

    def show_analysis(self, analysis_id: int) -> None:
        """Fetch an analysis and display it; start polling if still in progress."""
        self._stop_polling()
        self.run_async(self.api_client.get_email, analysis_id, on_success=self._on_loaded)

    def show_detail(self, detail: EmailDetail) -> None:
        """Detail already fetched — e.g. straight from the upload poll."""
        self._stop_polling()
        self.report_page.display(detail)
        if detail.status in (AnalysisStatus.PENDING, AnalysisStatus.RUNNING):
            # Populate stage rows immediately from the initial detail so the
            # user sees current state before the first poll tick fires.
            self.report_page.update_pipeline_stages(detail)
            self._start_polling(detail.id)

    def refresh_queue(self) -> None:
        """Reload the left-pane email queue from the server."""
        self.run_async(
            self.api_client.list_emails,
            page=1,
            page_size=_QUEUE_PAGE_SIZE,
            on_success=self._on_queue_loaded,
        )

    # ── Fetch callbacks ───────────────────────────────────────────────────────

    def _on_loaded(self, data: dict) -> None:
        detail = EmailDetail.model_validate(data)
        self.report_page.display(detail)
        if detail.status in (AnalysisStatus.PENDING, AnalysisStatus.RUNNING):
            self._start_polling(detail.id)

    def _on_queue_loaded(self, data: dict) -> None:
        response = AnalysesListResponse.model_validate(data)
        self.report_page.populate_queue(response.items)

    # ── Polling ───────────────────────────────────────────────────────────────

    def _start_polling(self, analysis_id: int) -> None:
        self._poll_analysis_id = analysis_id
        self._poll_attempts = 0
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_tick)
        self._poll_timer.start(_POLL_INTERVAL_MS)
        logger.debug("ReportController: started polling analysis_id=%d", analysis_id)

    def _stop_polling(self) -> None:
        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer.deleteLater()
            self._poll_timer = None
        self._poll_analysis_id = None
        self._poll_attempts = 0

    def _poll_tick(self) -> None:
        self._poll_attempts += 1
        if self._poll_attempts > _POLL_MAX_ATTEMPTS:
            self._stop_polling()
            self.notification_center.show_toast(
                "Analysis is taking longer than expected. Refresh to check again.",
                level="warning",
            )
            return
        if self._poll_analysis_id is not None:
            self.run_async(
                self.api_client.get_email,
                self._poll_analysis_id,
                on_success=self._on_poll_result,
            )

    def _on_poll_result(self, data: dict) -> None:
        detail = EmailDetail.model_validate(data)
        status = detail.status
        if status == AnalysisStatus.DONE:
            self._stop_polling()
            self.report_page.display(detail)
            # Update queue dot color now that analysis is done
            self.report_page.update_queue_item(detail)
            self.notification_center.show_toast(
                "Analysis complete — results loaded.", level="success"
            )
            # Update status bar — the main_window set it to "Analyzing…" on upload
            parent = self.parent()
            if parent is not None and hasattr(parent, "set_status"):
                parent.set_status("Analysis complete")
        elif status == AnalysisStatus.FAILED:
            self._stop_polling()
            self.report_page.display(detail)
            self.report_page.update_queue_item(detail)
            reason = detail.error_message or "Analysis failed"
            self.notification_center.show_toast(reason, level="error")
            parent = self.parent()
            if parent is not None and hasattr(parent, "set_status"):
                parent.set_status("Analysis failed")
        else:
            # Still PENDING / RUNNING — update the status label quietly,
            # then update the pipeline stage rows in-place (no rebuild).
            self.report_page.update_status(detail.status)
            self.report_page.update_pipeline_stages(detail)

    # ── Download ──────────────────────────────────────────────────────────────

    def _on_download_requested(self, analysis_id: int) -> None:
        dest_path, _ = QFileDialog.getSaveFileName(
            self.report_page,
            "Save report",
            f"analysis-{analysis_id}.docx",
            "Word Document (*.docx)",
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

    # ── Delete ────────────────────────────────────────────────────────────────

    def _on_delete_requested(self, analysis_id: int) -> None:
        if not confirm_delete(self.report_page, f"#{analysis_id}"):
            return
        self._stop_polling()
        self.run_async(
            self.api_client.delete_email,
            analysis_id,
            on_success=lambda _r: self._on_deleted(),
        )

    def _on_deleted(self) -> None:
        self.notification_center.show_toast("Analysis deleted", level="success")
        self.report_page.backRequested.emit()

    # ── Re-enrich ─────────────────────────────────────────────────────────────

    def _on_re_enrich_requested(self, analysis_id: int) -> None:
        self.run_async(
            self.api_client.re_enrich,
            analysis_id,
            on_success=self._on_re_enrich_done,
            on_error=self._on_re_enrich_error,
        )

    def _on_re_enrich_done(self, data: dict) -> None:
        detail = EmailDetail.model_validate(data)
        self.report_page.display(detail)
        self.report_page.set_re_enrich_idle()
        self.notification_center.show_toast(
            "Enrichment complete — report updated.", level="success"
        )

    def _on_re_enrich_error(self, err: ApiError) -> None:
        self.report_page.set_re_enrich_idle()
        # Show the backend's rejection reason as inline text next to the button
        # (in addition to the toast) so it is impossible to miss.
        msg = str(err)
        self.report_page.show_re_enrich_error(msg)
        self.notification_center.show_toast(
            f"Re-enrichment failed: {msg}", level="error"
        )
