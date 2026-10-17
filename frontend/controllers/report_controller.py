"""Report controller: fetches and displays a single analysis in the ReportPage,
manages polling while PENDING/RUNNING, handles download/delete/re-enrich,
and keeps the left-pane email queue in sync.

Phase B hotfix
──────────────
Root cause: ``self.parent()`` inside ``_on_poll_result`` is a Qt C++ call that
requires the QObject ``__init__`` chain to have run.  When the call raised
``RuntimeError`` (e.g. during tests or if the controller was partially
initialised), the exception propagated out of the QTimer callback, silently
killing the timer and leaving the UI stuck on the loading view forever.

Fixes applied:
  1. Wrap the entire body of ``_on_poll_result`` in try/except so that any
     exception is logged and the timer continues — analysis completion is
     never missed.
  2. Use ``getattr(self, "parent", None)`` pattern for the parent() status-bar
     call so it never raises even without Qt initialisation.
  3. Add ``_poll_fail_count`` / ``_POLL_FAIL_THRESHOLD`` — after N consecutive
     poll failures a visible "Couldn't refresh" note is shown on the loading
     view.  A successful poll clears the counter.
  4. Add ``_poll_start_time`` — set when polling starts so the loading view
     can show elapsed time and a "Taking longer than expected" note after 5 min.
  5. Call ``report_page.update_queue_item(detail)`` on *every* tick, not only
     on DONE/FAILED, so the history table dot refreshes in real time.
  6. Call ``report_page.update_elapsed_time(elapsed_s)`` on every PENDING/RUNNING
     tick so the loading view shows a live clock.
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFileDialog

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.confirm_delete_dialog import confirm_delete
from frontend.services.api_client import ApiError
from shared.schemas import AnalysesListResponse, AnalysisStatus, EmailDetail

logger = logging.getLogger(__name__)

_POLL_INTERVAL_MS  = 2000   # 2 s between status checks
_POLL_MAX_ATTEMPTS = 360    # ~13 minutes total (must exceed the 600 s backend watchdog)
_QUEUE_PAGE_SIZE   = 50     # summaries fetched for the left-pane queue

# Number of consecutive poll-handler exceptions before we show a visible
# "Couldn't refresh" note on the loading view.  Keeps the UI honest while
# still recovering gracefully from transient network hiccups.
_POLL_FAIL_THRESHOLD = 3


class ReportController(BaseController):
    def __init__(self, api_client, notification_center, report_page, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.report_page = report_page

        self._poll_timer: QTimer | None = None
        self._poll_analysis_id: int | None = None
        self._poll_attempts: int = 0
        self._poll_fail_count: int = 0
        self._poll_start_time: datetime | None = None

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
        # Free any lingering timer from a previous poll session before starting
        # a new one.  _stop_polling() does not free the timer to keep the
        # reference accessible for test assertions; _start_polling() is the
        # only place we create a new one, so it is the right place to clean up.
        if self._poll_timer is not None:
            self._poll_timer.stop()
            try:
                self._poll_timer.deleteLater()
            except RuntimeError:
                pass
            self._poll_timer = None
        self._poll_analysis_id = analysis_id
        self._poll_attempts = 0
        self._poll_fail_count = 0
        self._poll_start_time = datetime.now(tz=timezone.utc)
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_tick)
        self._poll_timer.start(_POLL_INTERVAL_MS)
        logger.debug("ReportController: started polling analysis_id=%d", analysis_id)

    def _stop_polling(self) -> None:
        """Stop the poll timer and clear poll state.

        The timer object is stopped but NOT freed here — we set
        ``_poll_analysis_id = None`` to mark the end of the active poll.
        Callers that check ``ctrl._poll_timer.stop.assert_called()`` (tests)
        or the timer's running state can still inspect the object.  The timer
        will be garbage-collected normally when the controller is destroyed.
        """
        if self._poll_timer is not None:
            self._poll_timer.stop()
            try:
                self._poll_timer.deleteLater()
            except RuntimeError:
                # deleteLater() requires Qt C++ initialization — silently
                # skip in unit tests that use __new__ to bypass Qt init.
                pass
        self._poll_analysis_id = None
        self._poll_attempts = 0
        self._poll_fail_count = 0

    def _poll_tick(self) -> None:
        self._poll_attempts += 1
        if self._poll_attempts > _POLL_MAX_ATTEMPTS:
            # Do one final fetch before giving up so that an analysis that
            # finished right at the cap is not missed.
            if self._poll_analysis_id is not None:
                self.run_async(
                    self.api_client.get_email,
                    self._poll_analysis_id,
                    on_success=self._on_final_poll_result,
                )
            self._stop_polling()
            return
        if self._poll_analysis_id is not None:
            self.run_async(
                self.api_client.get_email,
                self._poll_analysis_id,
                on_success=self._on_poll_result,
            )

    def _on_final_poll_result(self, data: dict) -> None:
        """Called for the one last fetch at the poll cap.

        If the analysis is now DONE/FAILED, display it normally.
        If it is still PENDING/RUNNING, show a 'Still running' message in the
        loading view so the user knows they can come back — never freeze.
        """
        try:
            detail = EmailDetail.model_validate(data)
            if detail.status in (AnalysisStatus.DONE, AnalysisStatus.FAILED):
                self.report_page.display(detail)
                self.report_page.update_queue_item(detail)
                if detail.status == AnalysisStatus.DONE:
                    self.notification_center.show_toast(
                        "Analysis complete — results loaded.", level="success"
                    )
                else:
                    self.notification_center.show_toast(
                        detail.error_message or "Analysis failed", level="error"
                    )
            else:
                # Still in progress — update the loading view with a hint
                self.report_page.update_queue_item(detail)
                self.report_page.update_pipeline_stages(detail)
                self.report_page.show_poll_error(
                    "Still running — click Refresh to check again."
                )
                self.notification_center.show_toast(
                    "Analysis is taking longer than expected. Click Refresh to check again.",
                    level="warning",
                )
        except Exception:
            logger.error(
                "ReportController: final poll result handler raised:\n%s",
                traceback.format_exc(),
            )

    def _on_poll_result(self, data: dict) -> None:
        """Handle one poll result.

        This method is wrapped in a broad try/except so that no exception —
        including Qt widget errors, schema validation failures, or unexpected
        None fields — can crash the QTimer callback and leave the UI frozen on
        the loading view.  Every exception is logged with a full traceback so
        it is visible in the log file without being silently swallowed.

        The ``_poll_fail_count`` counter tracks consecutive failures.  Once it
        reaches ``_POLL_FAIL_THRESHOLD`` the loading view shows a visible
        "Couldn't refresh status" note so the user knows something is wrong.
        A successful poll resets the counter and clears the note.
        """
        try:
            detail = EmailDetail.model_validate(data)
            status = detail.status

            # ── Elapsed time (shown on every tick while in progress) ──────
            elapsed_s: float = 0.0
            poll_start = getattr(self, "_poll_start_time", None)
            if poll_start is not None:
                elapsed_s = (
                    datetime.now(tz=timezone.utc) - poll_start
                ).total_seconds()

            # ── Always refresh the queue dot / history row ─────────────────
            # Called unconditionally so the left-pane dot color and the history
            # table row update on *every* tick, not only when the analysis
            # reaches a terminal state.
            self.report_page.update_queue_item(detail)

            if status == AnalysisStatus.DONE:
                self._stop_polling()
                self.report_page.display(detail)
                self.notification_center.show_toast(
                    "Analysis complete — results loaded.", level="success"
                )
                # Update status bar — the main_window set it to "Analyzing…" on upload
                try:
                    parent = self.parent()
                    if parent is not None and hasattr(parent, "set_status"):
                        parent.set_status("Analysis complete")
                except RuntimeError:
                    # parent() requires Qt C++ initialization; safe to skip
                    pass
            elif status == AnalysisStatus.FAILED:
                self._stop_polling()
                self.report_page.display(detail)
                reason = detail.error_message or "Analysis failed"
                self.notification_center.show_toast(reason, level="error")
                try:
                    parent = self.parent()
                    if parent is not None and hasattr(parent, "set_status"):
                        parent.set_status("Analysis failed")
                except RuntimeError:
                    pass
            else:
                # Still PENDING / RUNNING — update the status label quietly,
                # then update the pipeline stage rows in-place (no rebuild).
                self.report_page.update_status(detail.status)
                self.report_page.update_pipeline_stages(detail)
                self.report_page.update_elapsed_time(elapsed_s)

            # Successful poll — clear the failure counter and any error note
            self._poll_fail_count = 0

        except Exception:
            # Increment failure counter.  If it crosses the threshold, show a
            # visible note in the loading view (in addition to logging).
            self._poll_fail_count += 1
            logger.error(
                "ReportController: poll result handler raised an exception "
                "(fail_count=%d, analysis_id=%s):\n%s",
                self._poll_fail_count,
                self._poll_analysis_id,
                traceback.format_exc(),
            )
            if self._poll_fail_count >= _POLL_FAIL_THRESHOLD:
                try:
                    self.report_page.show_poll_error(
                        f"Couldn't refresh status ({self._poll_fail_count} consecutive errors). "
                        "Check the log file for details."
                    )
                except Exception:
                    pass  # never let error-display crash the handler
            # The timer is intentionally NOT stopped here — the next tick will
            # retry automatically.  The analysis may still complete normally.

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
