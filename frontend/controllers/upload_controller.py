"""Drives UploadPage's drop zone: validate -> upload -> poll status ->
signal MainWindow to navigate to ReportPage. Polling uses a QTimer, reusing
the same run_async plumbing on every tick.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import QTimer, Signal

from frontend.controllers.base_controller import BaseController
from frontend.services.eml_sniff import looks_like_eml
from shared.schemas import EmailDetail

logger = logging.getLogger(__name__)

_POLL_INTERVAL_MS = 1500
_POLL_MAX_ATTEMPTS = 80  # ~2 minutes at 1.5s each


class UploadController(BaseController):
    analysisReady = Signal(object)  # EmailDetail

    def __init__(self, api_client, notification_center, upload_page, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.upload_page = upload_page
        self._poll_timer: QTimer | None = None
        self._poll_attempts = 0
        self._current_analysis_id: int | None = None

        upload_page.drop_zone.filesDropped.connect(self._on_files_dropped)
        upload_page.drop_zone.fileSelected.connect(self._on_file_selected)

    def _on_files_dropped(self, paths: list[str]) -> None:
        for path in paths:
            self._start_upload(path)

    def _on_file_selected(self, path: str) -> None:
        self._start_upload(path)

    def _start_upload(self, path: str) -> None:
        ok, reason = looks_like_eml(path)
        if not ok:
            self.notification_center.show_toast(reason or "Invalid file", level="error")
            return

        self.upload_page.set_uploading(True, "Uploading…")
        self.run_async(
            self.api_client.upload_email,
            path,
            on_success=self._on_uploaded,
            on_finished=self._on_upload_request_finished,
        )

    def _on_upload_request_finished(self) -> None:
        # Leave the overlay up if a poll cycle is about to start; only clear
        # it here if the upload itself failed before a poll could begin.
        if self._poll_timer is None and self._current_analysis_id is None:
            self.upload_page.set_uploading(False)

    def _on_uploaded(self, response: dict) -> None:
        self._current_analysis_id = response["id"]
        self.notification_center.show_toast(
            f"Uploaded {response['filename']} — analyzing…", level="info"
        )
        self.upload_page.set_uploading(True, f"Analyzing {response['filename']}…")
        self._poll_attempts = 0
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_status)
        self._poll_timer.start(_POLL_INTERVAL_MS)

    def _poll_status(self) -> None:
        self._poll_attempts += 1
        if self._poll_attempts > _POLL_MAX_ATTEMPTS:
            self._stop_polling()
            self.upload_page.set_uploading(False)
            self.notification_center.show_toast(
                "Still processing — check it later in the history list.", level="warning"
            )
            return

        self.run_async(
            self.api_client.get_email, self._current_analysis_id, on_success=self._on_poll_result
        )

    def _on_poll_result(self, data: dict) -> None:
        status = data.get("status")
        if status == "DONE":
            self._stop_polling()
            self.upload_page.set_uploading(False)
            self.notification_center.show_toast("Analysis complete", level="success")
            self.analysisReady.emit(EmailDetail.model_validate(data))
        elif status == "FAILED":
            self._stop_polling()
            self.upload_page.set_uploading(False)
            reason = data.get("error_message") or "Analysis failed"
            self.notification_center.show_toast(reason, level="error")
        # else: still PENDING/RUNNING -- keep polling

    def _stop_polling(self) -> None:
        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer.deleteLater()
            self._poll_timer = None
        self._current_analysis_id = None
