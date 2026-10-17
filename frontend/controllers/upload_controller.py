"""Drives UploadPage's drop zone: validate -> upload -> navigate to ReportPage
immediately after the upload is accepted -> poll status in ReportPage context
(report_controller handles that).

The blocking dim overlay is shown ONLY during the upload HTTP request itself
(the POST /analyses call).  Once the server has accepted the upload and
returned 202, the overlay is dismissed and the UI switches to the report view.
The report view shows the live pipeline stage rows while the analysis runs —
there is no reason to keep the upload page blocked during analysis.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Signal

from frontend.controllers.base_controller import BaseController
from frontend.services.eml_sniff import looks_like_eml
from shared.schemas import EmailDetail, AnalysisStatus

logger = logging.getLogger(__name__)


class UploadController(BaseController):
    # Emitted as soon as the upload is accepted (202 received).
    # Carries the initial EmailDetail (status=PENDING) so the report view can
    # display the stage list immediately and start its own poll cycle.
    analysisReady = Signal(object)  # EmailDetail

    def __init__(self, api_client, notification_center, upload_page, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.upload_page = upload_page

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

        # Show the overlay only for the upload request itself.
        self.upload_page.set_uploading(True, "Uploading…")
        self.run_async(
            self.api_client.upload_email,
            path,
            on_success=self._on_uploaded,
            on_error=self._on_upload_error,
            on_finished=self._on_upload_finished,
        )

    def _on_upload_finished(self) -> None:
        """Always hide the overlay — called after on_success or on_error."""
        self.upload_page.set_uploading(False)

    def _on_upload_error(self, err) -> None:
        self.notification_center.show_toast(str(err), level="error")

    def _on_uploaded(self, response: dict) -> None:
        # The overlay is cleared by on_finished (which runs after on_success).
        # Immediately navigate to the report view with PENDING detail so
        # the pipeline stage rows appear right away.
        self.notification_center.show_toast(
            f"Uploaded {response['filename']} — analyzing…", level="info"
        )
        # Build a minimal EmailDetail from the UploadAccepted response.
        # status=PENDING triggers the report view's loading screen + polling.
        detail = EmailDetail(
            id=response["id"],
            filename=response["filename"],
            status=AnalysisStatus.PENDING,
            created_at=response["created_at"],
            updated_at=response.get("created_at", response["created_at"]),
        )
        self.analysisReady.emit(detail)
