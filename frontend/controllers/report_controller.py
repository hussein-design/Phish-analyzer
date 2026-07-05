from __future__ import annotations

from PySide6.QtWidgets import QFileDialog

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.confirm_delete_dialog import confirm_delete
from shared.schemas import EmailDetail


class ReportController(BaseController):
    def __init__(self, api_client, notification_center, report_page, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.report_page = report_page

        report_page.downloadRequested.connect(self._on_download_requested)
        report_page.deleteRequested.connect(self._on_delete_requested)

    def show_analysis(self, analysis_id: int) -> None:
        self.run_async(self.api_client.get_email, analysis_id, on_success=self._on_loaded)

    def show_detail(self, detail: EmailDetail) -> None:
        """detail already fetched -- e.g. straight from the upload poll."""
        self.report_page.display(detail)

    def _on_loaded(self, data: dict) -> None:
        self.report_page.display(EmailDetail.model_validate(data))

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

    def _on_delete_requested(self, analysis_id: int) -> None:
        if not confirm_delete(self.report_page, f"#{analysis_id}"):
            return
        self.run_async(
            self.api_client.delete_email,
            analysis_id,
            on_success=lambda _r: self._on_deleted(),
        )

    def _on_deleted(self) -> None:
        self.notification_center.show_toast("Analysis deleted", level="success")
        self.report_page.backRequested.emit()
