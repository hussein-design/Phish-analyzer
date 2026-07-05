"""QStackedWidget shell with exactly two routed pages -- UploadPage and
ReportPage -- plus a toolbar action opening SettingsDialog modally (a
dialog, not a third route), per the app's simplified two-page navigation.
"""

from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMainWindow, QStackedWidget, QStatusBar, QToolBar

from frontend.controllers.analyses_controller import AnalysesController
from frontend.controllers.report_controller import ReportController
from frontend.controllers.settings_controller import SettingsController
from frontend.controllers.upload_controller import UploadController
from frontend.services.api_client import ApiClient
from frontend.services.theme_manager import ThemeManager
from frontend.views.report_page import ReportPage
from frontend.views.upload_page import UploadPage
from frontend.widgets.toast import NotificationCenter


class MainWindow(QMainWindow):
    def __init__(self, api_client: ApiClient, theme_manager: ThemeManager) -> None:
        super().__init__()
        self.setWindowTitle("Phish Analyzer Desktop")
        self.resize(1100, 750)

        self.api_client = api_client
        self.theme_manager = theme_manager
        self.notification_center = NotificationCenter(self)

        self.upload_page = UploadPage(theme_manager, self)
        self.report_page = ReportPage(theme_manager, self)

        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.upload_page)
        self.stack.addWidget(self.report_page)
        self.setCentralWidget(self.stack)

        self.upload_controller = UploadController(
            api_client, self.notification_center, self.upload_page, self
        )
        self.analyses_controller = AnalysesController(
            api_client, self.notification_center, self.upload_page.table, self
        )
        self.report_controller = ReportController(
            api_client, self.notification_center, self.report_page, self
        )
        self.settings_controller = SettingsController(
            api_client, self.notification_center, self, self
        )

        self.upload_controller.analysisReady.connect(self._on_analysis_ready)
        self.upload_page.table.rowActivated.connect(self._show_report_page)
        self.report_page.backRequested.connect(self._show_upload_page)

        self._build_toolbar()
        self.setStatusBar(QStatusBar(self))
        self.statusBar().showMessage("Ready")

        self.analyses_controller.load_initial()

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main", self)
        self.addToolBar(toolbar)

        theme_action = QAction("Toggle theme", self)
        theme_action.triggered.connect(self.theme_manager.toggle)
        toolbar.addAction(theme_action)

        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.settings_controller.open_settings_dialog)
        toolbar.addAction(settings_action)

    def _on_analysis_ready(self, detail) -> None:
        self.report_controller.show_detail(detail)
        self.stack.setCurrentWidget(self.report_page)
        self.analyses_controller.refresh_after_upload()

    def _show_report_page(self, analysis_id: int) -> None:
        self.report_controller.show_analysis(analysis_id)
        self.stack.setCurrentWidget(self.report_page)

    def _show_upload_page(self) -> None:
        self.stack.setCurrentWidget(self.upload_page)
        self.analyses_controller.refresh_after_upload()
