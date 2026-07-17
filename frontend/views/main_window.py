"""QStackedWidget shell with exactly two routed pages -- UploadPage and
ReportPage -- plus a toolbar action opening SettingsDialog modally (a
dialog, not a third route), per the app's simplified two-page navigation.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QSizePolicy,
    QStackedWidget,
    QStatusBar,
    QToolBar,
    QWidget,
)

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
        self.setWindowTitle("Phish Analyzer")
        self.setMinimumSize(960, 640)
        self.resize(1200, 800)

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
        self._build_status_bar()

        self.analyses_controller.load_initial()

        # Update theme toggle label whenever the theme changes
        self.theme_manager.themeChanged.connect(self._on_theme_changed)

    # ── Toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.addToolBar(toolbar)

        # App branding label (left side)
        brand = QLabel("🛡 Phish Analyzer")
        brand_font = QFont()
        brand_font.setPointSize(14)
        brand_font.setWeight(QFont.Weight.Bold)
        brand.setFont(brand_font)
        brand.setStyleSheet(
            "color: #E2E8F0; background: transparent; "
            "padding: 0 12px 0 4px; letter-spacing: 0.3px;"
        )
        toolbar.addWidget(brand)

        # Flexible spacer to push right-side actions to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        spacer.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        toolbar.addWidget(spacer)

        # Settings action
        self._settings_action = QAction("⚙  Settings", self)
        self._settings_action.setToolTip("Open settings & API key configuration")
        self._settings_action.triggered.connect(self.settings_controller.open_settings_dialog)
        toolbar.addAction(self._settings_action)

        toolbar.addSeparator()

        # Theme toggle — label shows current state
        self._theme_action = QAction(self._theme_label(), self)
        self._theme_action.setToolTip("Toggle light / dark theme")
        self._theme_action.triggered.connect(self.theme_manager.toggle)
        toolbar.addAction(self._theme_action)

    def _build_status_bar(self) -> None:
        sb = QStatusBar(self)
        sb.setSizeGripEnabled(False)
        self.setStatusBar(sb)
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #64748B; background: transparent;")
        sb.addWidget(self._status_label)

        self._version_label = QLabel("v1.0")
        self._version_label.setStyleSheet(
            "color: #334155; background: transparent; padding-right: 8px;"
        )
        sb.addPermanentWidget(self._version_label)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _theme_label(self) -> str:
        return "☀  Light" if self.theme_manager.current == "dark" else "🌙  Dark"

    def _on_theme_changed(self, _name: str) -> None:
        self._theme_action.setText(self._theme_label())

    def set_status(self, message: str) -> None:
        self._status_label.setText(message)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _on_analysis_ready(self, detail) -> None:
        self.report_controller.show_detail(detail)
        self.stack.setCurrentWidget(self.report_page)
        self.analyses_controller.refresh_after_upload()
        self.set_status("Analysis complete")

    def _show_report_page(self, analysis_id: int) -> None:
        self.report_controller.show_analysis(analysis_id)
        self.stack.setCurrentWidget(self.report_page)

    def _show_upload_page(self) -> None:
        self.stack.setCurrentWidget(self.upload_page)
        self.analyses_controller.refresh_after_upload()
        self.set_status("Ready")
