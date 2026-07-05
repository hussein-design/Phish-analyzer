from __future__ import annotations

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.settings_dialog import SettingsDialog


class SettingsController(BaseController):
    def __init__(self, api_client, notification_center, main_window, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.main_window = main_window

    def open_settings_dialog(self) -> None:
        self.run_async(self.api_client.get_settings, on_success=self._show_dialog)

    def _show_dialog(self, settings: dict) -> None:
        dialog = SettingsDialog(settings, parent=self.main_window)
        if dialog.exec():
            self._save_settings(dialog)

    def _save_settings(self, dialog: SettingsDialog) -> None:
        payload = {
            "scoring": dialog.scoring_payload(),
            "url_suspicious_keywords": dialog.keywords_payload(),
            "suspicious_tlds": dialog.tlds_payload(),
            "url_shorteners": dialog.shorteners_payload(),
            "urgency_keywords": dialog.urgency_payload(),
        }
        self.run_async(
            self.api_client.update_settings,
            payload,
            on_success=lambda _r: self.notification_center.show_toast(
                "Settings saved", level="success"
            ),
        )

        keys_payload = dialog.keys_payload()
        if keys_payload:
            self.run_async(
                self.api_client.update_keys,
                keys_payload,
                on_success=lambda _r: self.notification_center.show_toast(
                    "API keys updated", level="success"
                ),
            )
