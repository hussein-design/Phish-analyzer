"""Settings dialog controller.

The settings PUT and the keys PUT used to fire as two separate run_async
calls, which meant two concurrent worker threads both writing to SQLite at
the same time.  SQLite serialises writers, but the second write would often
silently fail or overwrite the first.  The fix is to use a single chained
call: save the scoring/list settings first, then — only after that succeeds —
save the keys.  This guarantees sequential writes with no concurrency.
"""
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
        keys_payload = dialog.keys_payload()

        if keys_payload:
            # Keys were entered — save scoring settings first, then keys on success.
            # Using on_success chaining ensures the two SQLite writes are strictly
            # sequential (never concurrent), which prevents the race condition that
            # caused keys to silently not persist.
            def _after_settings_saved(_response: dict) -> None:
                self.run_async(
                    self.api_client.update_keys,
                    keys_payload,
                    on_success=lambda _r: self.notification_center.show_toast(
                        "Settings and API keys saved", level="success"
                    ),
                    on_error=lambda err: self.notification_center.show_toast(
                        f"Settings saved but API keys failed: {err}", level="error"
                    ),
                )

            self.run_async(
                self.api_client.update_settings,
                payload,
                on_success=_after_settings_saved,
                on_error=lambda err: self.notification_center.show_toast(
                    f"Failed to save settings: {err}", level="error"
                ),
            )
        else:
            # No keys entered — single write, no chaining needed.
            self.run_async(
                self.api_client.update_settings,
                payload,
                on_success=lambda _r: self.notification_center.show_toast(
                    "Settings saved", level="success"
                ),
                on_error=lambda err: self.notification_center.show_toast(
                    f"Failed to save settings: {err}", level="error"
                ),
            )
