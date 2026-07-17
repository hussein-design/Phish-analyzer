"""Settings dialog controller.

Saves everything — scoring weights, keyword lists, AND API keys — in a
single PUT /settings request.  This eliminates the two-step chained save
that was the root cause of API keys silently not persisting (the second
request in the chain was sometimes never fired or was swallowed).
"""
from __future__ import annotations

import logging

from frontend.controllers.base_controller import BaseController
from frontend.dialogs.settings_dialog import SettingsDialog
from frontend.services.api_client import ApiError

logger = logging.getLogger(__name__)


class SettingsController(BaseController):
    def __init__(self, api_client, notification_center, main_window, parent=None) -> None:
        super().__init__(api_client, notification_center, parent)
        self.main_window = main_window

    def open_settings_dialog(self) -> None:
        self.run_async(
            self.api_client.get_settings,
            on_success=self._show_dialog,
            on_error=lambda err: self.notification_center.show_toast(
                f"Could not load settings: {err}", level="error"
            ),
        )

    def _show_dialog(self, settings: dict) -> None:
        dialog = SettingsDialog(settings, parent=self.main_window)
        if dialog.exec():
            self._save_settings(dialog)

    def _save_settings(self, dialog: SettingsDialog) -> None:
        # Build one combined payload that includes everything — scoring weights,
        # lists, AND any API keys the user typed.  The backend's PUT /settings
        # handler writes all of this in a single atomic DB commit.
        payload: dict = {
            "scoring": dialog.scoring_payload(),
            "url_suspicious_keywords": dialog.keywords_payload(),
            "suspicious_tlds": dialog.tlds_payload(),
            "url_shorteners": dialog.shorteners_payload(),
            "urgency_keywords": dialog.urgency_payload(),
        }

        # Only add key fields when the user actually typed something.
        # Omitting them (leaving them absent from the dict) means "leave
        # unchanged".  The backend treats None as "leave unchanged".
        keys = dialog.keys_payload()
        if "virustotal_key" in keys:
            payload["virustotal_key"] = keys["virustotal_key"]
            logger.info("Settings save: virustotal_key included in payload (len=%d)", len(keys["virustotal_key"]))
        if "abuseipdb_key" in keys:
            payload["abuseipdb_key"] = keys["abuseipdb_key"]
            logger.info("Settings save: abuseipdb_key included in payload (len=%d)", len(keys["abuseipdb_key"]))
        if "shodan_key" in keys:
            payload["shodan_key"] = keys["shodan_key"]
            logger.info("Settings save: shodan_key included in payload (len=%d)", len(keys["shodan_key"]))

        # Sandbox: always include provider (user may have changed it to disabled);
        # only include the API key when the user typed a new one.
        sandbox = dialog.sandbox_payload()
        payload["sandbox_provider"] = sandbox.get("sandbox_provider")
        if "sandbox_api_key" in sandbox:
            payload["sandbox_api_key"] = sandbox["sandbox_api_key"]
            logger.info("Settings save: sandbox_api_key included in payload")

        has_keys = bool(keys) or "sandbox_api_key" in sandbox
        logger.info(
            "Settings save: payload keys present=%s, has_api_keys=%s",
            list(payload.keys()), has_keys,
        )

        self.run_async(
            self.api_client.update_settings,
            payload,
            on_success=lambda _r: self.notification_center.show_toast(
                "Settings and API keys saved" if has_keys else "Settings saved",
                level="success",
            ),
            on_error=self._on_save_error,
        )

    def _on_save_error(self, err: ApiError) -> None:
        logger.error("Failed to save settings: %s", err)
        self.notification_center.show_toast(
            f"Failed to save settings: {err}", level="error"
        )
