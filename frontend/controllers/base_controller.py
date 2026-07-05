"""One reusable async pattern for every controller: run_async() dispatches
onto the shared QThreadPool and wires a default error->toast handler, so
individual controllers don't each reinvent error handling.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject

from frontend.services.api_client import ApiClient, ApiError
from frontend.services.async_worker import ApiWorker, run_async
from frontend.widgets.toast import NotificationCenter

logger = logging.getLogger(__name__)


class BaseController(QObject):
    def __init__(
        self,
        api_client: ApiClient,
        notification_center: NotificationCenter,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.api_client = api_client
        self.notification_center = notification_center

    def run_async(
        self,
        fn: Callable[..., Any],
        *args: Any,
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[ApiError], None] | None = None,
        on_finished: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> ApiWorker:
        return run_async(
            fn,
            *args,
            on_success=on_success,
            on_error=on_error or self._default_error_handler,
            on_finished=on_finished,
            **kwargs,
        )

    def _default_error_handler(self, error: ApiError) -> None:
        logger.warning("API error: %s", error)
        self.notification_center.show_toast(str(error), level="error")
