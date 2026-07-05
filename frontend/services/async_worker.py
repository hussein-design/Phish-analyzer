"""QThreadPool + QRunnable async pattern, reused by every controller for
every API call. QThreadPool/QRunnable fits here because every call (list,
upload, delete, download, settings, poll) is a short one-shot blocking
call -- not a long-lived worker, so QThread+moveToThread would be overkill.

WorkerSignals is a QObject created on the GUI thread before the worker is
handed to the pool, so Qt auto-marshals succeeded/failed/finished emits back
onto the GUI thread as queued connections. Hard rule: never touch a QWidget
from inside ApiWorker.run() -- only from the connected slots.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from frontend.services.api_client import ApiError

logger = logging.getLogger(__name__)


class WorkerSignals(QObject):
    succeeded = Signal(object)
    failed = Signal(object)
    finished = Signal()


class ApiWorker(QRunnable):
    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            error = exc if isinstance(exc, ApiError) else ApiError.from_exception(exc)
            self.signals.failed.emit(error)
        else:
            self.signals.succeeded.emit(result)
        finally:
            self.signals.finished.emit()


def _default_error_logger(error: ApiError) -> None:
    logger.error("Unhandled API error: %s", error)


def run_async(
    fn: Callable[..., Any],
    *args: Any,
    on_success: Callable[[Any], None] | None = None,
    on_error: Callable[[ApiError], None] | None = None,
    on_finished: Callable[[], None] | None = None,
    **kwargs: Any,
) -> ApiWorker:
    worker = ApiWorker(fn, *args, **kwargs)
    if on_success:
        worker.signals.succeeded.connect(on_success)
    worker.signals.failed.connect(on_error or _default_error_logger)
    if on_finished:
        worker.signals.finished.connect(on_finished)
    QThreadPool.globalInstance().start(worker)
    return worker
