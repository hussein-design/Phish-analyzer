"""Application entrypoint: starts the FastAPI backend in a background thread
of this same process, waits for it to become healthy, then launches the
PySide6 UI.  Shuts the backend down gracefully when the UI exits.

A frozen onefile PyInstaller exe has no reliable python.exe to subprocess,
so the backend must run in-process — see backend/server.py.

Timeout error dialog (Phase B hotfix)
──────────────────────────────────────
When wait_for_backend_ready() times out the error dialog now includes the
last INFO/WARNING/ERROR log line that was emitted.  This tells the user (and
support) which lifespan step the backend reached before it stalled, making
"could not start" reports immediately actionable without needing to hunt for
the log file.

Implementation: a ``_LastLogHandler`` is attached to the root logger before
the backend thread starts.  It records every log record in a 1-element buffer
(thread-safe via threading.Lock).  If the health-check times out, the last
message is appended to the dialog text.
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
import time

import requests

from backend.app_factory import create_app
from backend.server import BackendServer
from shared.paths import app_data_dir

logger = logging.getLogger(__name__)

_PREFERRED_PORT = 8756
_HEALTH_TIMEOUT_S = 15.0


# ── Last-log capture ──────────────────────────────────────────────────────────

class _LastLogHandler(logging.Handler):
    """Thread-safe single-slot buffer: always holds the most recent log line."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._last: str = ""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            with self._lock:
                self._last = msg
        except Exception:
            self.handleError(record)

    def last(self) -> str:
        with self._lock:
            return self._last


# ── Port helpers ──────────────────────────────────────────────────────────────

def _port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((host, port)) != 0


def resolve_port(preferred: int = _PREFERRED_PORT) -> int:
    if _port_is_free(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ── Health check ──────────────────────────────────────────────────────────────

def wait_for_backend_ready(base_url: str, timeout: float = _HEALTH_TIMEOUT_S) -> bool:
    """Blocking retry loop — safe here because QApplication doesn't exist
    yet, so there is no Qt event loop to freeze."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{base_url}/health", timeout=1.0)
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.1)
    return False


# ── Error dialog ──────────────────────────────────────────────────────────────

def _show_startup_failure(message: str) -> None:
    logger.error(message)
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, "Phish Analyzer Desktop", 0x10)
    else:
        print(message, file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    app_data_dir()  # ensure app-data dirs exist before the backend touches SQLite

    # Attach the last-log handler BEFORE creating the app and starting the
    # backend thread so we capture every log line from configure_logging()
    # onward.  A simple formatter is used — just the message, no timestamp,
    # so the dialog line stays short enough to read at a glance.
    _last_log = _LastLogHandler()
    _last_log.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    _last_log.setLevel(logging.INFO)
    logging.getLogger().addHandler(_last_log)

    port = resolve_port()
    backend_app = create_app()
    backend_server = BackendServer(backend_app, host="127.0.0.1", port=port)
    backend_server.start()

    if not wait_for_backend_ready(backend_server.base_url):
        last_line = _last_log.last()
        detail = (
            f"\n\nLast log line reached:\n  {last_line}"
            if last_line
            else "\n\n(No log output captured — check the log file for details.)"
        )
        _show_startup_failure(
            "Phish Analyzer Desktop could not start its local backend service.\n"
            "Check the log file in the app data directory for details."
            + detail
        )
        return 1

    # Remove the last-log handler — the file handler and uvicorn's console
    # handler are sufficient for normal operation.
    logging.getLogger().removeHandler(_last_log)

    from PySide6.QtWidgets import QApplication

    from frontend.services.api_client import ApiClient
    from frontend.services.settings_store import SettingsStore
    from frontend.services.theme_manager import ThemeManager
    from frontend.views.main_window import MainWindow

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Phish Analyzer Desktop")
    qt_app.setOrganizationName("PhishAnalyzer")

    settings_store = SettingsStore()
    theme_manager = ThemeManager(qt_app)
    theme_manager.apply_theme(settings_store.get_theme(ThemeManager.detect_system_theme()))
    theme_manager.themeChanged.connect(settings_store.set_theme)

    api_client = ApiClient(backend_server.base_url)

    window = MainWindow(api_client, theme_manager)
    window.show()

    qt_app.aboutToQuit.connect(backend_server.request_shutdown)

    return qt_app.exec()


if __name__ == "__main__":
    sys.exit(main())
