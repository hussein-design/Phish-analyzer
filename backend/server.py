"""In-process backend host: runs uvicorn on a background daemon thread of the
same process. A frozen onefile PyInstaller exe has no reliable python.exe to
subprocess, so this is the only startup mechanism that works packaged.
"""

from __future__ import annotations

import asyncio
import logging
import threading

import uvicorn
from fastapi import FastAPI

logger = logging.getLogger(__name__)


class BackendServer:
    def __init__(self, app: FastAPI, host: str = "127.0.0.1", port: int = 8756) -> None:
        self.host = host
        self.port = port
        # loop="asyncio": uvloop ships no Windows wheels, and PyInstaller
        # would otherwise choke trying to bundle/import it on a Windows build.
        config = uvicorn.Config(app, host=host, port=port, log_config=None, loop="asyncio")
        self.server = uvicorn.Server(config)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        # Python 3.10+ no longer auto-creates an event loop on non-main
        # threads, so the thread target must call asyncio.run() explicitly.
        self._thread = threading.Thread(
            target=lambda: asyncio.run(self.server.serve()),
            name="uvicorn-backend",
            daemon=True,
        )
        self._thread.start()

    def request_shutdown(self, timeout: float = 5.0) -> None:
        # should_exit is uvicorn's documented thread-safe cooperative stop
        # flag -- it's polled by the server's own serve loop.
        self.server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Backend thread did not stop within %.1fs", timeout)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
