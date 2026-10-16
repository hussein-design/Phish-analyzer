"""Logging configuration for the Phish Analyzer backend.

Problem fixed here
──────────────────
``uvicorn`` attaches its own ``StreamHandler`` to the root logger *before*
``create_app()`` calls ``configure_logging()``.  The old guard

    if root.handlers:
        return

caused ``configure_logging`` to return immediately, so the
``RotatingFileHandler`` was never added.  Every log line then went only to
uvicorn's console handler and nothing was written to the log file.

Fix: check whether a ``RotatingFileHandler`` pointing at our target path is
already present instead of checking for *any* handlers.  If it isn't, add it.
The console handler is added with the same guard so a second call from a
re-entrant lifespan (in tests) doesn't duplicate console output.

Log file location
─────────────────
The file handler writes to ``shared.paths.log_file_path()``:

    • Development:  %LOCALAPPDATA%\\PhishAnalyzer\\PhishAnalyzerDesktop\\logs\\app.log
    • Frozen EXE:   Same path — ``paths.py`` uses ``platformdirs`` which
                    resolves the correct user-data directory whether running
                    from source or as a PyInstaller onedir bundle.
                    The path is intentionally *not* next to the executable so
                    logs survive app reinstalls and don't require admin rights.

Confirming it works in the frozen EXE
─────────────────────────────────────
``_icons_dir()``, ``db_path()``, and ``log_file_path()`` in ``shared/paths.py``
all use ``sys.frozen`` to detect the PyInstaller bundle and switch to
``sys._MEIPASS`` or ``Path(sys.executable).parent`` as appropriate.  The log
path is ``app_data_dir() / 'logs' / 'app.log'`` where ``app_data_dir()``
calls ``platformdirs.user_data_dir()``.  Both in-source and frozen builds
resolve the same user-data directory, so the file handler attaches and writes
to the same location in both cases.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from shared.paths import log_file_path


def configure_logging(level: str = "INFO") -> None:
    """Attach a RotatingFileHandler (and optionally a StreamHandler) to the
    root logger.

    Safe to call multiple times — each handler is only added once.  The check
    is based on the *type and target path* of the file handler, not on the
    mere presence of *any* handler, so this survives uvicorn pre-attaching its
    own StreamHandler before ``create_app()`` runs.
    """
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    target_path = str(log_file_path())

    # ── File handler ──────────────────────────────────────────────────────────
    # Add only if no RotatingFileHandler for our target path already exists.
    _has_file_handler = any(
        isinstance(h, RotatingFileHandler)
        and getattr(h, "baseFilename", None) == target_path
        for h in root.handlers
    )
    if not _has_file_handler:
        file_handler = RotatingFileHandler(
            target_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
        # Emit a sentinel line so we can verify the file handler is wired up
        # even when the app starts cleanly with no warnings to log.
        logging.getLogger(__name__).info(
            "File logging initialised → %s", target_path
        )

    # ── Console handler ───────────────────────────────────────────────────────
    # Add a StreamHandler only if none exists yet (uvicorn may have added one).
    _has_stream_handler = any(
        type(h) is logging.StreamHandler  # exact type — RotatingFileHandler is a subclass
        for h in root.handlers
    )
    if not _has_stream_handler:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(fmt)
        root.addHandler(console_handler)
