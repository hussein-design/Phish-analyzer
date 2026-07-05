"""App-data directory resolution shared by the backend and the frontend.

Both sides must agree on where the SQLite database, uploaded .eml originals,
and log files live on disk. A packaged app's install directory is often not
writable (e.g. Program Files without admin rights), so everything mutable
lives under the OS-standard per-user data directory instead.
"""

from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "PhishAnalyzerDesktop"
APP_AUTHOR = "PhishAnalyzer"


@lru_cache(maxsize=1)
def app_data_dir() -> Path:
    """Root directory for all mutable app state (DB, uploads, logs)."""
    path = Path(user_data_dir(APP_NAME, APP_AUTHOR))
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_dir() -> Path:
    path = app_data_dir() / "db"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return db_dir() / "analyzer.sqlite3"


def uploads_dir() -> Path:
    path = app_data_dir() / "uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def analysis_upload_dir(analysis_id: int) -> Path:
    path = uploads_dir() / str(analysis_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = app_data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_file_path() -> Path:
    return logs_dir() / "app.log"


def migrations_dir() -> Path:
    """Location of the Alembic migrations folder in both source and frozen runs."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "migrations"  # type: ignore[attr-defined]
    return project_root() / "migrations"


def alembic_ini_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "alembic.ini"  # type: ignore[attr-defined]
    return project_root() / "alembic.ini"


def assets_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "assets"  # type: ignore[attr-defined]
    return project_root() / "assets"


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent
