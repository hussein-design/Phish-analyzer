"""Environment-sourced configuration.

VT_API_KEY / ABUSEIPDB_API_KEY here are first-run SEED defaults only. Once
the app has run once, the live, GUI-editable source of truth for both keys
(and for scoring weights) is the single-row app_settings DB table -- a
desktop user has no workflow for "edit an env var and restart the app."
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from shared.paths import db_path, dotenv_path


class AppSettings(BaseSettings):
    # Must be an absolute path (see shared.paths.dotenv_path docstring) --
    # a bare ".env" resolves against the process cwd, not the project root,
    # and silently finds nothing if launched from anywhere else.
    model_config = SettingsConfigDict(
        env_file=str(dotenv_path()), env_file_encoding="utf-8", extra="ignore"
    )

    app_host: str = "127.0.0.1"
    app_port: int = 8756
    log_level: str = "INFO"

    database_url: str | None = None

    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    def async_database_url(self) -> str:
        return self.database_url or f"sqlite+aiosqlite:///{db_path()}"

    def sync_database_url(self) -> str:
        if self.database_url:
            return self.database_url.replace("+aiosqlite", "")
        return f"sqlite:///{db_path()}"


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()
