"""Thin HTTP wrapper around the local FastAPI backend.

Frontend-specific plumbing (not part of shared/): resolves the in-process
backend's base URL, owns a requests.Session, and translates HTTP failures
into an ApiError the toast system understands. Safe to call from inside a
QRunnable worker thread -- it never touches a Qt widget.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


@dataclass
class ApiError(Exception):
    user_message: str
    status_code: int | None = None
    error_code: str | None = None

    def __str__(self) -> str:
        return self.user_message

    @classmethod
    def from_exception(cls, exc: Exception) -> "ApiError":
        if isinstance(exc, requests.HTTPError):
            resp = exc.response
            detail = None
            error_code = None
            if resp is not None:
                try:
                    body = resp.json()
                    detail = body.get("detail")
                    error_code = body.get("error_code")
                except ValueError:
                    detail = resp.text
            status_code = resp.status_code if resp is not None else None
            return cls(
                user_message=detail or f"Request failed ({status_code or 'unknown'})",
                status_code=status_code,
                error_code=error_code,
            )
        if isinstance(exc, requests.ConnectionError):
            return cls(user_message="Could not reach the local backend. Try restarting the app.")
        if isinstance(exc, requests.Timeout):
            return cls(user_message="The request timed out. Please try again.")
        return cls(user_message=str(exc) or exc.__class__.__name__)


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def health(self) -> dict:
        resp = self.session.get(self._url("/health"), timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def upload_email(self, file_path: str) -> dict:
        path = Path(file_path)
        with path.open("rb") as f:
            files = {"file": (path.name, f, "message/rfc822")}
            resp = self.session.post(self._url("/analyses"), files=files, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def list_emails(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        search: str | None = None,
        status: str | None = None,
        verdict: str | None = None,
        sort_by: str = "created_at",
        sort_dir: str = "desc",
    ) -> dict:
        params: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_dir": sort_dir,
        }
        if search:
            params["search"] = search
        if status:
            params["status"] = status
        if verdict:
            params["verdict"] = verdict
        resp = self.session.get(self._url("/analyses"), params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_email(self, analysis_id: int) -> dict:
        resp = self.session.get(self._url(f"/analyses/{analysis_id}"), timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def delete_email(self, analysis_id: int) -> None:
        resp = self.session.delete(self._url(f"/analyses/{analysis_id}"), timeout=self.timeout)
        resp.raise_for_status()

    def download_report(self, analysis_id: int, dest_path: str) -> str:
        resp = self.session.get(
            self._url(f"/analyses/{analysis_id}/report.docx"), timeout=self.timeout
        )
        resp.raise_for_status()
        Path(dest_path).write_bytes(resp.content)
        return dest_path

    def get_settings(self) -> dict:
        resp = self.session.get(self._url("/settings"), timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def update_settings(self, payload: dict) -> dict:
        resp = self.session.put(self._url("/settings"), json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def update_keys(self, payload: dict) -> None:
        resp = self.session.put(self._url("/settings/keys"), json=payload, timeout=self.timeout)
        resp.raise_for_status()
