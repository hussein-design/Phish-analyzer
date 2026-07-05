from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


class AppError(Exception):
    """Base class for expected, structured application errors."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    error_code: str = "app_error"

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class InvalidEmlError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    error_code = "invalid_eml"


class AnalysisNotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "analysis_not_found"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "error_code": exc.error_code},
        )
