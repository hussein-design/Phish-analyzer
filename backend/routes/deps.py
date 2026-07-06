from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.analysis_service import AnalysisService

logger = logging.getLogger(__name__)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            # Roll back any uncommitted transaction so the connection is
            # returned to the pool in a clean state.  Without this, a route
            # handler that raises after a partial write could leave the
            # session in a broken state for the next request on the same
            # connection.
            await session.rollback()
            raise


def get_analysis_service(request: Request) -> AnalysisService:
    return request.app.state.analysis_service
