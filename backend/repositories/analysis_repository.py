"""Pure DB access for EmailAnalysis and its child rows.

No business/scoring logic lives here -- that belongs in services/. This
layer only knows how to build queries and persist the ORM graph handed to it.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.analysis import EmailAnalysis

SORTABLE_COLUMNS = {
    "created_at": EmailAnalysis.created_at,
    "score": EmailAnalysis.score,
    "verdict": EmailAnalysis.verdict,
    "filename": EmailAnalysis.filename,
}


class AnalysisRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_pending(self, *, filename: str, stored_path: str) -> EmailAnalysis:
        analysis = EmailAnalysis(filename=filename, stored_path=stored_path, status="PENDING")
        self.session.add(analysis)
        await self.session.commit()
        await self.session.refresh(analysis)
        return analysis

    async def get_by_id(self, analysis_id: int) -> EmailAnalysis | None:
        return await self.session.get(EmailAnalysis, analysis_id)

    async def save(self, analysis: EmailAnalysis) -> EmailAnalysis:
        self.session.add(analysis)
        await self.session.commit()
        await self.session.refresh(analysis)
        return analysis

    async def delete(self, analysis: EmailAnalysis) -> None:
        await self.session.delete(analysis)
        await self.session.commit()

    async def list_paginated(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
        verdict: str | None = None,
        sort_by: str = "created_at",
        sort_dir: str = "desc",
    ) -> tuple[list[EmailAnalysis], int]:
        stmt = select(EmailAnalysis)
        count_stmt = select(func.count()).select_from(EmailAnalysis)

        if search:
            like = f"%{search}%"
            condition = (
                EmailAnalysis.filename.ilike(like)
                | EmailAnalysis.subject.ilike(like)
                | EmailAnalysis.from_addr.ilike(like)
            )
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)
        if status:
            stmt = stmt.where(EmailAnalysis.status == status)
            count_stmt = count_stmt.where(EmailAnalysis.status == status)
        if verdict:
            stmt = stmt.where(EmailAnalysis.verdict == verdict)
            count_stmt = count_stmt.where(EmailAnalysis.verdict == verdict)

        column = SORTABLE_COLUMNS.get(sort_by, EmailAnalysis.created_at)
        stmt = stmt.order_by(column.desc() if sort_dir == "desc" else column.asc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        total = (await self.session.execute(count_stmt)).scalar_one()
        items = (await self.session.execute(stmt)).scalars().all()
        return list(items), total
