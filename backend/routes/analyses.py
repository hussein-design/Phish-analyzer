from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.exceptions import AnalysisNotFoundError
from backend.models.analysis import EmailAnalysis
from backend.repositories.analysis_repository import AnalysisRepository
from backend.routes.deps import get_analysis_service, get_session
from backend.services import report_service
from backend.services.analysis_service import AnalysisService
from shared.schemas import (
    AbuseResult,
    AnalysesListResponse,
    AttachmentIndicator as AttachmentIndicatorSchema,
    AuthResult,
    EmailDetail,
    EmailSummary,
    GlobalHashes,
    HeaderInfo,
    UploadAccepted,
    UrlIndicator as UrlIndicatorSchema,
)

router = APIRouter()


def _to_summary(a: EmailAnalysis) -> EmailSummary:
    return EmailSummary(
        id=a.id,
        filename=a.filename,
        subject=a.subject,
        from_addr=a.from_addr,
        status=a.status,
        verdict=a.verdict,
        score=a.score,
        created_at=a.created_at,
    )


def _to_detail(a: EmailAnalysis) -> EmailDetail:
    return EmailDetail(
        id=a.id,
        filename=a.filename,
        subject=a.subject,
        from_addr=a.from_addr,
        status=a.status,
        verdict=a.verdict,
        score=a.score,
        created_at=a.created_at,
        updated_at=a.updated_at,
        message_id=a.message_id,
        error_message=a.error_message,
        header_info=HeaderInfo(
            from_addr=a.from_addr,
            reply_to=a.reply_to,
            return_path=a.return_path,
            from_domain=a.from_domain,
            reply_domain=a.reply_domain,
            return_domain=a.return_domain,
            sender_ip=a.sender_ip,
            auth=AuthResult(spf=a.spf, dkim=a.dkim, dmarc=a.dmarc),
            auth_headers=a.auth_headers_raw or [],
            issues=a.header_issues or [],
            is_lookalike_domain=a.is_lookalike_domain,
            lookalike_of=a.lookalike_of,
            is_punycode_domain=a.is_punycode_domain,
            is_suspicious_sender_tld=a.is_suspicious_sender_tld,
        ),
        urls=[
            UrlIndicatorSchema(
                url=u.url,
                vt_malicious=u.vt_malicious,
                vt_harmless=u.vt_harmless,
                vt_suspicious=u.vt_suspicious,
                is_suspicious_keyword=u.is_suspicious_keyword,
                is_ip_host=u.is_ip_host,
                is_shortener=u.is_shortener,
                is_suspicious_tld=u.is_suspicious_tld,
                is_punycode=u.is_punycode,
            )
            for u in a.urls
        ],
        attachments=[
            AttachmentIndicatorSchema(
                filename=att.filename,
                content_type=att.content_type,
                sha256=att.sha256,
                is_executable_like=att.is_executable_like,
                is_double_extension=att.is_double_extension,
            )
            for att in a.attachments
        ],
        global_hashes=GlobalHashes(
            **(a.global_hashes or {"md5": [], "sha1": [], "sha256": []})
        ),
        abuse_result=(
            AbuseResult(
                abuse_score=a.abuse_score,
                total_reports=a.abuse_total_reports,
                country_code=a.abuse_country,
                isp=a.abuse_isp,
            )
            if a.abuse_score is not None
            else None
        ),
        reasons=[r.reason_text for r in a.reasons],
        urgency_keywords_found=a.urgency_keywords_found or [],
        body_preview=(a.body_text[:2000] if a.body_text else None),
        vt_enrichment_status=a.vt_enrichment_status,
        vt_enrichment_error=a.vt_enrichment_error,
        abuse_enrichment_status=a.abuse_enrichment_status,
        abuse_enrichment_error=a.abuse_enrichment_error,
    )


@router.post("", response_model=UploadAccepted, status_code=202)
async def upload_email(
    file: UploadFile = File(...),
    service: AnalysisService = Depends(get_analysis_service),
) -> UploadAccepted:
    raw_bytes = await file.read()
    analysis = await service.submit_upload(file.filename or "upload.eml", raw_bytes)
    return UploadAccepted(
        id=analysis.id,
        filename=analysis.filename,
        status=analysis.status,
        created_at=analysis.created_at,
    )


@router.get("", response_model=AnalysesListResponse)
async def list_emails(
    session: AsyncSession = Depends(get_session),
    search: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    verdict: str | None = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> AnalysesListResponse:
    repo = AnalysisRepository(session)
    items, total = await repo.list_paginated(
        page=page,
        page_size=page_size,
        search=search,
        status=status_filter,
        verdict=verdict,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return AnalysesListResponse(
        items=[_to_summary(a) for a in items], total=total, page=page, page_size=page_size
    )


@router.get("/{analysis_id}", response_model=EmailDetail)
async def get_email(
    analysis_id: int, session: AsyncSession = Depends(get_session)
) -> EmailDetail:
    analysis = await AnalysisRepository(session).get_by_id(analysis_id)
    if analysis is None:
        raise AnalysisNotFoundError(f"Analysis {analysis_id} not found")
    return _to_detail(analysis)


@router.delete("", status_code=200)
async def clear_all_analyses(session: AsyncSession = Depends(get_session)) -> dict:
    """Delete every analysis in the database and their stored .eml files."""
    count = await AnalysisRepository(session).delete_all()
    return {"deleted": count}


@router.delete("/{analysis_id}", status_code=204)
async def delete_email(analysis_id: int, session: AsyncSession = Depends(get_session)) -> None:
    repo = AnalysisRepository(session)
    analysis = await repo.get_by_id(analysis_id)
    if analysis is None:
        raise AnalysisNotFoundError(f"Analysis {analysis_id} not found")

    stored_path = analysis.stored_path
    await repo.delete(analysis)

    if stored_path:
        Path(stored_path).unlink(missing_ok=True)


@router.get("/{analysis_id}/report.docx")
async def download_report(
    analysis_id: int, session: AsyncSession = Depends(get_session)
) -> Response:
    analysis = await AnalysisRepository(session).get_by_id(analysis_id)
    if analysis is None:
        raise AnalysisNotFoundError(f"Analysis {analysis_id} not found")

    docx_bytes = report_service.build_docx_report(analysis)
    base_name = analysis.filename.rsplit(".", 1)[0] if analysis.filename else f"analysis-{analysis.id}"
    filename = f"{base_name}.docx"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
