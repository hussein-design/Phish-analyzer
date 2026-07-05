"""Pydantic contract shared by the FastAPI backend (as response_models) and the
PySide6 frontend (for parsing responses). Single source of truth for the API
shape so the two sides can never silently drift apart.

No PySide6 and no SQLAlchemy imports belong in this module.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class AnalysisStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class Verdict(str, Enum):
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class AuthResult(BaseModel):
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


class HeaderInfo(BaseModel):
    from_addr: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    from_domain: str | None = None
    reply_domain: str | None = None
    return_domain: str | None = None
    sender_ip: str | None = None
    auth: AuthResult = AuthResult()
    auth_headers: list[str] = []
    issues: list[str] = []
    is_lookalike_domain: bool = False
    lookalike_of: str | None = None
    is_punycode_domain: bool = False
    is_suspicious_sender_tld: bool = False


class UrlIndicator(BaseModel):
    url: str
    vt_malicious: int = 0
    vt_harmless: int = 0
    vt_suspicious: int = 0
    is_suspicious_keyword: bool = False
    is_ip_host: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    is_punycode: bool = False


class AttachmentIndicator(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    sha256: str | None = None
    is_executable_like: bool = False
    is_double_extension: bool = False


class GlobalHashes(BaseModel):
    md5: list[str] = []
    sha1: list[str] = []
    sha256: list[str] = []


class AbuseResult(BaseModel):
    abuse_score: int | None = None
    total_reports: int | None = None
    country_code: str | None = None
    isp: str | None = None


class EmailSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    subject: str | None = None
    from_addr: str | None = None
    status: AnalysisStatus
    verdict: Verdict | None = None
    score: int | None = None
    created_at: datetime


class EmailDetail(EmailSummary):
    message_id: str | None = None
    error_message: str | None = None
    header_info: HeaderInfo = HeaderInfo()
    urls: list[UrlIndicator] = []
    attachments: list[AttachmentIndicator] = []
    global_hashes: GlobalHashes = GlobalHashes()
    abuse_result: AbuseResult | None = None
    reasons: list[str] = []
    urgency_keywords_found: list[str] = []
    body_preview: str | None = None
    updated_at: datetime


class UploadAccepted(BaseModel):
    id: int
    filename: str
    status: AnalysisStatus
    created_at: datetime


class AnalysesListResponse(BaseModel):
    items: list[EmailSummary]
    total: int
    page: int
    page_size: int


class ScoringWeights(BaseModel):
    brand_mismatch: int = 2
    spf_fail: int = 2
    dkim_fail: int = 2
    dmarc_fail: int = 2
    header_issue: int = 1
    url_bad_keyword: int = 2
    url_ip_host: int = 3
    attachment_executable: int = 3
    vt_malicious_threshold: int = 3
    vt_malicious_points: int = 4
    abuseipdb_high_score: int = 50
    abuseipdb_points: int = 3
    brand_domain_lookalike: int = 3
    brand_domain_lookalike_threshold: int = 82  # similarity %, not points
    suspicious_tld: int = 2
    punycode_domain: int = 3
    url_shortener: int = 1
    attachment_double_extension: int = 4
    body_urgency_keyword: int = 1


class SettingsRead(BaseModel):
    scoring: ScoringWeights = ScoringWeights()
    brand_domains: dict[str, list[str]] = {}
    url_suspicious_keywords: list[str] = []
    suspicious_tlds: list[str] = []
    url_shorteners: list[str] = []
    urgency_keywords: list[str] = []
    virustotal_key_configured: bool = False
    abuseipdb_key_configured: bool = False


class SettingsUpdate(BaseModel):
    scoring: ScoringWeights | None = None
    brand_domains: dict[str, list[str]] | None = None
    url_suspicious_keywords: list[str] | None = None
    suspicious_tlds: list[str] | None = None
    url_shorteners: list[str] | None = None
    urgency_keywords: list[str] | None = None


class ApiKeysUpdate(BaseModel):
    virustotal_key: str | None = None
    abuseipdb_key: str | None = None


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
