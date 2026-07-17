"""Pydantic contract shared by the FastAPI backend (as response_models) and the
PySide6 frontend (for parsing responses). Single source of truth for the API
shape so the two sides can never silently drift apart.

No PySide6 and no SQLAlchemy imports belong in this module.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


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
    # Phase 2
    expanded_url: str | None = None
    page_title: str | None = None
    redirect_count: int = 0
    final_status_code: int | None = None
    is_redirect_suspicious: bool = False


class AttachmentIndicator(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    sha256: str | None = None
    is_executable_like: bool = False
    is_double_extension: bool = False
    # Phase 2: VirusTotal hash reputation
    vt_hash_malicious: int = 0
    vt_hash_suspicious: int = 0
    vt_hash_status: str | None = None
    # Phase 3: static attachment analysis flags
    is_macro_enabled: bool = False
    has_embedded_executable: bool = False
    is_archive: bool = False
    mime_magic_mismatch: bool = False
    file_metadata: dict | None = None


class GlobalHashes(BaseModel):
    md5: list[str] = []
    sha1: list[str] = []
    sha256: list[str] = []


class AbuseResult(BaseModel):
    abuse_score: int | None = None
    total_reports: int | None = None
    country_code: str | None = None
    isp: str | None = None


class ShodanResult(BaseModel):
    ip: str | None = None
    hostnames: list[str] = []
    ports: list[int] = []
    vulns: list[str] = []
    tags: list[str] = []
    org: str | None = None
    asn: str | None = None
    country: str | None = None
    city: str | None = None


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
    # Enrichment status per provider — tells the UI exactly why enrichment
    # data is absent so it can show a clear, actionable message.
    # Values: "no_key" | "ok" | "no_data" | "rate_limit" | "error" | None
    vt_enrichment_status: str | None = None
    vt_enrichment_error: str | None = None
    abuse_enrichment_status: str | None = None
    abuse_enrichment_error: str | None = None
    # Phase 1 additions
    mime_parts: list[str] = []
    lure_categories: list[dict] = []
    anchor_mismatches: list[dict] = []
    # Phase 2 additions
    shodan_result: ShodanResult | None = None
    shodan_enrichment_status: str | None = None
    shodan_enrichment_error: str | None = None
    # Phase 5: sandbox
    sandbox_status: str | None = None
    sandbox_provider: str | None = None
    sandbox_verdict: str | None = None
    sandbox_score: int | None = None
    sandbox_report_url: str | None = None
    sandbox_tags: list[str] = []
    sandbox_error: str | None = None


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
    # Phase 1 new signals
    lure_category: int = 2
    anchor_mismatch: int = 3
    # Phase 2/3 new signals
    redirect_suspicious: int = 3
    macro_enabled: int = 4
    embedded_executable: int = 5
    mime_magic_mismatch: int = 3
    vt_hash_malicious_points: int = 5


class SettingsRead(BaseModel):
    scoring: ScoringWeights = ScoringWeights()
    brand_domains: dict[str, list[str]] = {}
    url_suspicious_keywords: list[str] = []
    suspicious_tlds: list[str] = []
    url_shorteners: list[str] = []
    urgency_keywords: list[str] = []
    virustotal_key_configured: bool = False
    abuseipdb_key_configured: bool = False
    shodan_key_configured: bool = False
    sandbox_provider: str | None = None
    sandbox_key_configured: bool = False


class SettingsUpdate(BaseModel):
    # MED-04: size-cap every collection field so a malicious PUT /settings
    # payload cannot store megabytes of data into the single-row SQLite DB.
    # Limits are generous enough for any legitimate use-case while preventing
    # denial-of-service via oversized payloads.
    #
    # Per-item string cap: each keyword/TLD/domain entry is capped at 200 chars.
    # List length cap: no more than 500 entries per list, 100 brand entries.
    scoring: ScoringWeights | None = None
    brand_domains: Annotated[dict[
        Annotated[str, Field(max_length=200)],
        Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=50)]
    ], Field(max_length=100)] | None = None
    url_suspicious_keywords: Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=500)] | None = None
    suspicious_tlds: Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=500)] | None = None
    url_shorteners: Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=500)] | None = None
    urgency_keywords: Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=500)] | None = None
    # Optional API keys — only included when the user actually typed something.
    # None means "leave unchanged"; empty string means "clear the key".
    virustotal_key: str | None = Field(default=None, max_length=255)
    abuseipdb_key: str | None = Field(default=None, max_length=255)
    shodan_key: str | None = Field(default=None, max_length=255)
    # Phase 5: sandbox
    sandbox_provider: str | None = Field(default=None, max_length=64)
    sandbox_api_key: str | None = Field(default=None, max_length=255)


class ApiKeysUpdate(BaseModel):
    virustotal_key: str | None = None
    abuseipdb_key: str | None = None


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
