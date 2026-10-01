"""Phase 3 BEC (Business Email Compromise) signal detection service.

BEC emails typically have NO malicious link or attachment — static and dynamic
analysis will correctly return near-zero signal on them.  This service detects
social-engineering and impersonation patterns that are invisible to content
scanners.

SIGNALS
-------
1. vip_impersonation
   The From display name or sending address closely resembles a VIP/protected
   identity in the vip_identities table, but the actual sending domain does NOT
   match that person's protected_domain.  DB-backed — admins populate the VIP
   list, not hardcoded.

2. financial_request_language
   Body text contains patterns associated with BEC wire-transfer fraud.
   Organised into FIVE pattern categories (see _FINANCIAL_PATTERN_CATEGORIES
   below).  Each category that fires contributes independently.
   !! FALSE-POSITIVE RISK !!
   Legitimate urgent payment emails from finance teams will trigger this signal.
   This is a known, managed limitation — see the module docstring below and the
   README for mitigation guidance (primarily: keep the VIP list accurate so
   real finance-team senders don't also trigger vip_impersonation).

3. vendor_fraud_pattern
   Bank-detail-change language combined with a sender that does NOT appear in
   prior thread or sender history for this recipient — the classic "vendor
   impersonation / payment diversion" pattern.  Reuses Phase 2's
   sender_history and thread_history tables including the In-Reply-To-aware
   thread matching.

4. authority_pressure_combo
   A multiplier/flag that fires when financial_request_language AND at least
   one identity signal (vip_impersonation OR first_time_sender from Phase 2)
   co-occur.  This is the core BEC pattern: financial ask + authority/identity
   pressure together.  Signal is scored additively on top of the other signals,
   not instead of them — it reflects that the combination is more dangerous
   than the sum of its parts.

POINT VALUES (bec_score weighting)
-----------------------------------
  vip_impersonation:         4  (strong — direct identity fraud)
  financial_request_language: varies by category count (2 per category, max
                               capped at BEC_FINANCIAL_MAX_PTS = 6 to avoid
                               runaway scoring on verbose emails)
  vendor_fraud_pattern:      3  (strong — payment diversion indicator)
  authority_pressure_combo:  3  (additive — co-occurrence multiplier)

These weights can be overridden via scoring_weights dict.

FALSE-POSITIVE DOCUMENTATION
-----------------------------
financial_request_language is the signal most likely to false-positive on
legitimate emails.  Known cases:
  - CFO asking a supplier to confirm wire transfer details
  - Finance team circulating a payment approval for an invoice
  - IT team asking a vendor to update banking details after a legitimate
    account change
  - Executive asking team to purchase gift cards for a legitimate incentive
    programme

MITIGATIONS (not code-enforced — user responsibility):
  - Add finance team and executive real email addresses to the VIP list.
    Their legitimate emails will still trigger financial_request_language,
    but will NOT trigger vip_impersonation (since their real domain matches),
    so authority_pressure_combo will not fire, keeping the bec_score lower.
  - The verdict-merge formula uses a BEC_SUSPICIOUS_FLOOR threshold (default 4)
    so a single financial_request_language hit (score 2) on its own does not
    change the verdict — it needs to combine with at least one other signal.
  - Analysts are expected to use behavioral_score and bec_score as context for
    investigation, not as automated block/quarantine decisions.

FINANCIAL PATTERN CATEGORIES (all keyword-based, case-insensitive)
--------------------------------------------------------------------
Category 1 — WIRE_TRANSFER: explicit fund-movement vocabulary
Category 2 — BANK_DETAIL_CHANGE: account/routing number change requests
Category 3 — URGENCY_AUTHORITY: executive-pressure and secrecy framing
Category 4 — GIFT_CARD: gift card purchase patterns (common low-level BEC)
Category 5 — INVOICE_REDIRECT: invoice or payment redirect to new account

All categories are listed explicitly in _FINANCIAL_PATTERN_CATEGORIES below
so they can be reviewed, tuned, or extended without code changes to the
detection logic.
"""

from __future__ import annotations

import logging
import os
import re
from typing import NamedTuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default

# Minimum bec_score to force verdict to at least "suspicious" even when
# static+dynamic+behavioral combined_score is below the threshold.
# Default 4 means at least financial_request_language (2 pts) + one other
# signal must fire.  Setting to 0 disables the floor.
BEC_SUSPICIOUS_FLOOR: int = _int_env("BEC_SUSPICIOUS_FLOOR", 4)

# Maximum points financial_request_language can contribute (caps runaway
# scoring on emails that happen to use many financial keywords).
BEC_FINANCIAL_MAX_PTS: int = _int_env("BEC_FINANCIAL_MAX_PTS", 6)

# Points per signal
_PTS_VIP_IMPERSONATION     = 4
_PTS_FINANCIAL_PER_CATEGORY = 2   # per fired category; capped at BEC_FINANCIAL_MAX_PTS
_PTS_VENDOR_FRAUD          = 3
_PTS_AUTHORITY_PRESSURE    = 3


# ── Financial pattern categories ───────────────────────────────────────────────
# Each entry is (category_name, [keyword_or_phrase, ...]).
# Detection is case-insensitive substring match over the full body text.
# !! FALSE-POSITIVE RISK — see module docstring !!

_FINANCIAL_PATTERN_CATEGORIES: list[tuple[str, list[str]]] = [
    (
        "wire_transfer",
        [
            "wire transfer", "wire the funds", "wire payment", "wire $",
            "initiate a transfer", "initiate the transfer", "transfer the funds",
            "international transfer", "ach transfer", "swift transfer",
            "telegraphic transfer", "funds transfer", "transfer funds",
            "send the money", "remit payment", "remit the amount",
            "same-day transfer", "urgent transfer", "immediate transfer",
        ],
    ),
    (
        "bank_detail_change",
        [
            "new bank account", "new account details", "new banking details",
            "updated bank", "updated account", "changed bank", "change our bank",
            "new routing number", "new account number", "account number has changed",
            "banking information has changed", "new payment details",
            "please update your records", "update your payment",
            "use the following account", "use these bank details",
            "our bank details have", "payment should be made to",
        ],
    ),
    (
        "urgency_authority",
        [
            "strictly confidential", "do not discuss", "do not share",
            "between us only", "keep this between", "personal request",
            "direct request", "acting on behalf of the ceo",
            "on behalf of the president", "on behalf of our ceo",
            "approved by the board", "board has approved",
            "this is time sensitive", "needs to be done today",
            "needs to happen today", "before end of business",
            "by close of business", "eod today", "no later than today",
            "do not reply to this email", "call me directly",
        ],
    ),
    (
        "gift_card",
        [
            "gift card", "gift cards", "itunes card", "google play card",
            "amazon gift card", "steam gift card", "buy gift cards",
            "purchase gift cards", "send me the codes", "scratch the back",
            "redemption code", "card number and pin",
        ],
    ),
    (
        "invoice_redirect",
        [
            "new invoice", "revised invoice", "updated invoice",
            "please process this invoice", "process the attached invoice",
            "payment for invoice", "settle this invoice",
            "redirect this payment", "send payment to",
            "please use new account for future payments",
            "future invoices should be", "upcoming payments should go to",
            "we have changed our bank", "effective immediately",
        ],
    ),
]

# Pre-compile patterns for performance
_COMPILED_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    (cat, [re.compile(re.escape(kw), re.IGNORECASE) for kw in keywords])
    for cat, keywords in _FINANCIAL_PATTERN_CATEGORIES
]


# ── Result type ────────────────────────────────────────────────────────────────

class BecResult(NamedTuple):
    bec_score: int
    bec_reasons: list[str]
    sig_vip_impersonation: bool | None
    sig_financial_request: bool | None
    sig_vendor_fraud: bool | None
    sig_authority_pressure: bool | None


# ── Signal 1: vip_impersonation ───────────────────────────────────────────────

async def _check_vip_impersonation(
    session: AsyncSession,
    from_addr: str | None,
    from_domain: str | None,
) -> tuple[bool, str | None]:
    """Return (fired, reason_string).

    Loads active VIP entries and checks whether:
    a) The bare From email address exactly matches a protected_email, but the
       sending domain doesn't match — catches account-spoofing.
    b) The From display name contains a VIP's name (case-insensitive substring),
       and the sending domain is NOT protected_domain for that VIP.

    Returns (False, None) if no VIP entries exist (empty table = disabled).
    """
    from backend.models.vip_identity import VIPIdentity

    if not from_addr:
        return False, None

    # Normalise inputs
    display_lower = from_addr.lower()
    # Extract bare address
    import re as _re
    m = _re_addr.search(from_addr)
    bare_addr = m.group(1).lower() if m else from_addr.lower()
    sending_domain = (from_domain or "").lower()

    try:
        result = await session.execute(
            select(VIPIdentity).where(VIPIdentity.is_active == True)  # noqa: E712
        )
        vips = result.scalars().all()
    except Exception as exc:
        logger.warning("bec: vip_impersonation DB query failed: %s", type(exc).__name__)
        return False, None

    if not vips:
        return False, None

    for vip in vips:
        prot_domain = (vip.protected_domain or "").lower()
        prot_email  = (vip.protected_email or "").lower()
        vip_name    = (vip.name or "").lower()

        # Is the sending domain already legitimate for this VIP? Skip.
        if sending_domain and (
            sending_domain == prot_domain
            or sending_domain.endswith("." + prot_domain)
        ):
            continue

        # Check a: exact email address match (someone spoofing the address)
        if prot_email and bare_addr == prot_email:
            reason = (
                f"VIP impersonation: sender address '{bare_addr}' matches protected "
                f"identity '{vip.name}' ({vip.title or 'VIP'}) but sending domain "
                f"'{sending_domain}' ≠ legitimate domain '{prot_domain}'"
            )
            return True, reason

        # Check b: VIP name appears in the display portion of From
        if vip_name and len(vip_name) >= 3:
            # Build a normalised version of the display for matching
            # (remove punctuation, collapse spaces)
            display_norm = re.sub(r"[^a-z0-9 ]", " ", display_lower)
            name_norm    = re.sub(r"[^a-z0-9 ]", " ", vip_name)
            # All words of the VIP name must appear in the display
            name_words = name_norm.split()
            if name_words and all(w in display_norm for w in name_words):
                reason = (
                    f"VIP impersonation: From display name matches protected identity "
                    f"'{vip.name}' ({vip.title or 'VIP'}) but sending domain "
                    f"'{sending_domain}' ≠ legitimate domain '{prot_domain}'"
                )
                return True, reason

    return False, None


_re_addr = re.compile(r"<([^>]+)>")


# ── Signal 2: financial_request_language ──────────────────────────────────────

def _check_financial_request_language(
    body_text: str,
    max_pts: int = BEC_FINANCIAL_MAX_PTS,
) -> tuple[bool, list[str], list[str]]:
    """Return (fired, fired_categories, reason_strings).

    Scans body_text for each of the five financial pattern categories.
    Each category that fires contributes _PTS_FINANCIAL_PER_CATEGORY up to
    max_pts total.

    !! FALSE-POSITIVE RISK !!
    Legitimate urgent payment emails will trigger this signal.  See module
    docstring for mitigation guidance and the README for user documentation.
    """
    if not body_text:
        return False, [], []

    fired_categories: list[str] = []
    reasons: list[str] = []
    lower = body_text.lower()

    for cat_name, patterns in _COMPILED_PATTERNS:
        hit_keywords: list[str] = []
        for pattern in patterns:
            m = pattern.search(lower)
            if m:
                hit_keywords.append(m.group(0))
        if hit_keywords:
            fired_categories.append(cat_name)
            reasons.append(
                f"BEC financial pattern '{cat_name.replace('_', ' ')}' — "
                f"keywords: {', '.join(hit_keywords[:3])}"
                + (" …" if len(hit_keywords) > 3 else "")
            )

    return bool(fired_categories), fired_categories, reasons


# ── Signal 3: vendor_fraud_pattern ────────────────────────────────────────────

async def _check_vendor_fraud_pattern(
    session: AsyncSession,
    recipient: str,
    sender: str,
    subject: str | None,
    in_reply_to: str | None,
    message_id: str | None,
    financial_fired: bool,
) -> tuple[bool, str | None]:
    """Return (fired, reason_string).

    Bank-detail-change language (financial_fired) combined with a sender who
    does NOT appear in prior sender_history or thread_history for this
    recipient.  Uses Phase 2's In-Reply-To-aware thread matching.

    Rationale: a known vendor asking to update bank details is suspicious but
    plausible; an UNKNOWN sender asking to update bank details is a strong
    vendor-fraud signal.
    """
    if not financial_fired:
        return False, None

    from backend.models.sender_history import SenderHistory
    from backend.models.thread_history import ThreadHistory

    try:
        # Check sender history: has this sender ever contacted this recipient?
        any_history = await session.scalar(
            select(SenderHistory.id)
            .where(SenderHistory.recipient == recipient)
            .limit(1)
        )
        if any_history is None:
            # Cold start — cannot determine; return neutral
            return False, None

        sender_known = await session.scalar(
            select(SenderHistory.id)
            .where(
                SenderHistory.recipient == recipient,
                SenderHistory.sender == sender,
            )
            .limit(1)
        )

        if sender_known is not None:
            # Sender is known — not a vendor fraud pattern by itself
            return False, None

        # Sender is unknown — check if this looks like a reply to an existing thread
        from backend.services.behavioral_signals_service import (
            _normalize_thread_key, _is_reply_or_forward
        )
        thread_known = False
        if _is_reply_or_forward(subject):
            thread_key = _normalize_thread_key(subject)
            if thread_key:
                result = await session.execute(
                    select(ThreadHistory.message_id)
                    .where(
                        ThreadHistory.recipient == recipient,
                        ThreadHistory.thread_key == thread_key,
                    )
                )
                rows = result.scalars().all()
                # In-Reply-To tiebreaker: if In-Reply-To matches a known message,
                # this is a legitimate continuation — not vendor fraud.
                # rows is a list[str | None] from .scalars().all() — membership
                # test against the string in_reply_to is correct.
                if rows and in_reply_to and in_reply_to in rows:
                    return False, None
                if rows:
                    thread_known = True

        reason = (
            f"Vendor fraud pattern: financial/bank-detail language from an unknown "
            f"sender '{sender}' to '{recipient}'"
            + (" hijacking an existing thread" if thread_known else "")
        )
        return True, reason

    except Exception as exc:
        logger.warning("bec: vendor_fraud_pattern check failed: %s", type(exc).__name__)
        return False, None


# ── Signal 4: authority_pressure_combo ────────────────────────────────────────

def _check_authority_pressure_combo(
    financial_fired: bool,
    vip_impersonation_fired: bool,
    first_time_sender: bool | None,
) -> tuple[bool, str | None]:
    """Return (fired, reason_string).

    Fires when financial_request_language AND at least one identity/authority
    signal co-occur:
      - vip_impersonation (someone pretending to be an executive)
      - first_time_sender from Phase 2 (unknown sender demanding money)

    This combination is the textbook BEC pattern.  Points are additive on top
    of the individual signals, not instead of them.
    """
    if not financial_fired:
        return False, None

    identity_signals: list[str] = []
    if vip_impersonation_fired:
        identity_signals.append("VIP impersonation")
    if first_time_sender is True:
        identity_signals.append("first-time sender")

    if not identity_signals:
        return False, None

    reason = (
        f"Authority-pressure combination: financial request language co-occurs with "
        f"{' and '.join(identity_signals)} — core BEC pattern"
    )
    return True, reason


# ── Main entry point ───────────────────────────────────────────────────────────

async def compute_bec_signals(
    *,
    session: AsyncSession,
    from_addr: str | None,
    from_domain: str | None,
    subject: str | None,
    message_id: str | None,
    in_reply_to: str | None = None,
    body_text: str,
    recipient: str,
    # Phase 2 behavioral result (needed for first_time_sender)
    first_time_sender: bool | None = None,
    scoring_weights: dict | None = None,
) -> BecResult:
    """Compute all four BEC signals for the given email.

    Parameters
    ----------
    session:
        Active async SQLAlchemy session (read-only within this call).
    from_addr, from_domain:
        From header values.
    subject, message_id, in_reply_to:
        For thread-aware vendor_fraud_pattern check.
    body_text:
        Plain-text email body for financial pattern detection.
    recipient:
        Normalised recipient address — used for history lookups.
    first_time_sender:
        Value of the Phase 2 behavioral signal (True/False/None).
        Passed in rather than re-computed to avoid a duplicate DB query.
    scoring_weights:
        Optional overrides for signal point values.
    """
    w = scoring_weights or {}
    pts_vip         = w.get("bec_vip_impersonation",     _PTS_VIP_IMPERSONATION)
    pts_fin_cat     = w.get("bec_financial_per_category", _PTS_FINANCIAL_PER_CATEGORY)
    pts_vendor      = w.get("bec_vendor_fraud",           _PTS_VENDOR_FRAUD)
    pts_authority   = w.get("bec_authority_pressure",     _PTS_AUTHORITY_PRESSURE)
    fin_max         = w.get("bec_financial_max_pts",       BEC_FINANCIAL_MAX_PTS)

    # Normalise sender for history lookups
    from backend.services.behavioral_signals_service import _normalize_addr
    sender = _normalize_addr(from_addr)
    recipient_norm = recipient.strip().lower()

    bec_score = 0
    bec_reasons: list[str] = []

    # ── Signal 1: vip_impersonation ───────────────────────────────────────
    sig_vip: bool | None = False
    try:
        sig_vip, vip_reason = await _check_vip_impersonation(
            session, from_addr, from_domain
        )
        if sig_vip and vip_reason:
            bec_score += pts_vip
            bec_reasons.append(vip_reason)
    except Exception as exc:
        logger.warning("bec: vip_impersonation failed: %s", type(exc).__name__)
        sig_vip = None

    # ── Signal 2: financial_request_language ─────────────────────────────
    sig_financial: bool | None = False
    financial_fired = False
    try:
        sig_financial, fired_cats, fin_reasons = _check_financial_request_language(
            body_text, max_pts=fin_max
        )
        financial_fired = sig_financial
        if sig_financial:
            cat_pts = min(len(fired_cats) * pts_fin_cat, fin_max)
            bec_score += cat_pts
            bec_reasons.extend(fin_reasons)
    except Exception as exc:
        logger.warning("bec: financial_request_language failed: %s", type(exc).__name__)
        sig_financial = None

    # ── Signal 3: vendor_fraud_pattern ───────────────────────────────────
    sig_vendor: bool | None = False
    try:
        sig_vendor, vendor_reason = await _check_vendor_fraud_pattern(
            session,
            recipient=recipient_norm,
            sender=sender,
            subject=subject,
            in_reply_to=in_reply_to,
            message_id=message_id,
            financial_fired=financial_fired,
        )
        if sig_vendor and vendor_reason:
            bec_score += pts_vendor
            bec_reasons.append(vendor_reason)
    except Exception as exc:
        logger.warning("bec: vendor_fraud_pattern failed: %s", type(exc).__name__)
        sig_vendor = None

    # ── Signal 4: authority_pressure_combo ───────────────────────────────
    sig_authority: bool | None = False
    try:
        sig_authority, auth_reason = _check_authority_pressure_combo(
            financial_fired=financial_fired,
            vip_impersonation_fired=bool(sig_vip),
            first_time_sender=first_time_sender,
        )
        if sig_authority and auth_reason:
            bec_score += pts_authority
            bec_reasons.append(auth_reason)
    except Exception as exc:
        logger.warning("bec: authority_pressure_combo failed: %s", type(exc).__name__)
        sig_authority = None

    return BecResult(
        bec_score=bec_score,
        bec_reasons=bec_reasons,
        sig_vip_impersonation=sig_vip,
        sig_financial_request=sig_financial,
        sig_vendor_fraud=sig_vendor,
        sig_authority_pressure=sig_authority,
    )
