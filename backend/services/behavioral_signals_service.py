"""Phase 2 behavioral analysis service.

Computes five independent behavioral signals for a single email, drawing on
persistent sender/recipient history (sender_history, thread_history tables)
and an async WHOIS/RDAP domain-age lookup (cached via the existing
EnrichmentCache with namespace="domain_age").

SIGNALS
-------
1. first_time_sender
   True if this (recipient, sender) pair has never been seen before.
   Cold-start: always False when recipient history is entirely absent
   (the very first email analyzed for a given recipient mailbox). This is
   conservative — we prefer to miss the first genuinely suspicious email
   rather than raise an alert on every email to a fresh mailbox.

2. domain_age_anomaly
   True if the sender's domain was registered within
   BEHAVIORAL_DOMAIN_AGE_THRESHOLD_DAYS (default 30) before the email was
   sent.  Requires a successful RDAP/WHOIS lookup; fails gracefully
   (signal=False) if the lookup fails, times out, or returns no data.
   Uses enrichment_cache with namespace="domain_age", TTL=2592000 s (30 days)
   — domain registration dates are immutable facts so a 30-day cache is safe.

3. display_name_mismatch
   True if the email's From display name contains a brand token (e.g.
   "PayPal Support") but the sending domain does not belong to that brand.
   Reuses threat_signals.find_lookalike_domain() and brand_domains config —
   no new logic.  Also checks the simpler brand-impersonation pattern from
   scoring_service (brand name in display, domain not in legit list).

4. reply_chain_break
   True if the subject begins with Re:/Fwd: but neither the sender nor the
   message-ID matches any prior message in the thread_history for that
   (recipient, thread_key) pair.  Only fires when thread history for this
   thread_key exists; returns False (neutral) when the thread has no history.

5. send_time_anomaly
   True if the email was sent at an hour significantly outside this sender's
   historical pattern.  Only fires when message_count >= BEHAVIORAL_MIN_SEND_HISTORY
   (default 5) for the (recipient, sender) pair; returns False below the
   threshold rather than producing false positives on thin data.
   "Significantly outside" means the send hour does not appear in any send
   window defined by a clustering of the historical hours, with a
   BEHAVIORAL_SEND_TIME_TOLERANCE_HOURS (default 2 hours) tolerance on either
   side of any historically observed hour.

CONFIGURATION (via environment variables — see .env.example)
-------------------------------------------------------------
BEHAVIORAL_DOMAIN_AGE_THRESHOLD_DAYS  int, default 30
    Flag domains registered within this many days before the email was sent.

BEHAVIORAL_MIN_SEND_HISTORY           int, default 5
    Minimum number of prior emails from a (recipient, sender) pair before
    send_time_anomaly activates.  Below this threshold, send_time_anomaly
    always returns False (neutral — not enough data, no false positive).

BEHAVIORAL_SEND_TIME_TOLERANCE_HOURS  int, default 2
    Tolerance in hours around each historically observed send hour.  A send
    hour is considered "normal" if it falls within ±tolerance of any hour
    in the sender's history.  Set to 0 for exact-match only.

BEHAVIORAL_MAX_SEND_HOURS             int, default 200
    Hard cap on the number of send-hour samples stored per (recipient, sender)
    pair.  Prevents unbounded row growth for long-term senders.  Oldest
    entries are dropped when the cap is reached (FIFO).

COLD-START POLICY
-----------------
A "cold start" is any state where the sender_history table has no rows for
a given recipient mailbox.  In this state:
  - first_time_sender: False (we cannot distinguish "new to this mailbox" from
    "this is the first email ever analyzed for this mailbox")
  - reply_chain_break: False (no thread history to compare against)
  - send_time_anomaly: False (below BEHAVIORAL_MIN_SEND_HISTORY by definition)
  - display_name_mismatch and domain_age_anomaly: still computed (they don't
    depend on history)

The rationale: raising behavioral alerts on a fresh install would cause every
initial email to score as suspicious until history accumulates.  Since
display_name_mismatch and domain_age_anomaly are computed from the email itself
(not from history), they can fire immediately.

HISTORY UPDATE POLICY
---------------------
History is recorded AFTER scoring so that the current email's data is available
for future emails but does not inflate its own scores.  Callers must call
record_observation() once after scoring completes.

POINT VALUES (behavioral_score weighting)
-----------------------------------------
  first_time_sender:       1  (weak — legitimate first contacts happen all the time)
  domain_age_anomaly:      3  (strong — very new domains are a reliable BEC signal)
  display_name_mismatch:   2  (moderate — catches brand impersonation)
  reply_chain_break:       3  (strong — hijacked thread is a key BEC pattern)
  send_time_anomaly:       1  (weak — sender timezone differences cause false positives;
                                value increases once more history accumulates)

These weights can be overridden via scoring_weights if that dict ever gains
behavioral keys.  Current implementation uses the defaults above.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import NamedTuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── Configuration (env-sourced, with safe defaults) ───────────────────────────

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default


DOMAIN_AGE_TTL_SECONDS: int = 2_592_000  # 30 days — registration dates are immutable
DOMAIN_AGE_THRESHOLD_DAYS: int = _int_env("BEHAVIORAL_DOMAIN_AGE_THRESHOLD_DAYS", 30)
MIN_SEND_HISTORY: int = _int_env("BEHAVIORAL_MIN_SEND_HISTORY", 5)
SEND_TIME_TOLERANCE_HOURS: int = _int_env("BEHAVIORAL_SEND_TIME_TOLERANCE_HOURS", 2)
MAX_SEND_HOURS: int = _int_env("BEHAVIORAL_MAX_SEND_HOURS", 200)

# Point weights for each signal
_PTS_FIRST_TIME_SENDER       = 1
_PTS_DOMAIN_AGE_ANOMALY      = 3
_PTS_DISPLAY_NAME_MISMATCH   = 2
_PTS_REPLY_CHAIN_BREAK       = 3
_PTS_SEND_TIME_ANOMALY       = 1

# Regex to strip Re:/Fwd: prefixes from subjects
_RE_PREFIX = re.compile(
    r"^(re|fw|fwd|aw|sv|antw|rif|vs|wg|tr|回复|转发)\s*:\s*",
    re.IGNORECASE,
)

# RDAP bootstrap registries (tried in order, first success wins)
_RDAP_BOOTSTRAP_URLS: list[str] = [
    "https://rdap.org/domain/{domain}",
    "https://rdap.iana.org/domain/{domain}",
]

# Fallback WHOIS-over-HTTP provider (whoisjsonapi.com — free tier, no key)
_WHOIS_HTTP_URL = "https://whoisjsonapi.com/v1/{domain}"


# ── Public result type ─────────────────────────────────────────────────────────

class BehavioralResult(NamedTuple):
    """Return value of compute_behavioral_signals()."""

    # Composite score — sum of points from signals that fired.
    behavioral_score: int

    # Human-readable explanation for each signal that fired (empty list if none).
    behavioral_reasons: list[str]

    # Individual signal flags.  None means "could not evaluate" (e.g. no key,
    # lookup failed).  False means "evaluated and did not fire".
    # True means "evaluated and fired (counts toward behavioral_score)".
    sig_first_time_sender: bool | None
    sig_domain_age_anomaly: bool | None
    sig_display_name_mismatch: bool | None
    sig_reply_chain_break: bool | None
    sig_send_time_anomaly: bool | None


# ── Normalization helpers ──────────────────────────────────────────────────────

def _normalize_addr(addr: str | None) -> str:
    """Return the bare lowercase email address, stripping any display name."""
    if not addr:
        return ""
    # "Display Name <user@domain.com>" -> "user@domain.com"
    m = re.search(r"<([^>]+)>", addr)
    if m:
        return m.group(1).strip().lower()
    return addr.strip().lower()


def _normalize_thread_key(subject: str | None) -> str:
    """Strip Re:/Fwd: prefixes and normalize whitespace for use as a thread key."""
    if not subject:
        return ""
    key = subject.strip()
    # Iteratively strip leading prefixes (handles "Re: Re: Fwd: Subject")
    while True:
        new_key = _RE_PREFIX.sub("", key).strip()
        if new_key == key:
            break
        key = new_key
    return key.lower()[:512]  # cap to column width


def _is_reply_or_forward(subject: str | None) -> bool:
    """Return True if the subject starts with a Re:/Fwd: style prefix."""
    if not subject:
        return False
    return bool(_RE_PREFIX.match(subject.strip()))


# ── Signal 1: first_time_sender ───────────────────────────────────────────────

async def _check_first_time_sender(
    session: AsyncSession,
    recipient: str,
    sender: str,
) -> bool:
    """Return True if this is the first time this sender has contacted this recipient.

    Cold-start guard: if the recipient has NO history at all (message_count
    sum = 0 rows), return False instead of True — we cannot distinguish
    "genuinely new sender to this mailbox" from "fresh install with no data".
    """
    from backend.models.sender_history import SenderHistory

    # Check whether the recipient has any history at all (cold-start guard)
    any_history = await session.scalar(
        select(SenderHistory.id)
        .where(SenderHistory.recipient == recipient)
        .limit(1)
    )
    if any_history is None:
        # Cold start: no history for this recipient mailbox — neutral result
        logger.debug("behavioral: cold start for recipient=%s", recipient)
        return False

    # Check whether this specific sender is known to this recipient
    row = await session.scalar(
        select(SenderHistory.id)
        .where(
            SenderHistory.recipient == recipient,
            SenderHistory.sender == sender,
        )
        .limit(1)
    )
    return row is None  # True = never seen before


# ── Signal 2: domain_age_anomaly ──────────────────────────────────────────────

async def _lookup_domain_registration_date(domain: str) -> datetime | None:
    """Query RDAP/WHOIS for the domain registration date.

    Returns a timezone-aware UTC datetime on success, or None on any failure.
    Uses the enrichment_cache (namespace="domain_age") with a 30-day TTL.
    All failures are caught and logged; this function never raises.
    """
    from backend.services.enrichment.cache import enrichment_cache

    cache_key = domain.lower()
    cached = await enrichment_cache.get("domain_age", cache_key)
    if cached is not None:
        # Cached value is an ISO-8601 string or the sentinel "not_found"
        if cached == "not_found":
            return None
        try:
            return datetime.fromisoformat(cached)
        except (ValueError, TypeError):
            pass

    reg_date: datetime | None = None

    # Try RDAP first (structured JSON, no parsing ambiguity)
    for url_template in _RDAP_BOOTSTRAP_URLS:
        try:
            reg_date = await _rdap_lookup(domain, url_template)
            if reg_date is not None:
                break
        except Exception as exc:
            logger.debug("RDAP lookup failed (%s): %s", url_template, type(exc).__name__)

    # Fallback to WHOIS-over-HTTP if RDAP returned nothing
    if reg_date is None:
        try:
            reg_date = await _whois_http_lookup(domain)
        except Exception as exc:
            logger.debug("WHOIS HTTP lookup failed: %s", type(exc).__name__)

    # Cache the result (including "not_found" to avoid re-querying)
    cache_value: str = reg_date.isoformat() if reg_date else "not_found"
    try:
        await enrichment_cache.set(
            "domain_age", cache_key, cache_value, ttl=DOMAIN_AGE_TTL_SECONDS
        )
    except Exception:
        pass  # non-fatal — in-memory entry is still valid

    return reg_date


async def _rdap_lookup(domain: str, url_template: str) -> datetime | None:
    """Query a single RDAP endpoint for the domain registration date."""
    import httpx

    url = url_template.format(domain=domain)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        resp = await client.get(url)

    if resp.status_code != 200:
        return None

    data = resp.json()

    # RDAP uses "events" array with eventAction="registration"
    for event in data.get("events", []):
        if event.get("eventAction", "").lower() == "registration":
            event_date_str = event.get("eventDate", "")
            try:
                dt = datetime.fromisoformat(event_date_str.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                pass

    return None


async def _whois_http_lookup(domain: str) -> datetime | None:
    """Fallback: query whoisjsonapi.com (free, no key required)."""
    import httpx

    url = _WHOIS_HTTP_URL.format(domain=domain)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})

    if resp.status_code != 200:
        return None

    data = resp.json()

    # whoisjsonapi.com uses "created_date" key
    for key in ("created_date", "creation_date", "registered", "registeredOn"):
        raw = data.get(key)
        if raw:
            try:
                dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                pass

    return None


async def _check_domain_age_anomaly(
    domain: str | None,
    email_date: datetime | None,
    threshold_days: int = DOMAIN_AGE_THRESHOLD_DAYS,
) -> bool | None:
    """Return True if domain was registered within threshold_days before email_date.

    Returns None if the lookup failed (signal undetermined — treated as False
    by the caller so it never inflates the score on missing data).
    """
    if not domain:
        return None

    reg_date = await _lookup_domain_registration_date(domain)
    if reg_date is None:
        return None  # lookup failed or domain not found — neutral

    ref_date = email_date or datetime.now(timezone.utc)
    if ref_date.tzinfo is None:
        ref_date = ref_date.replace(tzinfo=timezone.utc)
    if reg_date.tzinfo is None:
        reg_date = reg_date.replace(tzinfo=timezone.utc)

    age_days = (ref_date - reg_date).days
    return 0 <= age_days < threshold_days


# ── Signal 3: display_name_mismatch ──────────────────────────────────────────

def _check_display_name_mismatch(
    from_addr: str | None,
    from_domain: str | None,
    brand_domains: dict[str, list[str]],
    lookalike_threshold: int = 82,
) -> bool:
    """Return True if the From display name implies a brand the sending domain
    doesn't belong to.

    Two sub-checks (matching scoring_service logic, not duplicating it):
    A) Brand token appears in the display name but sending domain is not in
       that brand's legit domain list.
    B) The sending domain is a lookalike (typosquat) of a brand domain —
       reuses threat_signals.find_lookalike_domain().

    Either sub-check firing returns True.
    """
    if not from_addr or not from_domain:
        return False

    from backend.services import threat_signals

    display_lower = from_addr.lower()

    # Sub-check A: brand name in display, domain not in legit list
    for brand, legit_domains in brand_domains.items():
        if brand.lower() in display_lower:
            if not any(ld.lower() in from_domain for ld in legit_domains):
                logger.debug(
                    "behavioral: display_name_mismatch brand=%s domain=%s", brand, from_domain
                )
                return True

    # Sub-check B: lookalike/typosquat domain (catches spoofs without brand in display)
    lookalike = threat_signals.find_lookalike_domain(
        from_domain, brand_domains, lookalike_threshold
    )
    if lookalike:
        logger.debug(
            "behavioral: display_name_mismatch lookalike domain=%s -> %s",
            from_domain, lookalike[1],
        )
        return True

    return False


# ── Signal 4: reply_chain_break ───────────────────────────────────────────────

async def _check_reply_chain_break(
    session: AsyncSession,
    recipient: str,
    sender: str,
    subject: str | None,
    message_id: str | None,
    in_reply_to: str | None = None,
) -> bool:
    """Return True if the subject looks like a reply/forward but the sender
    is new to this thread.

    Logic:
    1. If subject does NOT start with Re:/Fwd:, return False (not a reply).
    2. Derive thread_key from subject.
    3. Look up thread_history for (recipient, thread_key).
    4. If no prior history exists for this thread, return False (neutral —
       could be the first email in a legitimate new thread; we cannot know).
    5. In-Reply-To tiebreaker: if In-Reply-To is present and matches any
       known message_id in the thread, this is a legitimate continuation —
       return False regardless of whether the sender is new.  This suppresses
       false positives from subject-key collisions on generic subjects like
       "Re: Invoice" between two unrelated threads.
    6. If prior history exists but neither the sender nor the message_id
       match any prior message, return True (suspicious injection).
    """
    from backend.models.thread_history import ThreadHistory

    if not _is_reply_or_forward(subject):
        return False

    thread_key = _normalize_thread_key(subject)
    if not thread_key:
        return False

    # Load all prior messages in this thread for this recipient
    result = await session.execute(
        select(ThreadHistory.sender, ThreadHistory.message_id)
        .where(
            ThreadHistory.recipient == recipient,
            ThreadHistory.thread_key == thread_key,
        )
    )
    rows = result.all()

    if not rows:
        # No thread history — cannot determine chain break; return neutral
        return False

    known_senders = {row.sender for row in rows}
    known_message_ids = {row.message_id for row in rows if row.message_id}

    # In-Reply-To tiebreaker: if the client explicitly references a known
    # message in this thread, it is a legitimate continuation even if the
    # sender hasn't appeared in this thread before (e.g. a new CC recipient
    # replying, or a sender whose first message lacked a Message-ID).
    if in_reply_to and in_reply_to in known_message_ids:
        logger.debug(
            "behavioral: reply_chain_break suppressed — In-Reply-To %s matches "
            "known thread message_id (thread=%s sender=%s)",
            in_reply_to, thread_key, sender,
        )
        return False

    # Sender-based check: is this sender known to this thread?
    sender_known = sender in known_senders
    # Message-ID dedup check: already seen this exact message?
    msgid_known = bool(message_id and message_id in known_message_ids)

    if not sender_known and not msgid_known:
        logger.debug(
            "behavioral: reply_chain_break thread=%s sender=%s not in known=%s",
            thread_key, sender, known_senders,
        )
        return True

    return False


# ── Signal 5: send_time_anomaly ───────────────────────────────────────────────

def _check_send_time_anomaly(
    send_hour: int | None,
    historical_hours: list[int],
    min_history: int = MIN_SEND_HISTORY,
    tolerance: int = SEND_TIME_TOLERANCE_HOURS,
) -> bool:
    """Return True if send_hour is significantly outside the sender's normal
    send-time pattern.

    DESIGN
    ------
    - Only activates when len(historical_hours) >= min_history.
    - "Normal" means there is at least one historically observed hour H such
      that |send_hour - H| <= tolerance (mod 24 for wraparound).
    - Returns False (neutral) when below the minimum sample size — this is
      the documented cold-start policy for this signal.
    """
    if send_hour is None:
        return False

    if len(historical_hours) < min_history:
        # Not enough data — neutral, not a false positive
        return False

    for h in historical_hours:
        diff = abs(send_hour - h) % 24
        # Wraparound: distance through midnight (e.g. 23 and 1 are 2 apart)
        diff = min(diff, 24 - diff)
        if diff <= tolerance:
            return False  # within tolerance of a known send hour

    return True  # outside tolerance of every known send hour


async def _get_send_hour_history(
    session: AsyncSession,
    recipient: str,
    sender: str,
) -> list[int]:
    """Return the stored send_hours list for (recipient, sender), or []."""
    from backend.models.sender_history import SenderHistory

    row = await session.scalar(
        select(SenderHistory.send_hours)
        .where(
            SenderHistory.recipient == recipient,
            SenderHistory.sender == sender,
        )
    )
    return row or []


# ── Main entry point ──────────────────────────────────────────────────────────

async def compute_behavioral_signals(
    *,
    session: AsyncSession,
    # Email metadata
    from_addr: str | None,
    from_domain: str | None,
    subject: str | None,
    message_id: str | None,
    in_reply_to: str | None = None,
    email_date: datetime | None,
    # Recipient mailbox (normalized lowercase bare address)
    recipient: str,
    # Settings
    brand_domains: dict[str, list[str]],
    scoring_weights: dict | None = None,
    lookalike_threshold: int = 82,
) -> BehavioralResult:
    """Compute all five behavioral signals for the given email.

    This function reads from sender_history and thread_history but does NOT
    write to them — callers must call record_observation() after scoring to
    update history.  This keeps the current email from influencing its own
    scores.

    Parameters
    ----------
    session:
        Active async SQLAlchemy session (read-only within this call).
    from_addr:
        Full From header value including display name, e.g.
        "PayPal Support <noreply@evil.com>".
    from_domain:
        The domain portion of the From address, e.g. "evil.com".
    subject:
        The email Subject header.
    message_id:
        The Message-ID header value.
    in_reply_to:
        The In-Reply-To header value (the Message-ID this email explicitly
        claims to reply to).  Used as a tiebreaker for reply_chain_break:
        if In-Reply-To references a known message in the thread, the email
        is a legitimate continuation even if the sender is new to the thread.
    email_date:
        The Date header as a timezone-aware datetime.  Used by domain_age_anomaly.
    recipient:
        The normalized recipient mailbox address.
    brand_domains:
        Mapping from brand name to list of legitimate domains, from Settings.
    scoring_weights:
        Optional override for signal point values.  Keys:
          behavioral_first_time_sender, behavioral_domain_age_anomaly,
          behavioral_display_name_mismatch, behavioral_reply_chain_break,
          behavioral_send_time_anomaly
    lookalike_threshold:
        Similarity threshold (0-100) for find_lookalike_domain().
    """
    # Allow callers to override individual signal weights
    w = scoring_weights or {}
    pts_first_time   = w.get("behavioral_first_time_sender", _PTS_FIRST_TIME_SENDER)
    pts_domain_age   = w.get("behavioral_domain_age_anomaly", _PTS_DOMAIN_AGE_ANOMALY)
    pts_display_name = w.get("behavioral_display_name_mismatch", _PTS_DISPLAY_NAME_MISMATCH)
    pts_reply_break  = w.get("behavioral_reply_chain_break", _PTS_REPLY_CHAIN_BREAK)
    pts_send_time    = w.get("behavioral_send_time_anomaly", _PTS_SEND_TIME_ANOMALY)

    sender = _normalize_addr(from_addr)
    recipient_norm = recipient.strip().lower()

    behavioral_score = 0
    behavioral_reasons: list[str] = []

    # ── Signal 1: first_time_sender ───────────────────────────────────────
    sig_first_time: bool | None = False
    try:
        sig_first_time = await _check_first_time_sender(session, recipient_norm, sender)
        if sig_first_time:
            behavioral_score += pts_first_time
            behavioral_reasons.append(
                f"First-time sender: '{sender}' has never contacted '{recipient_norm}' before"
            )
    except Exception as exc:
        logger.warning("behavioral: first_time_sender check failed: %s", type(exc).__name__)
        sig_first_time = None

    # ── Signal 2: domain_age_anomaly ─────────────────────────────────────
    sig_domain_age: bool | None = None
    try:
        sig_domain_age = await _check_domain_age_anomaly(from_domain, email_date)
        if sig_domain_age is True:
            behavioral_score += pts_domain_age
            behavioral_reasons.append(
                f"Domain age anomaly: '{from_domain}' was registered within "
                f"{DOMAIN_AGE_THRESHOLD_DAYS} days before this email was sent"
            )
        elif sig_domain_age is False:
            pass  # normal — domain is old enough
    except Exception as exc:
        logger.warning("behavioral: domain_age_anomaly check failed: %s", type(exc).__name__)
        sig_domain_age = None

    # ── Signal 3: display_name_mismatch ──────────────────────────────────
    sig_display_name: bool | None = False
    try:
        sig_display_name = _check_display_name_mismatch(
            from_addr, from_domain, brand_domains, lookalike_threshold
        )
        if sig_display_name:
            behavioral_score += pts_display_name
            behavioral_reasons.append(
                f"Display name mismatch: From display implies a trusted brand "
                f"but sender domain '{from_domain}' is not a legitimate domain for it"
            )
    except Exception as exc:
        logger.warning(
            "behavioral: display_name_mismatch check failed: %s", type(exc).__name__
        )
        sig_display_name = None

    # ── Signal 4: reply_chain_break ───────────────────────────────────────
    sig_reply_break: bool | None = False
    try:
        sig_reply_break = await _check_reply_chain_break(
            session, recipient_norm, sender, subject, message_id, in_reply_to
        )
        if sig_reply_break:
            behavioral_score += pts_reply_break
            thread_key = _normalize_thread_key(subject)
            behavioral_reasons.append(
                f"Reply chain break: subject '{subject}' looks like a reply/forward "
                f"but sender '{sender}' is not in the known thread history "
                f"for topic '{thread_key}'"
            )
    except Exception as exc:
        logger.warning("behavioral: reply_chain_break check failed: %s", type(exc).__name__)
        sig_reply_break = None

    # ── Signal 5: send_time_anomaly ───────────────────────────────────────
    sig_send_time: bool | None = False
    try:
        historical_hours = await _get_send_hour_history(session, recipient_norm, sender)
        send_hour = email_date.hour if email_date else None
        sig_send_time = _check_send_time_anomaly(send_hour, historical_hours)
        if sig_send_time:
            behavioral_score += pts_send_time
            behavioral_reasons.append(
                f"Send time anomaly: email sent at {send_hour:02d}:xx UTC is outside "
                f"'{sender}' historical send-time window "
                f"(based on {len(historical_hours)} prior observations)"
            )
    except Exception as exc:
        logger.warning("behavioral: send_time_anomaly check failed: %s", type(exc).__name__)
        sig_send_time = None

    return BehavioralResult(
        behavioral_score=behavioral_score,
        behavioral_reasons=behavioral_reasons,
        sig_first_time_sender=sig_first_time,
        sig_domain_age_anomaly=sig_domain_age,
        sig_display_name_mismatch=sig_display_name,
        sig_reply_chain_break=sig_reply_break,
        sig_send_time_anomaly=sig_send_time,
    )


# ── History recording (called AFTER scoring) ──────────────────────────────────

async def record_observation(
    *,
    session: AsyncSession,
    from_addr: str | None,
    subject: str | None,
    message_id: str | None,
    in_reply_to: str | None = None,
    email_date: datetime | None,
    recipient: str,
) -> None:
    """Record the current email in sender_history and thread_history.

    Must be called AFTER compute_behavioral_signals() so that the current
    email does not influence its own behavioral scores.  Idempotent — calling
    it multiple times for the same email is safe (message_count will increment
    but duplicate thread_history rows are acceptable since they only affect
    the reply_chain_break membership check).
    """
    from backend.models.sender_history import SenderHistory
    from backend.models.thread_history import ThreadHistory

    sender = _normalize_addr(from_addr)
    recipient_norm = recipient.strip().lower()
    if not sender or not recipient_norm:
        return

    now = datetime.now(timezone.utc)
    send_hour = email_date.hour if email_date else now.hour

    # ── Update sender_history ──────────────────────────────────────────────
    try:
        existing = await session.scalar(
            select(SenderHistory).where(
                SenderHistory.recipient == recipient_norm,
                SenderHistory.sender == sender,
            )
        )
        if existing is None:
            new_row = SenderHistory(
                recipient=recipient_norm,
                sender=sender,
                first_seen=now,
                last_seen=now,
                message_count=1,
                send_hours=[send_hour],
            )
            session.add(new_row)
        else:
            existing.message_count += 1
            existing.last_seen = now
            # Append send hour; cap at MAX_SEND_HOURS (FIFO drop oldest)
            hours: list[int] = list(existing.send_hours or [])
            hours.append(send_hour)
            if len(hours) > MAX_SEND_HOURS:
                hours = hours[-MAX_SEND_HOURS:]
            existing.send_hours = hours
            # Mark the column as modified for SQLAlchemy JSON change detection
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(existing, "send_hours")
    except Exception as exc:
        logger.error("behavioral: failed to update sender_history: %s", type(exc).__name__)

    # ── Update thread_history ──────────────────────────────────────────────
    try:
        thread_key = _normalize_thread_key(subject)
        if thread_key:
            thread_row = ThreadHistory(
                recipient=recipient_norm,
                thread_key=thread_key,
                sender=sender,
                message_id=message_id,
                in_reply_to=in_reply_to,
                created_at=now,
            )
            session.add(thread_row)
    except Exception as exc:
        logger.error("behavioral: failed to update thread_history: %s", type(exc).__name__)
