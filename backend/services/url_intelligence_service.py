"""URL intelligence service — Phase 4.

For every URL extracted from an email, this service:

1. Follows HTTP redirects up to a configurable maximum hop count, recording
   the full redirect chain.  This exposes hidden destinations behind shortened
   links, open-redirect wrappers, and multi-stage redirect chains.

2. Identifies URL shorteners by hostname (bit.ly, t.co, etc.) and marks their
   expanded final destination.

3. Fetches a lightweight HEAD + partial GET of the final page to extract the
   <title> tag and detect brand-spoofing landing pages.

4. Compares the original URL's domain against the final domain and flags
   suspicious redirect behaviour (original ≠ final AND a known brand token
   appears in one but not the other).

Safety constraints
------------------
* All HTTP calls are made with a short timeout (default 8 s total / 3 s
  connect) and a conservative User-Agent that won't trigger anti-bot blocks.
* Only http:// and https:// URLs are processed — mailto:, ftp:, etc. are
  skipped.
* Redirects that resolve to private / RFC-1918 addresses are flagged and
  NOT followed (SSRF protection).
* HTML is only partially downloaded (first 32 KB) — we never execute scripts.
* Exceptions per-URL are caught and logged; a failure returns a partial result
  rather than crashing the pipeline.

The public entry point ``expand_urls()`` is async and accepts a list of URL
strings, returning a list of ``UrlIntelligence`` objects in the same order.
The caller (analysis_service) runs this concurrently with other enrichment
tasks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
_MAX_REDIRECTS = 10          # hard cap on redirect hops we follow
_CONNECT_TIMEOUT = 3.0       # seconds for TCP connect
_READ_TIMEOUT = 8.0          # seconds for reading the page
_MAX_PAGE_BYTES = 32_768     # 32 KB — enough to grab the <title> tag
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CONCURRENT_LIMIT = asyncio.Semaphore(5)  # max concurrent URL expansions

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

# ── Brand tokens for redirect-suspicious detection ────────────────────────────
_BRAND_TOKENS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "outlook", "office365", "onedrive", "sharepoint", "docusign",
    "fedex", "ups", "dhl", "wellsfargo", "chase", "citibank",
    "bankofamerica", "hsbc", "barclays",
]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class UrlIntelligence:
    """Intelligence gathered for one URL."""
    original_url: str

    # Redirect following
    redirect_chain: list[str] = field(default_factory=list)   # all intermediate URLs
    expanded_url: str | None = None     # final destination after all redirects
    redirect_count: int = 0
    final_status_code: int | None = None

    # Page inspection
    page_title: str | None = None

    # Flags
    is_redirect_suspicious: bool = False
    redirect_suspicious_reason: str | None = None

    # Error — set when the URL could not be fetched at all
    error: str | None = None


# ── Public entry point ────────────────────────────────────────────────────────

async def expand_urls(
    urls: list[str],
    *,
    max_redirects: int = _MAX_REDIRECTS,
    timeout_connect: float = _CONNECT_TIMEOUT,
    timeout_read: float = _READ_TIMEOUT,
) -> list[UrlIntelligence]:
    """Expand and inspect a list of URLs concurrently.

    Returns a list of UrlIntelligence objects in the same order as the
    input list.  Never raises — per-URL errors are stored in the object.
    """
    tasks = [
        _expand_one(url, max_redirects=max_redirects,
                    timeout_connect=timeout_connect, timeout_read=timeout_read)
        for url in urls
    ]
    return list(await asyncio.gather(*tasks))


# ── Per-URL worker ────────────────────────────────────────────────────────────

async def _expand_one(
    url: str,
    *,
    max_redirects: int,
    timeout_connect: float,
    timeout_read: float,
) -> UrlIntelligence:
    result = UrlIntelligence(original_url=url)

    if not url.startswith(("http://", "https://")):
        result.error = "Non-HTTP scheme — skipped"
        return result

    async with _CONCURRENT_LIMIT:
        try:
            await _fetch_with_redirects(
                result, url,
                max_redirects=max_redirects,
                timeout_connect=timeout_connect,
                timeout_read=timeout_read,
            )
        except Exception as exc:
            result.error = type(exc).__name__
            logger.debug("URL intelligence failed for %s: %s", url, exc)

    _assess_redirect_suspicion(result)
    return result


async def _fetch_with_redirects(
    result: UrlIntelligence,
    start_url: str,
    *,
    max_redirects: int,
    timeout_connect: float,
    timeout_read: float,
) -> None:
    """Follow redirects manually so we can record each hop."""
    timeout = httpx.Timeout(connect=timeout_connect, read=timeout_read, write=5.0, pool=5.0)
    headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    current_url = start_url
    hops = 0

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        # TLS verification enabled — do NOT disable; self-signed cert errors
        # are caught below and recorded in result.error.
    ) as client:
        while hops <= max_redirects:
            # SSRF guard: resolve hostname and reject private/loopback/link-local IPs
            host = _extract_host(current_url)
            if host and await _is_private_host_async(host):
                result.error = f"Redirect to private/internal address blocked: {host}"
                return

            try:
                resp = await client.get(current_url, headers=headers)
            except httpx.TooManyRedirects:
                break
            except (httpx.ConnectTimeout, httpx.ReadTimeout):
                result.error = "Request timed out"
                return
            except httpx.ConnectError as exc:
                result.error = f"Connection failed: {type(exc).__name__}"
                return
            except httpx.SSLError as exc:
                result.error = f"TLS/SSL error: {type(exc).__name__}"
                return
            except Exception as exc:
                result.error = type(exc).__name__
                return

            result.final_status_code = resp.status_code

            # Redirect?
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").strip()
                if not location:
                    break
                # BUG-08 fix: the old code only handled absolute-path redirects
                # (location starting with "/").  Relative redirects like
                # "redirect?foo=bar" were followed as-is, which would form an
                # invalid URL and cause an immediate connection error.
                # urllib.parse.urljoin handles all cases correctly:
                #   absolute URL  → returned unchanged
                #   /absolute-path → scheme+host prepended
                #   relative/path  → resolved against current_url's directory
                from urllib.parse import urljoin
                location = urljoin(current_url, location)
                result.redirect_chain.append(location)
                current_url = location
                hops += 1
                continue

            # Non-redirect — we've arrived at the final page
            result.expanded_url = str(resp.url) if str(resp.url) != start_url else None
            result.redirect_count = hops

            # Extract page title from a partial body read
            content_type = resp.headers.get("content-type", "").lower()
            if "html" in content_type:
                try:
                    # Read first _MAX_PAGE_BYTES only
                    body = b""
                    async for chunk in resp.aiter_bytes(chunk_size=4096):
                        body += chunk
                        if len(body) >= _MAX_PAGE_BYTES:
                            break
                    title_match = _TITLE_RE.search(body)
                    if title_match:
                        raw_title = title_match.group(1)
                        result.page_title = raw_title.decode("utf-8", errors="replace").strip()[:200]
                except Exception as exc:
                    logger.debug("Page title extraction failed: %s", exc)

            return

        # Fell off the loop (too many redirects or no terminal response)
        result.expanded_url = current_url if current_url != start_url else None
        result.redirect_count = hops


_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Common URL-shortener hostnames (mirrors DEFAULT_URL_SHORTENERS in defaults.py
# but available as a local constant so _assess_redirect_suspicion can use it
# without a DB round-trip).
_SHORTENER_HOSTS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
})


def _unwrap_known_wrapper(url: str) -> str | None:
    """Delegate to the single-source-of-truth unwrap table in url_unwrap.

    Returns the real destination URL if *url* is a known wrapper, else None.
    """
    from backend.services.url_unwrap import unwrap_url
    return unwrap_url(url)


def _assess_redirect_suspicion(result: UrlIntelligence) -> None:
    """Flag a redirect chain as suspicious.

    Wrapper-unwrap policy
    ─────────────────────
    Known link-protection wrappers (SafeLinks, iris.microsoft.com, Google
    redirect, Proofpoint URLDefense) are *transparent hops*: we extract the
    real destination from their query parameter and judge THAT, never the
    wrapper hostname.  A wrapper pointing to a normal domain must not fire.

    Firing conditions (after unwrapping)
    ──────────────────────────────────────
    The signal fires when the real destination meets at least one of:

    1. Raw IP host — ``http://1.2.3.4/malware`` hidden behind a wrapper.
    2. Known URL-shortener host — adds another layer of obfuscation.
    3. More than 2 real hops — the wrapper hop is excluded from this count
       so a SafeLinks → legitimate-site (1 real hop) never triggers it.

    Note: anchor-text vs href mismatch is handled independently by
    ``detect_anchor_mismatches`` in threat_signals.py; this function does
    not duplicate that check.
    """
    # ── Step 1: determine the "judged" URL ──────────────────────────────────
    # If the original URL is itself a known wrapper, extract its destination.
    # This is the URL the analyst and scoring engine should reason about.
    unwrapped = _unwrap_known_wrapper(result.original_url)
    judged_url = unwrapped if unwrapped else result.original_url

    # Determine the final resolved URL (end of any live redirect chain).
    final_url = result.expanded_url or (
        result.redirect_chain[-1] if result.redirect_chain else None
    )

    # Number of "real" hops: if the original was a wrapper, subtract 1
    # because the first hop was just unwrapping to the real destination.
    wrapper_hop = 1 if unwrapped else 0
    real_hop_count = max(0, result.redirect_count - wrapper_hop)

    # Use the final resolved URL when available; otherwise fall back to the
    # unwrapped / original URL so we still judge something.
    destination_url = final_url or judged_url

    destination_host = _extract_host(destination_url) or _extract_host(judged_url)
    if not destination_host:
        return

    # ── Step 2: apply firing conditions on the destination ──────────────────

    # Condition 1: destination is a raw IP address
    if _IP_HOST_RE.match(destination_host):
        result.is_redirect_suspicious = True
        result.redirect_suspicious_reason = (
            f"Link{'(via wrapper) ' if unwrapped else ' '}redirects to raw IP host: "
            f"{destination_host}"
        )
        return

    # Condition 2: destination is a known URL shortener
    if destination_host in _SHORTENER_HOSTS:
        result.is_redirect_suspicious = True
        result.redirect_suspicious_reason = (
            f"Link{'(via wrapper) ' if unwrapped else ' '}redirects to URL shortener: "
            f"{destination_host}"
        )
        return

    # Condition 3: more than 2 real hops (excludes the wrapper hop itself)
    if real_hop_count > 2:
        result.is_redirect_suspicious = True
        result.redirect_suspicious_reason = (
            f"Excessive redirect chain: {real_hop_count} hops "
            f"(excluding wrapper) to {destination_host}"
        )
        return

    # All other cases — wrapper pointing to a normal domain, or a
    # low-hop redirect to a non-shortener non-IP domain — are benign.


def _extract_host(url: str) -> str | None:
    """Extract hostname from URL without importing urllib."""
    try:
        after_scheme = url.split("://", 1)
        if len(after_scheme) < 2:
            return None
        host = after_scheme[1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
        return host.lower().strip() or None
    except Exception:
        return None


# Hostnames that must never be fetched regardless of DNS resolution
_BLOCKED_HOSTNAMES = frozenset({
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal",          # GCP metadata service
    "169.254.169.254",                    # AWS/Azure/GCP IMDS
    "metadata.internal",
    "100.100.100.200",                    # Alibaba Cloud metadata
})


def _is_private_ip(addr_str: str) -> bool:
    """Return True if addr_str is a private / loopback / link-local address."""
    try:
        addr = ipaddress.ip_address(addr_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


async def _is_private_host_async(host: str) -> bool:
    """Return True if host resolves to a private/loopback/link-local address.

    CRIT-02 fix: hostnames are resolved via DNS before the check so that
    names like 'localhost', 'metadata.google.internal', or any hostname that
    DNS-resolves to an RFC-1918 address cannot bypass the SSRF guard.
    """
    if host in _BLOCKED_HOSTNAMES:
        return True

    # If it looks like a bare IP, check directly
    if _is_private_ip(host):
        return True

    # Resolve hostname — run in a thread executor since socket.getaddrinfo is blocking
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        )
        for _family, _type, _proto, _canonname, sockaddr in results:
            resolved_ip = sockaddr[0]
            if _is_private_ip(resolved_ip):
                logger.warning("SSRF guard: %s resolved to private IP %s — blocked", host, resolved_ip)
                return True
        return False
    except (socket.gaierror, OSError):
        # DNS resolution failed — block to be safe
        logger.debug("SSRF guard: DNS resolution failed for %s — blocked", host)
        return True
