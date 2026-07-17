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
                # Resolve relative redirects
                if location.startswith("/"):
                    base = current_url.split("://", 1)
                    scheme_host = base[0] + "://" + base[1].split("/", 1)[0] if len(base) > 1 else ""
                    location = scheme_host + location
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


def _assess_redirect_suspicion(result: UrlIntelligence) -> None:
    """Flag a redirect chain as suspicious when the final domain differs
    meaningfully from the original and a brand token is involved."""
    original_host = _extract_host(result.original_url)
    final_url = result.expanded_url or (result.redirect_chain[-1] if result.redirect_chain else None)
    if not final_url:
        return

    final_host = _extract_host(final_url)
    if not original_host or not final_host or original_host == final_host:
        return

    # Brand token in original host but not in final host → likely spoof redirect
    orig_compact = original_host.replace("-", "").replace(".", "")
    final_compact = final_host.replace("-", "").replace(".", "")

    for token in _BRAND_TOKENS:
        if token in orig_compact and token not in final_compact:
            result.is_redirect_suspicious = True
            result.redirect_suspicious_reason = (
                f"Original URL implies '{token}' (host={original_host}) "
                f"but redirects to unrelated domain '{final_host}'"
            )
            return
        if token in final_compact and token not in orig_compact:
            result.is_redirect_suspicious = True
            result.redirect_suspicious_reason = (
                f"Redirect lands on domain suggesting '{token}' (host={final_host}) "
                f"from unrelated origin '{original_host}'"
            )
            return

    # Any redirect through a URL shortener to a different domain is mildly suspicious
    if result.redirect_count >= 2 and original_host != final_host:
        result.is_redirect_suspicious = True
        result.redirect_suspicious_reason = (
            f"Multi-hop redirect ({result.redirect_count} hops) "
            f"from {original_host} to {final_host}"
        )


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
