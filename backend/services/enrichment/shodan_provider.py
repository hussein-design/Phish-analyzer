"""Shodan sender-IP enrichment.

Queries the Shodan InternetDB API (free, no key required) for basic IP
intelligence, then optionally queries the Shodan main API (requires an
API key) for deeper detail: open ports, CVEs, tags, and hostnames.

Returns a structured result dict::

    {
        "status": "no_data" | "ok" | "no_key" | "rate_limit" | "error",
        "error":  str | None,
        "data": {
            "ip":         str,
            "hostnames":  list[str],
            "ports":      list[int],
            "vulns":      list[str],   # CVE IDs (main API only)
            "tags":       list[str],   # e.g. ["vpn", "cloud"]
            "org":        str | None,  # organisation name (main API only)
            "asn":        str | None,  # e.g. "AS15169"
            "country":    str | None,
            "city":       str | None,
        } | None,
    }

The InternetDB endpoint (https://internetdb.shodan.io/<ip>) is always
attempted first — it needs no API key and covers ports, vulns, CPEs,
hostnames, and tags.  When a Shodan API key is configured, a second call
to the main host-info endpoint (/shodan/host/<ip>) fetches org/ASN/geo
data and additional CVEs, and the results are merged.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

# InternetDB returns 404 for IPs with no Shodan data (clean/private).
# We treat that as "no_data" rather than an error.
_NO_DATA_CODES = {404, 400}


async def enrich_ip(ip: str | None, api_key: str | None) -> dict:
    """Enrich a sender IP using Shodan.

    Parameters
    ----------
    ip:      IPv4 address string, or None (returns no_data immediately).
    api_key: Shodan API key.  None is acceptable — the InternetDB free tier
             is always attempted regardless.
    """
    if not ip:
        return {"status": "no_data", "error": None, "data": None}

    # Reject obviously private / loopback ranges — not useful to query.
    if _is_private_ip(ip):
        return {"status": "no_data", "error": "Private/reserved IP — skipped", "data": None}

    data: dict = {
        "ip":        ip,
        "hostnames": [],
        "ports":     [],
        "vulns":     [],
        "tags":      [],
        "org":       None,
        "asn":       None,
        "country":   None,
        "city":      None,
    }

    # ── InternetDB (free, no key) ─────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_INTERNETDB_URL.format(ip=ip))

        if resp.status_code in _NO_DATA_CODES:
            # No Shodan data for this IP — not an error.
            if not api_key:
                return {"status": "no_data", "error": None, "data": None}
            # Fall through to the main API if a key is available.
        elif resp.status_code == 429:
            msg = "Shodan InternetDB rate limit (HTTP 429)"
            logger.warning(msg)
            return {"status": "rate_limit", "error": msg, "data": None}
        elif resp.status_code != 200:
            msg = f"Shodan InternetDB unexpected status {resp.status_code}"
            logger.warning("%s for IP %s", msg, ip)
            # Non-fatal — continue to main API if key available.
        else:
            payload = resp.json()
            data["hostnames"] = payload.get("hostnames") or []
            data["ports"]     = payload.get("ports") or []
            data["vulns"]     = payload.get("vulns") or []
            data["tags"]      = payload.get("tags") or []
            logger.info(
                "Shodan InternetDB OK for %s: ports=%d vulns=%d",
                ip, len(data["ports"]), len(data["vulns"]),
            )

    except httpx.TimeoutException as exc:
        logger.warning("Shodan InternetDB timeout for %s: %s", ip, exc)
        # Non-fatal — continue to main API if key available.
    except Exception as exc:
        logger.warning("Shodan InternetDB error for %s: %s", ip, exc)

    # ── Main API (key required) ────────────────────────────────────────────────
    if api_key:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    _SHODAN_HOST_URL.format(ip=ip),
                    params={"key": api_key},
                )

            if resp.status_code == 401:
                msg = "Shodan API key invalid or unauthorised (HTTP 401)"
                logger.warning(msg)
                return {"status": "error", "error": msg, "data": None}
            elif resp.status_code == 429:
                msg = "Shodan API rate limit (HTTP 429)"
                logger.warning(msg)
                return {"status": "rate_limit", "error": msg, "data": None}
            elif resp.status_code in _NO_DATA_CODES:
                pass  # no additional data, use what InternetDB gave us
            elif resp.status_code != 200:
                logger.warning(
                    "Shodan host API unexpected status %s for IP %s",
                    resp.status_code, ip,
                )
            else:
                payload = resp.json()
                data["org"]     = payload.get("org")
                data["asn"]     = payload.get("asn")
                data["country"] = payload.get("country_code")
                data["city"]    = payload.get("city")
                # Merge additional CVEs from the main API
                extra_vulns = list(payload.get("vulns", {}).keys())
                existing = set(data["vulns"])
                data["vulns"] = data["vulns"] + [v for v in extra_vulns if v not in existing]
                # Merge additional hostnames
                extra_hosts = payload.get("hostnames") or []
                existing_h = set(data["hostnames"])
                data["hostnames"] = data["hostnames"] + [h for h in extra_hosts if h not in existing_h]
                logger.info("Shodan main API OK for %s: org=%s", ip, data["org"])

        except httpx.TimeoutException as exc:
            logger.warning("Shodan main API timeout for %s: %s", ip, exc)
        except Exception as exc:
            logger.warning("Shodan main API error for %s: %s", ip, exc)

    # Determine final status.  Even if only InternetDB ran, we have useful data.
    has_data = any([
        data["hostnames"], data["ports"], data["vulns"],
        data["tags"], data["org"], data["asn"],
    ])

    return {
        "status": "ok" if has_data else "no_data",
        "error": None,
        "data": data if has_data else None,
    }


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 private, loopback, link-local, and CGNAT ranges."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
