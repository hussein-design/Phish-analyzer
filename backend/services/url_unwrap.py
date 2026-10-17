"""URL wrapper unwrapping — single source of truth.

Known link-protection / redirect wrapper services are listed once here.
Both ``url_intelligence_service`` and ``virustotal_provider`` import
``unwrap_url`` from this module; there are no duplicate tables elsewhere.

Supported wrappers (parsing only — zero network requests):

* **Microsoft SafeLinks** — host ends with
  ``safelinks.protection.outlook.com``; real URL in ``url`` param.
* **Microsoft IRIS** — host is or ends with ``.iris.microsoft.com``;
  real URL in ``url`` param.
* **Google redirect** — host ends with ``google.com`` AND path starts
  with ``/url``; real URL in ``q`` param.
* **Proofpoint URLDefense** — host ends with ``urldefense.proofpoint.com``
  or ``urldefense.com``; real URL in ``u`` param.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse, unquote


def unwrap_url(url: str) -> str | None:
    """Return the real destination URL for known redirect wrappers.

    Returns *None* (not the original URL) when:
      - the URL is not a recognised wrapper, OR
      - the destination parameter is absent / empty / not an http(s) URL.

    This allows callers to distinguish "was a wrapper, destination
    extracted" from "was not a wrapper at all".
    """
    if not url:
        return None

    try:
        parsed = urlparse(url)
    except Exception:
        return None

    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    qs = parse_qs(parsed.query)

    def _get(*params: str) -> str | None:
        for p in params:
            vals = qs.get(p)
            if vals:
                inner = unquote(vals[0])
                if inner.startswith(("http://", "https://")):
                    return inner
        return None

    # SafeLinks: *.safelinks.protection.outlook.com
    if host.endswith("safelinks.protection.outlook.com"):
        return _get("url", "URL")

    # Microsoft IRIS: iris.microsoft.com or *.iris.microsoft.com
    if host == "iris.microsoft.com" or host.endswith(".iris.microsoft.com"):
        return _get("url", "URL")

    # Google redirect: *.google.com with /url path
    if host.endswith("google.com") and path.startswith("/url"):
        return _get("q", "Q")

    # Proofpoint URLDefense
    if host.endswith("urldefense.proofpoint.com") or host.endswith("urldefense.com"):
        return _get("u", "U")

    return None
