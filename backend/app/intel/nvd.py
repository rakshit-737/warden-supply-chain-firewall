"""NIST National Vulnerability Database (NVD) CVE API 2.0 client — opt-in.

Used for exactly one purpose: filling in a CVSS v3.x score for an advisory whose OSV record
carries none. It is disabled by default (``NVD_ENABLED=false``) because the public API is
strictly rate limited (5 requests / 30 s without a key, 50 / 30 s with one); the HTTP client's
token bucket is sized to those limits and each batch performs a bounded number of lookups.

``GET {NVD_API_BASE}?cveId=CVE-...`` returns ``vulnerabilities[].cve.metrics.cvssMetricV31`` /
``cvssMetricV30`` entries. Warden takes the vector string (preferring the ``Primary`` entry)
and computes the base score itself with :mod:`app.intel.cvss` instead of trusting the
reported number.

The optional ``NVD_API_KEY`` travels only in the ``apiKey`` request header. It is never put in
a URL, log line, error message, cache entry or ``repr``.
"""

from __future__ import annotations

from app.core.http import SafeHttpClient
from app.core.logging import get_logger
from app.intel import cvss
from app.intel.client import IntelCache, IntelSourceError, cache_key, translate_http_errors
from app.intel.models import SOURCE_NVD, is_cve_id

log = get_logger("warden.intel.nvd")

# Public NVD limits: 5 requests per rolling 30 s without a key, 50 with one.
RATE_PER_SECOND_ANONYMOUS = 5 / 30
RATE_PER_SECOND_WITH_KEY = 50 / 30
MAX_LOOKUPS_ANONYMOUS = 5
MAX_LOOKUPS_WITH_KEY = 25


def parse_cve_response(data: object, cve: str) -> cvss.CvssScore | None:
    """Best CVSS v3.x score for ``cve`` in an NVD CVE API 2.0 response, or ``None``."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("unexpected NVD response shape")
    for item in data["vulnerabilities"]:
        record = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(record, dict) or str(record.get("id", "")).upper() != cve:
            continue
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) if isinstance(metrics.get(key), list) else []
            ordered = sorted((e for e in entries if isinstance(e, dict)), key=lambda e: e.get("type") != "Primary")
            for entry in ordered:
                data_ = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
                scored = cvss.score_vector(data_.get("vectorString"))
                if scored is not None:
                    return scored
    return None


class NvdClient:
    def __init__(
        self,
        http: SafeHttpClient,
        cache: IntelCache,
        *,
        base_url: str,
        api_key: str | None,
        ttl_seconds: int,
    ) -> None:
        self._http = http
        self._cache = cache
        self._url = base_url
        self._api_key = api_key or None
        self._ttl = ttl_seconds

    def __repr__(self) -> str:  # never include the API key
        return f"NvdClient(base_url={self._url!r}, api_key={'set' if self._api_key else 'unset'})"

    @property
    def max_lookups_per_batch(self) -> int:
        return MAX_LOOKUPS_WITH_KEY if self._api_key else MAX_LOOKUPS_ANONYMOUS

    def cvss_for(self, cve: str) -> cvss.CvssScore | None:
        """CVSS v3.x score NVD records for ``cve`` (``None`` if it has none). Raises IntelSourceError."""
        cve = cve.strip().upper() if isinstance(cve, str) else ""
        if not is_cve_id(cve):
            raise IntelSourceError(SOURCE_NVD, "invalid CVE id", kind="invalid")
        key = cache_key("nvd:v1", cve)
        cached = self._cache.get(key)
        if cached is not None:
            if cached.get("scored") is False:
                return None
            scored = cvss.score_vector(cached.get("vector"))
            if scored is not None:
                return scored
        headers = {"apiKey": self._api_key} if self._api_key else None
        data = translate_http_errors(SOURCE_NVD, self._http.get_json, self._url, params={"cveId": cve},
                                     headers=headers, max_bytes=4 * 1024 * 1024)
        try:
            scored = parse_cve_response(data, cve)
        except ValueError as exc:
            raise IntelSourceError(SOURCE_NVD, str(exc), kind="invalid") from exc
        self._cache.set(key, {"scored": True, "vector": scored.vector} if scored else {"scored": False}, self._ttl)
        return scored
