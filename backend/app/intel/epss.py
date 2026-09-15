"""FIRST Exploit Prediction Scoring System (EPSS) client.

``GET {EPSS_API_BASE}?cve=CVE-A,CVE-B,...`` returns, per CVE, the estimated probability of
exploitation activity in the next 30 days and its percentile::

    {"status": "OK", "total": 2, "data": [{"cve": "CVE-...", "epss": "0.0221", "percentile": "0.8812",
                                           "date": "YYYY-MM-DD"}, ...]}

Requests carry at most 100 CVEs. Scores are cached per CVE for ``EPSS_CACHE_TTL_SECONDS``;
a CVE that EPSS does not score (e.g. recently published) is cached as "not scored" so it is
not re-queried on every scan. A CVE is only treated as "not scored" when the response was
complete — if the service reports more results than it returned, missing CVEs stay
unresolved rather than being recorded as absent.

Numeric values arrive as strings and are validated to finite numbers in [0, 1]; entries for
CVEs that were not requested are ignored.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.core.http import SafeHttpClient
from app.core.logging import get_logger
from app.intel.client import IntelCache, IntelSourceError, cache_key, translate_http_errors
from app.intel.models import SOURCE_EPSS, is_cve_id

log = get_logger("warden.intel.epss")

MAX_CVES_PER_REQUEST = 100


@dataclass(frozen=True)
class EpssScore:
    cve: str
    epss: float
    percentile: float | None = None
    date: str | None = None


@dataclass
class EpssLookup:
    scores: dict[str, EpssScore] = field(default_factory=dict)
    resolved: set[str] = field(default_factory=set)  # CVEs with a definitive answer (scored or not scored)
    errors: list[str] = field(default_factory=list)


def _probability(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        f = float(value)
    except (ValueError, OverflowError):  # OverflowError: an integer too large for a float
        return None
    return f if math.isfinite(f) and 0.0 <= f <= 1.0 else None


class EpssClient:
    def __init__(self, http: SafeHttpClient, cache: IntelCache, *, base_url: str, ttl_seconds: int) -> None:
        self._http = http
        self._cache = cache
        self._url = base_url
        self._ttl = ttl_seconds

    def lookup(self, cves: Iterable[str]) -> EpssLookup:
        """EPSS scores for ``cves``. Never raises for source failures (see ``errors``)."""
        result = EpssLookup()
        wanted: list[str] = []
        for cve in cves:
            c = cve.strip().upper() if isinstance(cve, str) else ""
            if is_cve_id(c) and c not in wanted:
                wanted.append(c)
        missing: list[str] = []
        for cve in wanted:
            cached = self._cache.get(cache_key("epss:v1", cve))
            if cached is not None and self._absorb_cached(result, cve, cached):
                continue
            missing.append(cve)
        for start in range(0, len(missing), MAX_CVES_PER_REQUEST):
            batch = missing[start:start + MAX_CVES_PER_REQUEST]
            try:
                self._fetch_batch(batch, result)
            except IntelSourceError as exc:
                log.warning("epss_lookup_failed", error=str(exc), cves=len(batch))
                result.errors.append(str(exc))
        return result

    @staticmethod
    def _absorb_cached(result: EpssLookup, cve: str, cached: dict) -> bool:
        if cached.get("scored") is False:
            result.resolved.add(cve)
            return True
        epss = _probability(cached.get("epss"))
        if epss is None:
            return False  # corrupt entry: refetch
        date = cached.get("date")
        result.scores[cve] = EpssScore(cve, epss, _probability(cached.get("percentile")),
                                       date if isinstance(date, str) and len(date) <= 32 else None)
        result.resolved.add(cve)
        return True

    def _fetch_batch(self, batch: list[str], result: EpssLookup) -> None:
        data = translate_http_errors(SOURCE_EPSS, self._http.get_json, self._url, params={"cve": ",".join(batch)},
                                     max_bytes=4 * 1024 * 1024)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise IntelSourceError(SOURCE_EPSS, "unexpected response shape", kind="invalid")
        status = data.get("status")
        if status is not None and str(status).upper() != "OK":
            raise IntelSourceError(SOURCE_EPSS, "service reported a non-OK status", kind="status")
        requested = set(batch)
        answered: set[str] = set()
        present: set[str] = set()
        for item in data["data"]:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve").strip().upper() if isinstance(item.get("cve"), str) else None
            if cve not in requested:
                continue
            present.add(cve)
            epss = _probability(item.get("epss"))
            if epss is None:
                continue  # an unusable value leaves the CVE unresolved
            date = item.get("date") if isinstance(item.get("date"), str) and len(item["date"]) <= 32 else None
            score = EpssScore(cve, epss, _probability(item.get("percentile")), date)
            result.scores[cve] = score
            result.resolved.add(cve)
            answered.add(cve)
            self._cache.set(cache_key("epss:v1", cve),
                            {"scored": True, "epss": score.epss, "percentile": score.percentile, "date": date},
                            self._ttl)
        total = data.get("total")
        truncated = isinstance(total, int) and not isinstance(total, bool) and total > len(data["data"])
        unanswered = requested - answered
        if truncated and unanswered:
            raise IntelSourceError(SOURCE_EPSS, "response was truncated", kind="invalid")
        for cve in sorted(unanswered - present):  # present-but-invalid CVEs stay unresolved
            result.resolved.add(cve)
            self._cache.set(cache_key("epss:v1", cve), {"scored": False}, self._ttl)
