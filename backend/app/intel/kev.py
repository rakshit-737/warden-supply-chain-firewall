"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The KEV catalog is a single JSON feed (``KEV_FEED_URL``) listing CVEs with evidence of active
exploitation::

    {"catalogVersion": "...", "count": N,
     "vulnerabilities": [{"cveID": "CVE-YYYY-NNNN", "dateAdded": "YYYY-MM-DD", ...}, ...]}

Warden keeps only ``cveID -> dateAdded``, caches it for ``KEV_CACHE_TTL_SECONDS`` (shared
cache plus a per-process copy so the feed is not re-decoded for every package), and looks a
vulnerability up by *any* of its CVE identifiers.

The shared cache entry records the wall-clock time the feed was fetched (``fetched_at``). A
process that loads the catalog from the shared cache memoises it only for the entry's
*remaining* lifetime, so no replica serves a catalog older than ``KEV_CACHE_TTL_SECONDS``; an
entry without that timestamp (written by an older version) is memoised for at most
``UNDATED_CACHE_MEMO_SECONDS``.

Fail-closed choices: a feed that yields no valid entries is treated as an error rather than
as "nothing is exploited" (a truncated or tampered feed must not silently clear KEV flags),
and cached copies are re-validated on read.

After a failed fetch, further fetch attempts are suppressed for ``failure_backoff_seconds``
(the shared cache is still consulted): while the feed is down every concurrent scan would
otherwise spend (retries x timeout) re-trying it. Callers still receive an error, so the
outage is reported as missing KEV data, never as "not exploited".
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from app.core.http import SafeHttpClient
from app.core.logging import get_logger
from app.intel.client import IntelCache, IntelSourceError, translate_http_errors
from app.intel.models import SOURCE_KEV

log = get_logger("warden.intel.kev")

KEV_CACHE_KEY = "intel:kev:v1"
MAX_KEV_ENTRIES = 100_000
UNDATED_CACHE_MEMO_SECONDS = 300.0
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")


@dataclass(frozen=True)
class KevCatalog:
    entries: Mapping[str, str | None]  # CVE id -> dateAdded (YYYY-MM-DD) or None
    catalog_version: str | None = None

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, identifiers: Iterable[str]) -> tuple[str, str | None] | None:
        """First identifier (in the given order) listed in KEV, as ``(cve, date_added)``."""
        for ident in identifiers:
            if not isinstance(ident, str):
                continue
            cve = ident.strip().upper()
            if cve in self.entries:
                return cve, self.entries[cve]
        return None

    def to_cache(self) -> dict:
        return {"catalog_version": self.catalog_version, "entries": dict(self.entries)}


def _valid_entries(pairs: Iterable[tuple[object, object]]) -> dict[str, str | None]:
    entries: dict[str, str | None] = {}
    for cve, date in pairs:
        if not isinstance(cve, str):
            continue
        cve = cve.strip().upper()
        if not _CVE_RE.match(cve):
            continue
        entries[cve] = date.strip() if isinstance(date, str) and _DATE_RE.match(date.strip()) else None
        if len(entries) >= MAX_KEV_ENTRIES:
            break
    return entries


def _catalog_version(value: object) -> str | None:
    return value[:40] if isinstance(value, str) and value.isprintable() else None


def parse_kev_feed(data: object) -> KevCatalog:
    """Validate the KEV JSON feed. Raises ``ValueError`` if it has no usable entries."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("KEV feed has no vulnerabilities list")
    entries = _valid_entries(
        (item.get("cveID"), item.get("dateAdded")) for item in data["vulnerabilities"] if isinstance(item, dict)
    )
    if not entries:
        raise ValueError("KEV feed contains no valid entries")
    return KevCatalog(entries=entries, catalog_version=_catalog_version(data.get("catalogVersion")))


def cached_fetched_at(cached: object) -> float | None:
    """Wall-clock fetch time stored with a shared cache entry (``None`` when absent or invalid)."""
    value = cached.get("fetched_at") if isinstance(cached, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def catalog_from_cache(cached: dict | None) -> KevCatalog | None:
    if not cached or not isinstance(cached.get("entries"), dict):
        return None
    entries = _valid_entries(cached["entries"].items())
    if not entries:
        return None
    return KevCatalog(entries=entries, catalog_version=_catalog_version(cached.get("catalog_version")))


class KevClient:
    def __init__(
        self,
        http: SafeHttpClient,
        cache: IntelCache,
        *,
        feed_url: str,
        ttl_seconds: int,
        max_feed_bytes: int = 32 * 1024 * 1024,
        failure_backoff_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._http = http
        self._cache = cache
        self._url = feed_url
        self._ttl = ttl_seconds
        self._max_bytes = max_feed_bytes
        self._backoff = max(0.0, failure_backoff_seconds)
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._memo: tuple[float, KevCatalog] | None = None  # (monotonic expiry, catalog)
        self._failure: tuple[float, str] | None = None  # (when, error kind) of the last failed fetch

    def _from_shared_cache(self) -> tuple[KevCatalog, float] | None:
        """A still-fresh shared catalog and its remaining lifetime in seconds."""
        cached = self._cache.get(KEV_CACHE_KEY)
        catalog = catalog_from_cache(cached)
        if catalog is None:
            return None
        fetched_at = cached_fetched_at(cached)
        if fetched_at is None:
            return catalog, min(float(self._ttl), UNDATED_CACHE_MEMO_SECONDS)
        remaining = self._ttl - max(0.0, self._wall_clock() - fetched_at)
        return (catalog, remaining) if remaining > 0 else None

    def catalog(self) -> KevCatalog:
        """The KEV catalog (memoised, cached). Raises :class:`IntelSourceError` if unavailable."""
        with self._lock:
            now = self._clock()
            if self._memo is not None and now < self._memo[0]:
                return self._memo[1]
            shared = self._from_shared_cache()
            if shared is not None:
                catalog, lifetime = shared
            else:
                if self._failure is not None and now - self._failure[0] < self._backoff:
                    raise IntelSourceError(SOURCE_KEV, "feed unavailable (a recent fetch failed; retry suppressed)",
                                           kind=self._failure[1])
                try:
                    catalog = self._fetch()
                except IntelSourceError as exc:
                    self._failure = (self._clock(), exc.kind)
                    raise
                self._failure = None
                self._cache.set(KEV_CACHE_KEY, {**catalog.to_cache(), "fetched_at": self._wall_clock()}, self._ttl)
                lifetime = float(self._ttl)
            self._memo = (self._clock() + lifetime, catalog)
            return catalog

    def _fetch(self) -> KevCatalog:
        data = translate_http_errors(SOURCE_KEV, self._http.get_json, self._url, max_bytes=self._max_bytes)
        try:
            catalog = parse_kev_feed(data)
        except ValueError as exc:
            raise IntelSourceError(SOURCE_KEV, str(exc), kind="invalid") from exc
        log.info("kev_catalog_loaded", entries=len(catalog), catalog_version=catalog.catalog_version)
        return catalog

    def clear(self) -> None:
        with self._lock:
            self._memo = None
            self._failure = None
