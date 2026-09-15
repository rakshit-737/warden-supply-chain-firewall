"""Vulnerability intelligence service: OSV lookups enriched with CISA KEV, FIRST EPSS and NVD.

``IntelService.batch(packages)`` answers "which published advisories affect these exact
package versions?" in a fixed sequence:

1. **OSV querybatch** for every supported ``(ecosystem, name, version)`` (chunks of 1000,
   pagination followed), results cached per query for ``INTEL_CACHE_TTL_SECONDS``.
2. **OSV hydration** of each distinct advisory id (``GET /v1/vulns/{id}``, cached), parsed
   for the queried package; withdrawn advisories are dropped.
3. **CISA KEV** membership by any CVE alias (feed cached ``KEV_CACHE_TTL_SECONDS``).
4. **FIRST EPSS** scores for CVE aliases (≤100 CVEs per request, cached per CVE).
5. **NVD** (only when ``NVD_ENABLED``) to fill a CVSS v3.x score an advisory lacks.

The central rule is that a failure is never reported as "no vulnerabilities". Each
:class:`~app.intel.models.IntelResult` carries per-source statuses and an overall status:

* ``unavailable`` — OSV could not be queried for this package (or the ecosystem is not
  supported), so vulnerability status is unknown;
* ``partial`` — vulnerabilities were found, but some advisory details or enrichment
  (KEV/EPSS/NVD) could not be retrieved; advisories whose details failed to load are still
  reported (id only) rather than dropped;
* ``disabled`` — ``INTEL_ENABLED=false`` or ``INTEL_OFFLINE=true``; no network is touched;
* ``ok`` — every source that was needed answered.

All HTTP goes through per-source :class:`~app.core.http.SafeHttpClient` instances (single-host
allowlists, HTTPS only, size caps, retries, ``INTEL_RATE_LIMIT_PER_SECOND`` token bucket,
``INTEL_TIMEOUT_SECONDS``). Clients are created lazily, so constructing the service — or
using it in offline mode — performs no network setup. Repeated transport failures during
hydration or NVD lookups trip a small circuit breaker so a dead service cannot stall a scan
for (retries × timeout) per advisory.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core import metrics
from app.core.config import Settings
from app.core.config import settings as global_settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text
from app.intel import nvd as nvd_module
from app.intel.client import CacheBackend, IntelCache, IntelSourceError, build_http_client
from app.intel.epss import EpssClient, EpssLookup
from app.intel.kev import KevCatalog, KevClient
from app.intel.models import (
    ALL_SOURCES,
    SOURCE_EPSS,
    SOURCE_KEV,
    SOURCE_NVD,
    SOURCE_OSV,
    IntelResult,
    IntelStatus,
    SourceStatus,
    Vulnerability,
    normalize_severity,
    utc_now_iso,
)
from app.intel.nvd import NvdClient
from app.intel.osv import OsvClient, OsvQuery, osv_ecosystem, parse_vulnerability

log = get_logger("warden.intel.service")

MODE_ENABLED = "enabled"
MODE_DISABLED = "disabled"
MODE_OFFLINE = "offline"

MAX_NAME_CHARS = 214
MAX_VERSION_CHARS = 128
_CIRCUIT_BREAKER_FAILURES = 3
_TRANSPORT_KINDS = frozenset({"network", "host_not_allowed", "scheme", "redirect"})


@dataclass(eq=False)  # identity semantics: the same package may legitimately appear twice in a batch
class _Lookup:
    """Mutable per-package state while a batch is being assembled."""

    ecosystem: str
    name: str
    version: str
    osv_ecosystem: str | None = None
    vulns: list[Vulnerability] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def osv_answered(self) -> bool:
        return self.sources.get(SOURCE_OSV) in (SourceStatus.OK, SourceStatus.PARTIAL)

    def fail(self, source: str, status: str, message: str) -> None:
        self.sources[source] = status
        self.errors.setdefault(source, sanitize_text(message, max_len=200))


def _coverage_status(needed: set[str], resolved: set[str]) -> str:
    if not needed:
        return SourceStatus.SKIPPED
    got = needed & resolved
    if got == needed:
        return SourceStatus.OK
    return SourceStatus.PARTIAL if got else SourceStatus.ERROR


def _coerce_package(item: Any) -> tuple[str, str, str]:
    if isinstance(item, dict):
        values = (item.get("ecosystem"), item.get("name"), item.get("version"))
    elif isinstance(item, (tuple, list)) and len(item) == 3:
        values = tuple(item)
    elif all(hasattr(item, attr) for attr in ("ecosystem", "name", "version")):
        values = (item.ecosystem, item.name, item.version)
    else:
        raise TypeError("packages must be (ecosystem, name, version) tuples, dicts or objects")
    return tuple("" if v is None else str(v).strip() for v in values)  # type: ignore[return-value]


class IntelService:
    def __init__(
        self,
        *,
        config: Settings | None = None,
        cache: CacheBackend | None = None,
        sleep: Callable[[float], None] | None = None,
        http_client: httpx.Client | None = None,
        osv: OsvClient | None = None,
        kev: KevClient | None = None,
        epss: EpssClient | None = None,
        nvd: NvdClient | None = None,
    ) -> None:
        self._config = config
        self._cache = IntelCache(cache)
        self._sleep = sleep
        self._http_client = http_client
        self._osv, self._kev, self._epss, self._nvd = osv, kev, epss, nvd
        # Injected source clients belong to the caller and survive ``close()``; built ones are rebuilt.
        self._injected = {SOURCE_OSV: osv is not None, SOURCE_KEV: kev is not None,
                          SOURCE_EPSS: epss is not None, SOURCE_NVD: nvd is not None}
        self._owned: list[Any] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ configuration
    @property
    def config(self) -> Settings:
        return self._config if self._config is not None else global_settings

    def mode(self) -> str:
        cfg = self.config
        if not cfg.INTEL_ENABLED:
            return MODE_DISABLED
        if cfg.INTEL_OFFLINE:
            return MODE_OFFLINE
        return MODE_ENABLED

    def _client(self, source: str, base_url: str, *, rate: float | None, max_bytes: int):
        http = build_http_client(
            source, base_url, timeout=float(self.config.INTEL_TIMEOUT_SECONDS), rate_limit_per_second=rate,
            max_response_bytes=max_bytes, sleep=self._sleep, http_client=self._http_client,
        )
        self._owned.append(http)
        return http

    def _get_osv(self) -> OsvClient:
        with self._lock:
            if self._osv is None:
                cfg = self.config
                http = self._client(SOURCE_OSV, cfg.OSV_API_BASE, rate=cfg.INTEL_RATE_LIMIT_PER_SECOND,
                                    max_bytes=16 * 1024 * 1024)
                self._osv = OsvClient(http, self._cache, base_url=cfg.OSV_API_BASE,
                                      ttl_seconds=cfg.INTEL_CACHE_TTL_SECONDS)
            return self._osv

    def _get_kev(self) -> KevClient:
        with self._lock:
            if self._kev is None:
                cfg = self.config
                http = self._client(SOURCE_KEV, cfg.KEV_FEED_URL, rate=cfg.INTEL_RATE_LIMIT_PER_SECOND,
                                    max_bytes=32 * 1024 * 1024)
                self._kev = KevClient(http, self._cache, feed_url=cfg.KEV_FEED_URL,
                                      ttl_seconds=cfg.KEV_CACHE_TTL_SECONDS)
            return self._kev

    def _get_epss(self) -> EpssClient:
        with self._lock:
            if self._epss is None:
                cfg = self.config
                http = self._client(SOURCE_EPSS, cfg.EPSS_API_BASE, rate=cfg.INTEL_RATE_LIMIT_PER_SECOND,
                                    max_bytes=4 * 1024 * 1024)
                self._epss = EpssClient(http, self._cache, base_url=cfg.EPSS_API_BASE,
                                        ttl_seconds=cfg.EPSS_CACHE_TTL_SECONDS)
            return self._epss

    def _get_nvd(self) -> NvdClient:
        with self._lock:
            if self._nvd is None:
                cfg = self.config
                key = cfg.NVD_API_KEY or None
                rate = nvd_module.RATE_PER_SECOND_WITH_KEY if key else nvd_module.RATE_PER_SECOND_ANONYMOUS
                rate = min(rate, cfg.INTEL_RATE_LIMIT_PER_SECOND) if cfg.INTEL_RATE_LIMIT_PER_SECOND > 0 else rate
                http = self._client(SOURCE_NVD, cfg.NVD_API_BASE, rate=rate, max_bytes=4 * 1024 * 1024)
                self._nvd = NvdClient(http, self._cache, base_url=cfg.NVD_API_BASE, api_key=key,
                                      ttl_seconds=cfg.INTEL_CACHE_TTL_SECONDS)
            return self._nvd

    def close(self) -> None:
        """Close the HTTP clients this service created.

        The service remains usable: source clients it built are dropped and rebuilt lazily on the
        next lookup (a closed ``httpx.Client`` cannot send requests). Injected clients are kept.
        """
        with self._lock:
            for http in self._owned:
                try:
                    http.close()
                except Exception as exc:  # pragma: no cover - best effort: closing must never fail the caller
                    log.debug("intel_http_close_failed", error_type=type(exc).__name__)
            self._owned.clear()
            if not self._injected[SOURCE_OSV]:
                self._osv = None
            if not self._injected[SOURCE_KEV]:
                self._kev = None
            if not self._injected[SOURCE_EPSS]:
                self._epss = None
            if not self._injected[SOURCE_NVD]:
                self._nvd = None

    # ------------------------------------------------------------------ public API
    def package_vulnerabilities(self, ecosystem: str, name: str, version: str) -> IntelResult:
        """Intelligence for one exact package version."""
        return self.batch([(ecosystem, name, version)])[0]

    def batch(self, packages: Iterable[Any]) -> list[IntelResult]:
        """Intelligence for many package versions; results are in the same order as ``packages``.

        Each item is an ``(ecosystem, name, version)`` tuple, a dict with those keys, or an
        object with those attributes.

        Metrics: ``intel_requests_total{source,status}`` is incremented once per package lookup for
        every source that was consulted, labelled with that source's outcome (``ok`` / ``partial`` /
        ``error`` / ``unsupported``). Skipped and disabled sources are not counted, and cache hits
        are not distinguished from network answers at this level.
        """
        items = [_coerce_package(p) for p in packages]
        fetched_at = utc_now_iso()
        lookups = [_Lookup(sanitize_text(eco, max_len=40), sanitize_text(name, max_len=MAX_NAME_CHARS),
                           sanitize_text(ver, max_len=MAX_VERSION_CHARS))
                   for eco, name, ver in items]
        mode = self.mode()
        if mode != MODE_ENABLED:
            return [self._finish(lk, fetched_at, disabled=True) for lk in lookups]
        if not lookups:
            return []

        self._query_osv(items, lookups)
        with_vulns = {lk for lk in lookups if lk.osv_answered and lk.vulns}
        self._apply_kev(lookups, with_vulns)
        self._apply_epss(lookups, with_vulns)
        self._apply_nvd(lookups, with_vulns)
        results = [self._finish(lk, fetched_at) for lk in lookups]
        for result in results:
            for source, status in result.sources.items():
                if status not in (SourceStatus.SKIPPED, SourceStatus.DISABLED):
                    metrics.inc_intel(source, status)
        return results

    # ------------------------------------------------------------------ stages
    def _query_osv(self, items: Sequence[tuple[str, str, str]], lookups: list[_Lookup]) -> None:
        queries: list[OsvQuery] = []
        index: list[int] = []
        for i, ((eco, name, version), lk) in enumerate(zip(items, lookups)):
            lk.osv_ecosystem = osv_ecosystem(eco)
            if lk.osv_ecosystem is None:
                lk.fail(SOURCE_OSV, SourceStatus.UNSUPPORTED, "ecosystem is not supported by OSV")
            elif not name or not version or len(name) > MAX_NAME_CHARS or len(version) > MAX_VERSION_CHARS:
                lk.fail(SOURCE_OSV, SourceStatus.ERROR, "an exact package name and version are required")
            else:
                queries.append(OsvQuery(lk.osv_ecosystem, name, version))
                index.append(i)
        if not queries:
            return
        try:
            outcomes = self._get_osv().query_batch(queries)
        except Exception as exc:  # defensive: query_batch reports source failures in outcomes
            log.error("osv_query_unexpected_error", error_type=type(exc).__name__)
            for i in index:
                lookups[i].fail(SOURCE_OSV, SourceStatus.ERROR, f"unexpected error ({type(exc).__name__})")
            return

        records, failures = self._hydrate(o for o in outcomes if o.error is None)
        for i, outcome in zip(index, outcomes):
            lk = lookups[i]
            if outcome.error is not None:
                lk.fail(SOURCE_OSV, SourceStatus.ERROR, outcome.error)
                continue
            problems = [outcome.incomplete] if outcome.incomplete else []
            for vid, modified in outcome.vulns:
                vuln: Vulnerability | None = None
                record = records.get(vid)
                if record is not None:
                    try:
                        vuln = parse_vulnerability(record, ecosystem=lk.osv_ecosystem or "", name=lk.name)
                    except Exception as exc:  # hostile/unexpected record shape must not crash the scan
                        log.warning("osv_parse_failed", advisory=vid, error_type=type(exc).__name__)
                    if vuln is None:
                        problems.append(f"advisory {vid} could not be parsed")
                else:
                    problems.append(failures.get(vid, f"advisory {vid} could not be retrieved"))
                if vuln is None:
                    # OSV matched this exact version: report the id rather than hide a known match.
                    vuln = Vulnerability(id=vid, modified=modified, sources=[SOURCE_OSV])
                if vuln.withdrawn:
                    continue
                lk.vulns.append(vuln)
            lk.sources[SOURCE_OSV] = SourceStatus.PARTIAL if problems else SourceStatus.OK
            if problems:
                lk.errors[SOURCE_OSV] = sanitize_text(problems[0], max_len=200)

    def _hydrate(self, outcomes: Iterable[Any]) -> tuple[dict[str, dict], dict[str, str]]:
        wanted: dict[str, str | None] = {}
        for outcome in outcomes:
            for vid, modified in outcome.vulns:
                wanted.setdefault(vid, modified)
        records: dict[str, dict] = {}
        failures: dict[str, str] = {}
        client = self._get_osv() if wanted else None
        consecutive = 0
        for vid, modified in wanted.items():
            if consecutive >= _CIRCUIT_BREAKER_FAILURES:
                failures[vid] = "osv: skipped after repeated transport failures"
                continue
            try:
                records[vid] = client.get_vulnerability(vid, modified)  # type: ignore[union-attr]
                consecutive = 0
            except IntelSourceError as exc:
                failures[vid] = str(exc)
                consecutive = consecutive + 1 if exc.kind in _TRANSPORT_KINDS else 0
            except Exception as exc:
                failures[vid] = f"osv: unexpected error ({type(exc).__name__})"
                log.error("osv_hydrate_unexpected_error", advisory=vid, error_type=type(exc).__name__)
        if failures:
            log.warning("osv_hydration_incomplete", failed=len(failures), total=len(wanted))
        return records, failures

    def _apply_kev(self, lookups: list[_Lookup], with_vulns: set[_Lookup]) -> None:
        catalog: KevCatalog | None = None
        error: str | None = None
        if with_vulns:
            try:
                catalog = self._get_kev().catalog()
            except IntelSourceError as exc:
                error = str(exc)
            except Exception as exc:
                error = f"cisa-kev: unexpected error ({type(exc).__name__})"
                log.error("kev_unexpected_error", error_type=type(exc).__name__)
            if error:
                log.warning("kev_unavailable", error=error)
        for lk in lookups:
            if lk not in with_vulns:
                lk.sources[SOURCE_KEV] = SourceStatus.SKIPPED
            elif catalog is None:
                lk.fail(SOURCE_KEV, SourceStatus.ERROR, error or "cisa-kev: unavailable")
            else:
                lk.sources[SOURCE_KEV] = SourceStatus.OK
                for vuln in lk.vulns:
                    hit = catalog.lookup(vuln.cve_ids())
                    if hit:
                        vuln.kev, vuln.kev_date_added = True, hit[1]
                        vuln.add_source(SOURCE_KEV)

    def _apply_epss(self, lookups: list[_Lookup], with_vulns: set[_Lookup]) -> None:
        # Iterate ``lookups`` (not the set) so request contents follow the batch order deterministically.
        all_cves: dict[str, None] = {}
        for lk in lookups:
            if lk in with_vulns:
                for vuln in lk.vulns:
                    for cve in vuln.cve_ids():
                        all_cves[cve] = None
        result = EpssLookup()
        if all_cves:
            try:
                result = self._get_epss().lookup(list(all_cves))
            except Exception as exc:  # defensive: lookup reports source failures in ``errors``
                result.errors.append(f"first-epss: unexpected error ({type(exc).__name__})")
                log.error("epss_unexpected_error", error_type=type(exc).__name__)
        for lk in lookups:
            needed = {c for v in lk.vulns for c in v.cve_ids()} if lk in with_vulns else set()
            status = _coverage_status(needed, result.resolved)
            if status in (SourceStatus.ERROR, SourceStatus.PARTIAL):
                lk.fail(SOURCE_EPSS, status, result.errors[0] if result.errors else "first-epss: incomplete answer")
            else:
                lk.sources[SOURCE_EPSS] = status
            for vuln in lk.vulns:
                scores = [result.scores[c] for c in vuln.cve_ids() if c in result.scores]
                if scores:
                    best = max(scores, key=lambda s: s.epss)
                    vuln.epss_score, vuln.epss_percentile = best.epss, best.percentile
                    vuln.add_source(SOURCE_EPSS)

    def _apply_nvd(self, lookups: list[_Lookup], with_vulns: set[_Lookup]) -> None:
        if not self.config.NVD_ENABLED:
            for lk in lookups:
                lk.sources[SOURCE_NVD] = SourceStatus.DISABLED
            return
        needed_by: dict[int, set[str]] = {}
        ordered: list[str] = []
        for pos, lk in enumerate(lookups):
            needed_by[pos] = set()
            if lk not in with_vulns:
                continue
            for vuln in lk.vulns:
                cves = vuln.cve_ids()
                if vuln.cvss_score is None and cves:
                    needed_by[pos].add(cves[0])
                    if cves[0] not in ordered:
                        ordered.append(cves[0])
        scores: dict[str, Any] = {}
        errors: list[str] = []
        if ordered:
            client = self._get_nvd()
            limit = client.max_lookups_per_batch
            for n, cve in enumerate(ordered):
                if n >= limit:
                    errors.append("nvd: lookup limit per batch reached")
                    break
                try:
                    scores[cve] = client.cvss_for(cve)
                except IntelSourceError as exc:
                    errors.append(str(exc))
                    log.warning("nvd_lookup_failed", error=str(exc))
                    break  # rate limited or down: further calls would only stall the scan
                except Exception as exc:
                    errors.append(f"nvd: unexpected error ({type(exc).__name__})")
                    log.error("nvd_unexpected_error", error_type=type(exc).__name__)
                    break
        for pos, lk in enumerate(lookups):
            status = _coverage_status(needed_by[pos], set(scores))
            if status in (SourceStatus.ERROR, SourceStatus.PARTIAL):
                lk.fail(SOURCE_NVD, status, errors[0] if errors else "nvd: incomplete answer")
            else:
                lk.sources[SOURCE_NVD] = status
            for vuln in lk.vulns:
                cves = vuln.cve_ids()
                scored = scores.get(cves[0]) if vuln.cvss_score is None and cves else None
                if scored is not None:
                    vuln.cvss_score, vuln.cvss_vector, vuln.cvss_version = (
                        scored.base_score, scored.vector, scored.version)
                    if vuln.severity == "unknown":
                        vuln.severity = normalize_severity(scored.rating)
                    vuln.add_source(SOURCE_NVD)

    # ------------------------------------------------------------------ result
    def _finish(self, lk: _Lookup, fetched_at: str, *, disabled: bool = False) -> IntelResult:
        if disabled:
            sources = dict.fromkeys(ALL_SOURCES, SourceStatus.DISABLED)
            status = IntelStatus.DISABLED
        else:
            sources = {s: lk.sources.get(s, SourceStatus.SKIPPED) for s in ALL_SOURCES}
            if sources[SOURCE_OSV] in (SourceStatus.ERROR, SourceStatus.UNSUPPORTED):
                status = IntelStatus.UNAVAILABLE
            elif any(v in (SourceStatus.ERROR, SourceStatus.PARTIAL) for v in sources.values()):
                status = IntelStatus.PARTIAL
            else:
                status = IntelStatus.OK
        return IntelResult(
            vulnerabilities=sorted(lk.vulns, key=lambda v: v.id),
            status=status,
            sources=sources,
            fetched_at=fetched_at,
            ecosystem=lk.ecosystem or None,
            name=lk.name or None,
            version=lk.version or None,
            errors=dict(lk.errors),
        )


_service: IntelService | None = None
_service_lock = threading.Lock()


def get_intel_service() -> IntelService:
    """Process-wide service (configured from ``app.core.config.settings``)."""
    global _service
    with _service_lock:
        if _service is None:
            _service = IntelService()
        return _service


def reset_intel_service(service: IntelService | None = None) -> None:
    """Test hook: close the current singleton and optionally install a replacement."""
    global _service
    with _service_lock:
        old, _service = _service, service
    if old is not None and old is not service:
        old.close()
