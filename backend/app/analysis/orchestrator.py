"""Analysis orchestrator — the Warden package-analysis pipeline.

Pipeline for ``Orchestrator.analyze(ecosystem, name, version, options)``:

1. **Cache lookup.** The key covers the package coordinates, ``ANALYZER_VERSION``, the
   selected analyzers (names + versions), the fusion mode, every scan option that changes
   results (effective offline, intel, provenance, wheel analysis, private namespaces,
   project context) and the settings that switch data sources on or off (``INTEL_ENABLED``,
   ``NVD_ENABLED``, ``PROVENANCE_ENABLED``, ``ANALYZE_WHEELS``, ``DEPCONF_ALLOW_PUBLIC_LOOKUP``).
   Lookups are counted in ``cache_requests_total`` by the cache client itself (once per lookup).
2. **Fetch.** ``fetcher.build_context(name, version, options)`` builds the hostile-input
   ``PackageContext``; fetchers with the v1 two-argument signature are still supported.
   ``AnalysisError`` (package not found, registry unreachable) propagates to the caller.
3. **Analyzers, concurrently.** Analyzers from ``get_analyzers()`` run in a per-scan
   ``ThreadPoolExecutor`` (``ANALYZER_WORKERS``). Each has ``ANALYZER_TIMEOUT_SECONDS``
   measured from when it starts running, and the whole scan has ``SCAN_TIMEOUT_SECONDS``
   measured from the start of ``analyze``. ``requires_network`` analyzers are skipped in
   offline scans; an analyzer whose ``availability()`` reports unavailable yields an info
   ``TOOL_UNAVAILABLE`` finding. A crash, timeout or malformed return value yields
   ``ANALYZER_ERROR`` (medium, weight 2.0, confidence 1.0) whose evidence holds only the
   exception *type*: exception messages can contain package content or secrets, so they are
   neither stored nor logged. Every finding is stamped with ``with_defaults(analyzer=…,
   analyzer_version=…)``, and findings are emitted in registry order regardless of
   completion order, so output is deterministic. If the configuration
   (``ENABLED_ANALYZERS`` / ``DISABLED_ANALYZERS``) selects no analyzer at all, the scan
   records an ``ANALYZER_ERROR`` for the ``analyzer_registry`` stage rather than returning
   a verdict built from zero analysis. Each run is counted via :mod:`app.core.metrics`.
4. **Correlation.** ``correlation.engine.correlate`` (a phase-2 stub today) may add
   attack chains and derived findings.
5. **Risk.** :func:`app.analysis.risk.assess` produces the Risk Engine 2.0 breakdown;
   ``risk_score``/``severity`` come from it, and the v1 rule/ML fusion is preserved as
   ``malicious_risk``. ``vulnerabilities`` and ``intel_status`` are derived from the
   vulnerability analyzer's findings and run record: ``not_run`` when no vulnerability
   analyzer ran or it was skipped offline; ``disabled`` when intelligence is switched off by
   configuration or by the scan's ``intel`` option (the registered vulnerability analyzer then
   emits an info ``INTEL_UNAVAILABLE`` finding with status ``disabled``; an analyzer that
   instead returns nothing for a scan with ``intel`` off yields ``not_run``). None of these
   ever reads as "no known vulnerabilities".
6. **Cache store** — except when the result is incomplete (``ANALYZER_ERROR``,
   ``FETCH_FAILED``) or vulnerability intelligence failed transiently (``unavailable`` /
   ``partial``). Incomplete verdicts fail closed and are retried on the next request
   instead of being served for the cache TTL. ``not_run`` / ``disabled`` intel statuses
   come from configuration or scan options, all of which are part of the cache key (so
   switching intelligence back on can never serve a stale "not consulted" verdict); those
   verdicts are cached normally.

Python threads cannot be forcibly stopped: a timed-out analyzer's result is discarded and
the scan proceeds, but its thread keeps running until the analyzer returns. Analyzers are
expected to be bounded by the input caps enforced during extraction.

The orchestrator contains no HTTP or DB code, which keeps it unit-testable in isolation
(see tests/test_orchestrator.py).
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import inspect
import json
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from app.analysis import analyzers as analyzer_registry
from app.analysis import risk as risk_engine
from app.analysis.analyzers.base import PackageContext, ScanOptions
from app.analysis.correlation import engine as correlation_engine
from app.analysis.fetcher import RegistryFetcher
from app.analysis.findings import Finding, Severity, sort_key
from app.analysis.model_store import get_model_store
from app.analysis.signals import Code, Signal
from app.core import metrics
from app.core.cache import cache
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_evidence, sanitize_text

log = get_logger("warden.orchestrator")

PIPELINE_PROVENANCE = "analysis-pipeline"
FETCH_STAGE_NAME = "acquisition"
CORRELATION_STAGE_NAME = "correlation"
REGISTRY_STAGE_NAME = "analyzer_registry"
VERDICT_CACHE_NAME = "verdict"
# Bound on findings kept per analyzer: a hostile package must not be able to make one
# analyzer emit an unbounded number of findings. The most important ones are kept.
MAX_FINDINGS_PER_ANALYZER = 500
# Poll interval while some analyzers are queued but not yet started (their deadline is not
# known until they start).
_QUEUE_POLL_SECONDS = 0.05
_NON_CACHEABLE_CODES = frozenset({Code.ANALYZER_ERROR, Code.FETCH_FAILED})
_NON_CACHEABLE_INTEL = frozenset({"unavailable", "partial"})
_PROVENANCE_CODES = (Code.PROVENANCE_FAILED, Code.PROVENANCE_ATTESTED, Code.PROVENANCE_UNVERIFIED)
_RESULT_CHANGING_SETTINGS = (
    "INTEL_ENABLED", "NVD_ENABLED", "PROVENANCE_ENABLED", "ANALYZE_WHEELS", "DEPCONF_ALLOW_PUBLIC_LOOKUP",
)


@dataclass
class AnalysisResult:
    # --- v1 fields: positional order is a compatibility contract -------------------
    ecosystem: str
    name: str
    version: str
    rule_score: int
    ml_score: int
    risk_score: int
    severity: str
    features: dict
    signals: list[dict]
    analyzer_version: str
    duration_ms: int
    ml_available: bool
    cached: bool = False
    capabilities: list[str] = field(default_factory=list)
    # --- Warden 2 fields ------------------------------------------------------------
    risk: dict = field(default_factory=dict)
    attack_chains: list[dict] = field(default_factory=list)
    analyzer_runs: list[dict] = field(default_factory=list)
    package_intel: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)
    vulnerabilities: list[dict] = field(default_factory=list)
    intel_status: dict = field(default_factory=dict)
    model_version: str | None = None
    explanation: dict = field(default_factory=dict)
    scan_options: dict = field(default_factory=dict)
    # Bounded per-member listing (path, size, sha256, kind, executable) used by release diffs.
    file_inventory: list[dict] = field(default_factory=list)


_RESULT_FIELDS = frozenset(f.name for f in fields(AnalysisResult))


# --------------------------------------------------------------------------- options / cache
def _effective_offline(options: ScanOptions) -> bool:
    return bool(options.offline or settings.INTEL_OFFLINE)


def _options_dict(options: ScanOptions) -> dict[str, Any]:
    raw = asdict(options)
    raw["private_namespaces"] = sorted(str(p) for p in (options.private_namespaces or ()))
    raw["effective_offline"] = _effective_offline(options)
    return sanitize_evidence(raw)


def _cache_key(
    ecosystem: str,
    name: str,
    version: str | None,
    options: ScanOptions | None = None,
    analyzers: Sequence[Any] | None = None,
) -> str:
    options = options or ScanOptions()
    material = {
        "coordinates": [ecosystem, name, version or "latest"],
        "analyzer_version": settings.ANALYZER_VERSION,
        "analyzers": [[str(getattr(a, "name", "")), str(getattr(a, "version", ""))] for a in (analyzers or ())],
        "fusion": settings.SCORE_FUSION,
        "options": {
            "offline": _effective_offline(options),
            "intel": bool(options.intel),
            "provenance": bool(options.provenance),
            "analyze_wheels": bool(options.analyze_wheels),
            "private_namespaces": sorted(str(p) for p in (options.private_namespaces or ())),
            "project_context": options.project_context,
        },
        # Configuration that changes which data sources a scan consults.
        "config": {name: bool(getattr(settings, name, False)) for name in _RESULT_CHANGING_SETTINGS},
    }
    raw = json.dumps(material, sort_keys=True, default=str, separators=(",", ":"))
    return "verdict:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- findings helpers
def _pipeline_finding(code: str, severity: Severity, weight: float, message: str, evidence: dict) -> Finding:
    return Finding(code, severity, weight, message, evidence, confidence=1.0, provenance=PIPELINE_PROVENANCE)


def _analyzer_error(name: str, status: str, error_type: str) -> Finding:
    reason = "timed out" if status == "timeout" else "failed"
    return _pipeline_finding(
        Code.ANALYZER_ERROR, Severity.medium, 2.0,
        f"Analyzer '{name}' {reason}; analysis is incomplete",
        {"analyzer": name, "status": status, "error_type": error_type},
    )


def _tool_unavailable(name: str, status: Any) -> Finding:
    return _pipeline_finding(
        Code.TOOL_UNAVAILABLE, Severity.info, 0.0,
        f"Analyzer '{name}' skipped: its tool or data source is unavailable",
        {
            "analyzer": name,
            "tool": getattr(status, "name", None),
            "version": getattr(status, "version", None),
            "detail": getattr(status, "detail", None),
        },
    )


def _no_analyzers_selected() -> Finding:
    finding = _pipeline_finding(
        Code.ANALYZER_ERROR, Severity.medium, 2.0,
        "No analyzers were selected by configuration; analysis is incomplete",
        {"analyzer": REGISTRY_STAGE_NAME, "status": "error", "error_type": "NoAnalyzersSelected"},
    )
    return finding.with_defaults(analyzer=REGISTRY_STAGE_NAME, analyzer_version=settings.ANALYZER_VERSION)


def _run_record(name: str, version: str | None, status: str, duration_ms: int, finding_count: int,
                detail: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "status": status,
        "duration_ms": int(max(0, duration_ms)),
        "finding_count": int(finding_count),
        "detail": sanitize_text(detail, max_len=200) if detail else None,
    }


@dataclass
class _Outcome:
    findings: list[Finding]
    run: dict[str, Any]


def _invoke(analyzer: Any, ctx: PackageContext, index: int, started: dict[int, float],
            lock: threading.Lock) -> tuple[str, Any, float]:
    """Worker body: availability check then analyze. Exceptions propagate to the future."""
    begin = time.monotonic()
    with lock:
        started[index] = begin
    availability = getattr(analyzer, "availability", None)
    if callable(availability):
        status = availability()
        if not getattr(status, "available", True):
            return "unavailable", status, time.monotonic() - begin
    return "ok", analyzer.analyze(ctx), time.monotonic() - begin


def _call_build_context(fetcher: Any, name: str, version: str | None, options: ScanOptions) -> PackageContext:
    """Call ``build_context(name, version, options)``, or ``(name, version)`` for v1 fetchers."""
    build = fetcher.build_context
    try:
        signature = inspect.signature(build)
    except (TypeError, ValueError):
        return build(name, version, options)
    params = list(signature.parameters.values())
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    if any(p.kind is p.VAR_POSITIONAL for p in params) or len(positional) >= 3:
        return build(name, version, options)
    if "options" in signature.parameters or any(p.kind is p.VAR_KEYWORD for p in params):
        return build(name, version, options=options)
    return build(name, version)


def _chain_dict(chain: Any) -> dict:
    if hasattr(chain, "to_dict"):
        return sanitize_evidence(chain.to_dict())
    if isinstance(chain, Mapping):
        return sanitize_evidence(dict(chain))
    return {"value": sanitize_text(chain)}


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        fid = f.finding_id
        if fid not in seen:
            seen.add(fid)
            out.append(f)
    return out


def _model_version() -> str | None:
    try:
        store = get_model_store()
    except Exception:  # model loading problems must not fail a scan
        return None
    version = getattr(store, "model_version", None)
    if not version:
        meta = getattr(store, "metadata", None) or {}
        version = (meta.get("model_version") or meta.get("version")) if isinstance(meta, Mapping) else None
    return sanitize_text(version, max_len=64) if version else None


# --------------------------------------------------------------------------- summaries
MAX_FILE_INVENTORY = 5000


def file_inventory(ctx: Any) -> list[dict[str, Any]]:
    """The archive members safe extraction saw, sorted by path and bounded."""
    rows = []
    for entry in sorted(getattr(ctx, "inventory", None) or [], key=lambda e: e.relpath)[:MAX_FILE_INVENTORY]:
        rows.append({
            "path": sanitize_text(entry.relpath, max_len=300),
            "size": entry.size,
            "sha256": entry.sha256,
            "kind": entry.kind,
            "executable": bool(entry.is_executable_binary),
        })
    return rows


def package_intel_summary(ctx: Any) -> dict[str, Any]:
    """Facts about the analysed release. ``None`` means "not known", never "zero"."""
    md = getattr(ctx, "metadata", None) or {}
    art = getattr(ctx, "analyzed_artifact", None)
    releases = list(getattr(ctx, "releases", None) or [])
    inventory = list(getattr(ctx, "inventory", None) or [])
    version = getattr(ctx, "version", None)

    def release(r: Any) -> dict | None:
        return {"version": r.version, "upload_time": r.upload_time, "yanked": r.yanked} if r else None

    previous = None
    for i, r in enumerate(releases):
        if r.version == version and i > 0:
            previous = releases[i - 1]
            break

    artifact = None
    if art is not None:
        artifact = {
            "filename": art.filename,
            "packagetype": art.packagetype,
            "size": art.size,
            "sha256": (art.digests or {}).get("sha256"),
            "downloaded_sha256": art.downloaded_sha256,
            "hash_verified": art.hash_verified,
            "upload_time": art.upload_time,
            "yanked": art.yanked,
            "yanked_reason": art.yanked_reason,
            "requires_python": art.requires_python,
        }

    inventory_summary = None
    if inventory:
        kinds = Counter(str(e.kind) for e in inventory)
        inventory_summary = {
            "total": len(inventory),
            "by_kind": dict(sorted(kinds.items())),
            "executable_binaries": sum(1 for e in inventory if e.is_executable_binary),
            "skipped": sum(1 for e in inventory if e.skipped_reason),
        }

    requires_dist = md.get("requires_dist") if isinstance(md, Mapping) else None
    summary = {
        "artifact": artifact,
        "artifact_count": len(getattr(ctx, "artifacts", None) or []) or None,
        "release_count": len(releases) or None,
        "first_release": release(releases[0]) if releases else None,
        "previous_release": release(previous),
        "inventory": inventory_summary,
        "files_analyzed": len(getattr(ctx, "files", None) or []),
        "binaries_count": len(getattr(ctx, "binaries", None) or {}),
        "maintainers": {
            "count": md.get("_maintainer_count"),
            "author": md.get("author"),
            "maintainer": md.get("maintainer"),
            "maintainers": md.get("maintainers"),
        },
        "requires_dist_count": len(requires_dist) if isinstance(requires_dist, list) else None,
        "age_days": md.get("_age_days"),
    }
    return sanitize_evidence(summary, max_items=50)


def provenance_summary(findings: Sequence[Finding], ctx: Any) -> dict[str, Any]:
    """Provenance verdict from provenance findings; ``not_run`` when none were produced."""
    by_code: dict[str, list[Finding]] = {}
    for f in findings:
        by_code.setdefault(f.code, []).append(f)
    status, decisive = "not_run", None
    for code, label in zip(_PROVENANCE_CODES, ("failed", "attested", "unverified")):
        if by_code.get(code):
            status, decisive = label, by_code[code][0]
            break
    art = getattr(ctx, "analyzed_artifact", None)
    hash_verified = getattr(art, "hash_verified", None)
    if by_code.get(Code.HASH_MISMATCH):
        hash_verified = False
    related_codes = (*_PROVENANCE_CODES, Code.REPO_MISMATCH, Code.HASH_MISMATCH)
    related = [f for code in related_codes for f in by_code.get(code, [])]
    return {
        "status": status,
        "hash_verified": hash_verified,
        "repo_mismatch": bool(by_code.get(Code.REPO_MISMATCH)),
        "finding_ids": [f.finding_id for f in related],
        "evidence": dict(decisive.evidence) if decisive else {},
    }


def _explanation(findings: Sequence[Finding], breakdown: risk_engine.RiskBreakdown) -> dict[str, Any]:
    top = sorted(findings, key=lambda f: (sort_key(f), f.finding_id))[:5]
    return {
        "method": "rule-contributions",
        "rule_contributions": breakdown.rule_contributions[:20],
        "top_findings": [
            {"finding_id": f.finding_id, "code": f.code, "severity": f.severity.value,
             "confidence": f.confidence, "title": f.title}
            for f in top
        ],
        "ml": {
            "available": breakdown.ml_available,
            "ml_score": breakdown.ml_score,
            "anomaly_score": round(breakdown.anomaly_score, 3),
        },
    }


# --------------------------------------------------------------------------- orchestrator
class Orchestrator:
    def __init__(
        self,
        fetcher: RegistryFetcher | None = None,
        *,
        analyzers: Sequence[Any] | Callable[[], Sequence[Any]] | None = None,
        cache_backend: Any = None,
    ) -> None:
        # Lazily instantiated so constructing the orchestrator (done at import in the
        # router) performs no network-client setup.
        self._fetcher_override = fetcher
        self._fetcher_instance: RegistryFetcher | None = None
        self._analyzers = analyzers
        self._cache = cache_backend

    @property
    def _fetcher(self) -> RegistryFetcher:
        if self._fetcher_override is not None:
            return self._fetcher_override
        if self._fetcher_instance is None:
            self._fetcher_instance = RegistryFetcher()
        return self._fetcher_instance

    @property
    def _cache_backend(self) -> Any:
        return self._cache if self._cache is not None else cache

    def _selected_analyzers(self) -> list[Any]:
        if self._analyzers is None:
            return list(analyzer_registry.get_analyzers())
        if callable(self._analyzers):
            return list(self._analyzers())
        return list(self._analyzers)

    # ------------------------------------------------------------------ cache
    def _cache_get(self, key: str) -> AnalysisResult | None:
        # Hit/miss/error metrics are recorded by CacheClient.get_json (the "verdict:" key prefix
        # names the cache); counting here as well would double every lookup.
        try:
            payload = self._cache_backend.get_json(key)
        except Exception as exc:  # cache outages degrade to "miss"
            log.warning("verdict_cache_read_failed", error_type=type(exc).__name__)
            return None
        result: AnalysisResult | None = None
        if isinstance(payload, dict):
            try:
                result = AnalysisResult(**{k: v for k, v in payload.items() if k in _RESULT_FIELDS})
            except TypeError:  # payload from an incompatible version: treat as a miss
                log.info("verdict_cache_payload_incompatible")
                result = None
        if result is not None:
            result.cached = True
        return result

    def _cache_set(self, key: str, result: AnalysisResult) -> None:
        try:
            self._cache_backend.set_json(key, asdict(result), settings.VERDICT_CACHE_TTL_SECONDS)
        except Exception as exc:
            log.warning("verdict_cache_write_failed", error_type=type(exc).__name__)

    # ------------------------------------------------------------------ analyzers
    def _run_analyzers(self, analyzers: list[Any], ctx: PackageContext, options: ScanOptions,
                       deadline: float) -> list[_Outcome]:
        outcomes: dict[int, _Outcome] = {}
        offline = _effective_offline(options)
        runnable: list[tuple[int, Any]] = []
        for index, analyzer in enumerate(analyzers):
            name, version = str(analyzer.name), getattr(analyzer, "version", None)
            if getattr(analyzer, "requires_network", False) and offline:
                outcomes[index] = _Outcome([], _run_record(name, version, "skipped", 0, 0, "offline"))
            else:
                runnable.append((index, analyzer))

        if runnable:
            self._execute(runnable, ctx, deadline, outcomes)
        return [outcomes[i] for i in sorted(outcomes)]

    def _execute(self, runnable: list[tuple[int, Any]], ctx: PackageContext, deadline: float,
                 outcomes: dict[int, _Outcome]) -> None:
        per_timeout = max(0.001, float(settings.ANALYZER_TIMEOUT_SECONDS))
        workers = max(1, min(int(settings.ANALYZER_WORKERS), len(runnable)))
        started: dict[int, float] = {}
        lock = threading.Lock()
        pool = cf.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="warden-analyzer")
        try:
            futures = {pool.submit(_invoke, a, ctx, i, started, lock): (i, a) for i, a in runnable}
            pending = set(futures)
            while pending:
                with lock:
                    starts = {f: started.get(futures[f][0]) for f in pending}
                now = time.monotonic()
                horizon = min([deadline] + [s + per_timeout for s in starts.values() if s is not None])
                wait_for = max(0.0, horizon - now)
                if any(s is None for s in starts.values()):
                    wait_for = min(wait_for, _QUEUE_POLL_SECONDS)
                done, pending = cf.wait(pending, timeout=wait_for, return_when=cf.FIRST_COMPLETED)
                for future in done:
                    index, analyzer = futures[future]
                    outcomes[index] = self._collect(future, analyzer)

                now = time.monotonic()
                expired: set[cf.Future] = set()
                for future in pending:
                    if future.done():
                        continue  # collected on the next iteration
                    index, analyzer = futures[future]
                    with lock:
                        began = started.get(index)
                    if began is not None and now >= began + per_timeout:
                        detail = f"exceeded analyzer timeout ({per_timeout:g}s)"
                    elif now >= deadline:
                        detail = "exceeded scan timeout" if began is not None else "scan timeout before start"
                    else:
                        continue
                    future.cancel()
                    expired.add(future)
                    elapsed = int((now - began) * 1000) if began is not None else 0
                    name = str(analyzer.name)
                    log.error("analyzer_timeout", analyzer=name, detail=detail)
                    finding = _analyzer_error(name, "timeout", "TimeoutError")
                    outcomes[index] = _Outcome(
                        [self._stamp(finding, analyzer)],
                        _run_record(name, getattr(analyzer, "version", None), "timeout", elapsed, 1, detail),
                    )
                pending -= expired
        finally:
            # Never wait for hung analyzers; queued ones are cancelled.
            pool.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _stamp(finding: Finding, analyzer: Any) -> Finding:
        return finding.with_defaults(analyzer=str(analyzer.name), analyzer_version=getattr(analyzer, "version", None))

    def _collect(self, future: cf.Future, analyzer: Any) -> _Outcome:
        name, version = str(analyzer.name), getattr(analyzer, "version", None)
        try:
            status, payload, elapsed = future.result()
        except BaseException as exc:  # any analyzer failure (even SystemExit) must fail closed
            if isinstance(exc, KeyboardInterrupt):
                raise
            error_type = type(exc).__name__
            log.error("analyzer_error", analyzer=name, error_type=error_type)
            finding = self._stamp(_analyzer_error(name, "error", error_type), analyzer)
            return _Outcome([finding], _run_record(name, version, "error", 0, 1, error_type))

        duration_ms = int(elapsed * 1000)
        if status == "unavailable":
            finding = self._stamp(_tool_unavailable(name, payload), analyzer)
            detail = getattr(payload, "detail", None) or "unavailable"
            return _Outcome([finding], _run_record(name, version, "unavailable", duration_ms, 1, detail))

        if not isinstance(payload, (list, tuple)) or not all(isinstance(f, Finding) for f in payload):
            log.error("analyzer_error", analyzer=name, error_type="InvalidAnalyzerOutput")
            finding = self._stamp(_analyzer_error(name, "error", "InvalidAnalyzerOutput"), analyzer)
            return _Outcome([finding], _run_record(name, version, "error", duration_ms, 1, "InvalidAnalyzerOutput"))

        produced = list(payload)
        detail = None
        if len(produced) > MAX_FINDINGS_PER_ANALYZER:
            detail = f"findings truncated from {len(produced)} to {MAX_FINDINGS_PER_ANALYZER}"
            produced = sorted(produced, key=sort_key)[:MAX_FINDINGS_PER_ANALYZER]
        stamped = [self._stamp(f, analyzer) for f in produced]
        return _Outcome(stamped, _run_record(name, version, "ok", duration_ms, len(stamped), detail))

    # ------------------------------------------------------------------ correlation
    def _correlate(self, findings: list[Finding]) -> tuple[list[dict], list[Finding], dict[str, Any]]:
        version = getattr(correlation_engine, "VERSION", None)
        begin = time.monotonic()
        try:
            result = correlation_engine.correlate(tuple(findings))
            chains = [_chain_dict(c) for c in (getattr(result, "chains", None) or [])]
            derived = [
                f.with_defaults(analyzer=CORRELATION_STAGE_NAME, analyzer_version=version)
                for f in (getattr(result, "findings", None) or [])
                if isinstance(f, Finding)
            ]
        except Exception as exc:
            error_type = type(exc).__name__
            log.error("analyzer_error", analyzer=CORRELATION_STAGE_NAME, error_type=error_type)
            finding = _analyzer_error(CORRELATION_STAGE_NAME, "error", error_type).with_defaults(
                analyzer=CORRELATION_STAGE_NAME, analyzer_version=version)
            elapsed = int((time.monotonic() - begin) * 1000)
            return [], [finding], _run_record(CORRELATION_STAGE_NAME, version, "error", elapsed, 1, error_type)
        elapsed = int((time.monotonic() - begin) * 1000)
        return chains, derived, _run_record(CORRELATION_STAGE_NAME, version, "ok", elapsed, len(derived))

    # ------------------------------------------------------------------ entry point
    def analyze(
        self,
        ecosystem: str,
        name: str,
        version: str | None,
        options: ScanOptions | None = None,
    ) -> AnalysisResult:
        options = options if options is not None else ScanOptions()
        analyzers = self._selected_analyzers()
        key = _cache_key(ecosystem, name, version, options, analyzers)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        start = time.monotonic()
        deadline = start + max(0.001, float(settings.SCAN_TIMEOUT_SECONDS))
        ctx = _call_build_context(self._fetcher, name, version, options)
        if getattr(ctx, "options", None) is not options:
            try:
                ctx.options = options
            except AttributeError:
                pass

        findings: list[Signal] = []
        for signal in getattr(ctx, "context_signals", None) or []:
            if isinstance(signal, Mapping):
                signal = Finding.from_dict(dict(signal))
            if isinstance(signal, Finding):
                findings.append(signal.with_defaults(analyzer=FETCH_STAGE_NAME,
                                                     analyzer_version=settings.ANALYZER_VERSION))

        runs: list[dict[str, Any]] = []
        for outcome in self._run_analyzers(analyzers, ctx, options, deadline):
            findings.extend(outcome.findings)
            runs.append(outcome.run)
        if not analyzers and self._analyzers is None:
            # A configuration that selects no analyzer at all (e.g. only misspelt names in
            # ENABLED_ANALYZERS) must never yield a "clean" verdict: fail closed.
            log.error("no_analyzers_selected")
            findings.append(_no_analyzers_selected())
            runs.append(_run_record(REGISTRY_STAGE_NAME, settings.ANALYZER_VERSION, "error", 0, 1,
                                    "no analyzers selected by configuration"))
        if self._analyzers is None:
            # Only a settings-driven selection can have "disabled by configuration" analyzers;
            # an explicitly injected analyzer list says nothing about the registry.
            known = {analyzer_registry.normalize_analyzer_name(a.name) for a in analyzers}
            for analyzer in analyzer_registry.all_analyzers():
                if analyzer_registry.normalize_analyzer_name(analyzer.name) not in known:
                    runs.append(_run_record(str(analyzer.name), getattr(analyzer, "version", None), "skipped", 0,
                                            0, "disabled by configuration"))

        findings = _dedupe(findings)
        chains, derived, correlation_run = self._correlate(findings)
        findings = _dedupe([*findings, *derived])
        runs.append(correlation_run)

        for record in runs:
            metrics.observe_analyzer(record["name"], record["status"], record["duration_ms"] / 1000.0)

        vulnerabilities = risk_engine.extract_vulnerabilities(findings)
        intel_status = risk_engine.derive_intel_status(findings, runs, intel_requested=bool(options.intel))
        breakdown = risk_engine.assess(
            findings, ctx, vulnerabilities=vulnerabilities, intel_status=intel_status,
            analyzer_runs=runs, project_context=options.project_context,
        )
        capabilities = sorted({f.capability for f in findings if f.capability})
        duration_ms = int((time.monotonic() - start) * 1000)

        out = AnalysisResult(
            ecosystem=ecosystem,
            name=name,
            version=ctx.version,
            rule_score=breakdown.rule_score,
            ml_score=breakdown.ml_score,
            risk_score=breakdown.final_score,
            severity=breakdown.severity,
            features=breakdown.features,
            signals=[f.to_dict() for f in findings],
            analyzer_version=settings.ANALYZER_VERSION,
            duration_ms=duration_ms,
            ml_available=breakdown.ml_available,
            capabilities=capabilities,
            risk=breakdown.to_dict(),
            attack_chains=chains,
            analyzer_runs=runs,
            package_intel=package_intel_summary(ctx),
            provenance=provenance_summary(findings, ctx),
            vulnerabilities=vulnerabilities,
            intel_status=intel_status,
            model_version=_model_version() if breakdown.ml_available else None,
            explanation=_explanation(findings, breakdown),
            scan_options=_options_dict(options),
            file_inventory=file_inventory(ctx),
        )

        incomplete = any(f.code in _NON_CACHEABLE_CODES for f in findings)
        if incomplete or intel_status.get("status") in _NON_CACHEABLE_INTEL:
            log.info("verdict_not_cached", package=name, incomplete=incomplete,
                     intel_status=intel_status.get("status"))
        else:
            self._cache_set(key, out)
        log.info(
            "scan_complete", package=name, version=ctx.version,
            risk=out.risk_score, severity=out.severity, duration_ms=duration_ms,
        )
        return out
