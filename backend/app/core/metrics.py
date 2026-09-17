"""Prometheus metrics for Warden X.

All metrics live in a dedicated :class:`~prometheus_client.CollectorRegistry` (``REGISTRY``)
rather than the process-global default registry, so exposition contains only Warden's own
series and tests can inspect values deterministically.

Security and reliability rationale
----------------------------------
* **Bounded label cardinality.** Label values are never taken verbatim from request data.
  HTTP routes are labelled with the *route template* (``/api/v1/scans/{scan_id}``), never the
  raw path, so package names, ids and attacker-chosen URLs cannot create series. Enumerated
  labels (decision, severity, environment, HTTP method, ...) are mapped onto a fixed
  allowlist with ``other`` as the catch-all. Free-form labels that come from code (analyzer,
  tool, queue, cache and intel-source names) must match a conservative identifier pattern
  and are capped at a fixed number of distinct values per label; anything beyond the cap is
  recorded as ``other``. A bug or a hostile input can therefore never grow the registry
  without bound (which would otherwise be a memory DoS on the API process and on Prometheus).
* **Never break the caller.** Every helper swallows its own failures: observability must not
  turn a successful scan into an error. Invalid values (negative/NaN durations) are dropped.
* **No sensitive data.** Metrics carry counts and timings only; no helper accepts package
  contents, finding evidence or user identifiers.
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from enum import Enum
from functools import wraps
from typing import Any, TypeVar

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from app.core.logging import get_logger

try:  # prometheus_client >= 0.18: drop the redundant *_created series (halves series count).
    from prometheus_client import disable_created_metrics

    disable_created_metrics()
except ImportError:  # pragma: no cover - older client
    pass

log = get_logger("warden.metrics")

OTHER = "other"
UNMATCHED_ROUTE = "__unmatched__"  # routed, but no route matched (404)
UNROUTED = "__unrouted__"  # answered by middleware before routing (e.g. 413/429)

REGISTRY = CollectorRegistry(auto_describe=True)

# --------------------------------------------------------------------------- label policy
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,47}$")
_ROUTE_RE = re.compile(r"^/[A-Za-z0-9_.:/{}\-]{0,199}$")

_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_DECISIONS = frozenset({"allow", "warn", "block", "error", "unknown"})
_ECOSYSTEMS = frozenset({"pypi", "npm", "maven", "go", "cargo", "rubygems", "nuget", "container", "project"})
_ENVIRONMENTS = frozenset({"development", "staging", "production", "test", "default"})
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_ANALYZER_STATUSES = frozenset({"ok", "error", "timeout", "skipped", "unavailable"})
_CACHE_RESULTS = frozenset({"hit", "miss", "error"})


def _coerce(value: Any) -> str:
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()[:256]


def _enum_label(value: Any, allowed: frozenset[str]) -> str:
    v = _coerce(value).lower()
    return v if v in allowed else OTHER


class BoundedLabel:
    """Maps free-form (code-supplied) label values onto a bounded set.

    Values must look like identifiers; at most ``max_values`` distinct values are admitted per
    label, after which new values collapse to ``other``.
    """

    def __init__(self, max_values: int, pattern: re.Pattern[str] = _IDENT_RE) -> None:
        self.max_values = max_values
        self._pattern = pattern
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def __call__(self, value: Any) -> str:
        v = _coerce(value)
        if v in (UNMATCHED_ROUTE, UNROUTED):
            return v
        if not self._pattern.match(v):
            return OTHER
        with self._lock:
            if v in self._seen:
                return v
            if len(self._seen) >= self.max_values:
                return OTHER
            self._seen.add(v)
            return v


_route_label = BoundedLabel(512, _ROUTE_RE)
_analyzer_label = BoundedLabel(64)
_tool_label = BoundedLabel(64)
_queue_label = BoundedLabel(32)
_cache_label = BoundedLabel(32)
_intel_source_label = BoundedLabel(32)
_intel_status_label = BoundedLabel(32)
_event_type_label = BoundedLabel(64)


def _method_label(method: Any) -> str:
    m = _coerce(method).upper()
    return m if m in _HTTP_METHODS else OTHER


def _status_label(status: Any) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return OTHER
    return str(code) if 100 <= code <= 599 else OTHER


def _duration(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and v >= 0 else None


# --------------------------------------------------------------------------- metrics
_HTTP_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
_SCAN_BUCKETS = (0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 180.0, 300.0, 600.0)
_ANALYZER_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0)
_ML_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

HTTP_REQUESTS = Counter(
    "http_requests_total", "HTTP requests by method, route template and status.",
    ("method", "route", "status"), registry=REGISTRY,
)
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds", "HTTP request latency by method and route template.",
    ("method", "route"), buckets=_HTTP_BUCKETS, registry=REGISTRY,
)
SCANS = Counter("scans_total", "Package scans by policy decision and ecosystem.", ("decision", "ecosystem"),
                registry=REGISTRY)
SCAN_DURATION = Histogram("scan_duration_seconds", "End-to-end package scan duration.", buckets=_SCAN_BUCKETS,
                          registry=REGISTRY)
ANALYZER_DURATION = Histogram("analyzer_duration_seconds", "Per-analyzer run duration.", ("analyzer",),
                              buckets=_ANALYZER_BUCKETS, registry=REGISTRY)
ANALYZER_RUNS = Counter("analyzer_runs_total", "Analyzer runs by outcome.", ("analyzer", "status"), registry=REGISTRY)
CACHE_REQUESTS = Counter("cache_requests_total", "Cache lookups by cache and result.", ("cache", "result"),
                         registry=REGISTRY)
INTEL_REQUESTS = Counter("intel_requests_total", "Vulnerability-intelligence requests by source and status.",
                         ("source", "status"), registry=REGISTRY)
POLICY_DECISIONS = Counter("policy_decisions_total", "Policy decisions by decision and environment.",
                           ("decision", "environment"), registry=REGISTRY)
SECURITY_EVENTS = Counter("security_events_total", "Security events published by type and severity.",
                          ("type", "severity"), registry=REGISTRY)
ML_INFERENCE = Histogram("ml_inference_seconds", "ML model inference latency.", buckets=_ML_BUCKETS,
                         registry=REGISTRY)
QUEUE_DEPTH = Gauge("queue_depth", "Pending items per work queue.", ("queue",), registry=REGISTRY)
MONITORED_PACKAGES = Gauge("monitored_packages", "Packages under continuous monitoring.", registry=REGISTRY)
TOOL_AVAILABLE = Gauge("tool_available", "1 when an optional external analysis tool is available, else 0.",
                       ("tool",), registry=REGISTRY)
BLOCKED_PACKAGES = Counter("blocked_packages_total", "Package scans that ended in a block decision.",
                           registry=REGISTRY)

# --------------------------------------------------------------------------- helpers
_F = TypeVar("_F", bound=Callable[..., Any])
_failure_logged: set[str] = set()


def _never_raise(func: _F) -> _F:
    """Observability must never break the caller: log the first failure per helper, then stay quiet."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            if func.__name__ not in _failure_logged:
                _failure_logged.add(func.__name__)
                log.warning("metrics_helper_failed", helper=func.__name__, error_type=type(exc).__name__)
            return None

    return wrapper  # type: ignore[return-value]


@_never_raise
def observe_http(method: str, route: str, status: int, duration_seconds: float) -> None:
    """Record one HTTP request. ``route`` must be a route template, never a raw path."""
    m, r = _method_label(method), _route_label(route)
    HTTP_REQUESTS.labels(m, r, _status_label(status)).inc()
    d = _duration(duration_seconds)
    if d is not None:
        HTTP_REQUEST_DURATION.labels(m, r).observe(d)


@_never_raise
def observe_scan(decision: str, ecosystem: str, duration_seconds: float | None = None) -> None:
    """Record a completed package scan (also counts ``blocked_packages_total`` for blocks)."""
    d_label = _enum_label(decision, _DECISIONS)
    SCANS.labels(d_label, _enum_label(ecosystem, _ECOSYSTEMS)).inc()
    if d_label == "block":
        BLOCKED_PACKAGES.inc()
    d = _duration(duration_seconds)
    if d is not None:
        SCAN_DURATION.observe(d)


@_never_raise
def observe_analyzer(analyzer: str, status: str, duration_seconds: float | None = None) -> None:
    """Record one analyzer run (status: ok|error|timeout|skipped|unavailable)."""
    a = _analyzer_label(analyzer)
    ANALYZER_RUNS.labels(a, _enum_label(status, _ANALYZER_STATUSES)).inc()
    d = _duration(duration_seconds)
    if d is not None:
        ANALYZER_DURATION.labels(a).observe(d)


@_never_raise
def inc_cache(cache: str, result: str) -> None:
    """Count a cache lookup (result: hit|miss|error)."""
    CACHE_REQUESTS.labels(_cache_label(cache), _enum_label(result, _CACHE_RESULTS)).inc()


@_never_raise
def inc_intel(source: str, status: str) -> None:
    """Count an intelligence request (e.g. source ``osv``, status ``ok``/``error``/``cached``)."""
    INTEL_REQUESTS.labels(_intel_source_label(source), _intel_status_label(status)).inc()


@_never_raise
def inc_policy(decision: str, environment: str | None) -> None:
    POLICY_DECISIONS.labels(_enum_label(decision, _DECISIONS),
                            _enum_label(environment or "default", _ENVIRONMENTS)).inc()


@_never_raise
def inc_event(event_type: str, severity: str) -> None:
    SECURITY_EVENTS.labels(_event_type_label(event_type), _enum_label(severity, _SEVERITIES)).inc()


@_never_raise
def set_queue_depth(queue: str, depth: int | float) -> None:
    d = _duration(depth)  # same validation: finite and non-negative
    if d is not None:
        QUEUE_DEPTH.labels(_queue_label(queue)).set(d)


@_never_raise
def set_monitored_packages(count: int) -> None:
    c = _duration(count)
    if c is not None:
        MONITORED_PACKAGES.set(c)


@_never_raise
def set_tool_available(tool: str, available: bool) -> None:
    TOOL_AVAILABLE.labels(_tool_label(tool)).set(1 if available else 0)


_SCAN_ECOSYSTEMS = ("pypi",)
_PRE_CACHES = ("verdict",)


@_never_raise
def preinitialize(analyzers: Iterable[str] = (), event_types: Iterable[str] = ()) -> None:
    """Create the known label combinations with value 0.

    Without this a counter series appears only after its first increment, so dashboards and alert
    expressions such as ``rate(scans_total{decision="block"}[5m])`` see "no data" instead of 0 on a
    fresh process. Only fixed, enumerated values are used, so cardinality stays bounded.
    """
    for decision in ("allow", "warn", "block"):
        for ecosystem in _SCAN_ECOSYSTEMS:
            SCANS.labels(decision, ecosystem)
        for environment in ("development", "staging", "production"):
            POLICY_DECISIONS.labels(decision, environment)
    for cache in _PRE_CACHES:
        for result in sorted(_CACHE_RESULTS):
            CACHE_REQUESTS.labels(_cache_label(cache), result)
    for analyzer in analyzers:
        label = _analyzer_label(analyzer)
        for status in sorted(_ANALYZER_STATUSES):
            ANALYZER_RUNS.labels(label, status)
    for event_type in event_types:
        label = _event_type_label(event_type)
        for severity in sorted(_SEVERITIES):
            SECURITY_EVENTS.labels(label, severity)


@contextmanager
def time_ml() -> Iterator[None]:
    """Time an ML inference block into ``ml_inference_seconds`` (recorded even if it raises)."""
    start = time.perf_counter()
    try:
        yield
    finally:
        _observe_ml(time.perf_counter() - start)


@_never_raise
def _observe_ml(seconds: float) -> None:
    d = _duration(seconds)
    if d is not None:
        ML_INFERENCE.observe(d)


def render_latest() -> tuple[bytes, str]:
    """Prometheus text exposition of ``REGISTRY`` and its content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def label_values(metric_name: str) -> Iterable[dict[str, str]]:
    """Label sets currently exported for ``metric_name`` (diagnostics and tests)."""
    for family in REGISTRY.collect():
        for sample in family.samples:
            if sample.name == metric_name:
                yield dict(sample.labels)


__all__ = [
    "OTHER", "REGISTRY", "UNMATCHED_ROUTE", "UNROUTED", "BoundedLabel", "inc_cache", "inc_event", "inc_intel",
    "inc_policy", "label_values", "observe_analyzer", "observe_http", "observe_scan", "render_latest",
    "set_monitored_packages", "set_queue_depth", "set_tool_available", "time_ml",
]
