"""Shared plumbing for intelligence sources: hardened HTTP clients, errors and caching.

Every intelligence source (OSV, CISA KEV, FIRST EPSS, NVD) talks to exactly one host. Each
gets its *own* :class:`~app.core.http.SafeHttpClient` whose allowlist is only that host
(derived from the configured base URL, so the defaults are ``api.osv.dev``,
``www.cisa.gov``, ``api.first.org`` and ``services.nvd.nist.gov``). A redirect from one
service to another host — including a different intelligence host — is refused, and HTTPS
is mandatory.

Failures are translated into :class:`IntelSourceError`, whose message is log-safe (URLs
without query strings, never request headers such as NVD's ``apiKey``). Callers turn these
into ``partial``/``unavailable`` statuses; an error is never reported as "no
vulnerabilities".

Caching goes through ``app.core.cache.cache`` (Redis, or the in-process fallback). A cache
outage degrades to a cache miss rather than failing the lookup, and values read back from
the cache are re-validated by the source modules because a shared cache is another input.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.core.http import OutboundHTTPError, SafeHttpClient
from app.core.logging import get_logger

log = get_logger("warden.intel")

CACHE_PREFIX = "intel"


class IntelSourceError(Exception):
    """An intelligence source could not answer. ``str(exc)`` is safe to log and store."""

    def __init__(self, source: str, message: str, *, kind: str = "error") -> None:
        super().__init__(f"{source}: {message}")
        self.source = source
        self.kind = kind  # network | status | too_large | host_not_allowed | scheme | redirect | decode | invalid


class CacheBackend(Protocol):
    def get_json(self, key: str) -> dict | None: ...

    def set_json(self, key: str, value: dict, ttl: int) -> None: ...


class IntelCache:
    """Fault-tolerant wrapper over the shared JSON cache."""

    def __init__(self, backend: CacheBackend | None = None) -> None:
        self._backend = backend

    def _resolve(self) -> CacheBackend:
        if self._backend is None:
            from app.core.cache import cache  # imported lazily: connecting to Redis is a side effect

            self._backend = cache
        return self._backend

    def get(self, key: str) -> dict | None:
        try:
            value = self._resolve().get_json(key)
        except Exception as exc:  # cache outage or corrupt entry -> behave as a miss
            log.warning("intel_cache_get_failed", key=key.split(":", 3)[:3], error_type=type(exc).__name__)
            return None
        return value if isinstance(value, dict) else None

    def set(self, key: str, value: dict, ttl: int) -> None:
        if ttl <= 0:
            return
        try:
            self._resolve().set_json(key, value, ttl)
        except Exception as exc:
            log.warning("intel_cache_set_failed", key=key.split(":", 3)[:3], error_type=type(exc).__name__)


def cache_key(namespace: str, *parts: object) -> str:
    """Cache key whose variable parts (package names, versions, ids) are hashed.

    Hashing keeps attacker-influenced text out of Redis key names and bounds key length.
    """
    digest = hashlib.sha256(json.dumps([str(p) for p in parts], separators=(",", ":")).encode("utf-8"))
    return f"{CACHE_PREFIX}:{namespace}:{digest.hexdigest()[:40]}"


def host_of(url: str) -> str:
    """Lower-cased hostname of a configured service URL (raises ``ValueError`` if absent)."""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("service URL has no host")
    return host


def build_http_client(
    source: str,
    base_url: str,
    *,
    timeout: float,
    rate_limit_per_second: float | None,
    max_response_bytes: int,
    retries: int = 2,
    sleep: Callable[[float], None] | None = None,
    http_client: httpx.Client | None = None,
) -> SafeHttpClient:
    """A SafeHttpClient restricted to the single host of ``base_url``."""
    kwargs: dict[str, Any] = {}
    if sleep is not None:
        kwargs["sleep"] = sleep
    return SafeHttpClient(
        name=f"intel-{source}",
        allowed_hosts=[host_of(base_url)],
        max_response_bytes=max_response_bytes,
        timeout=timeout,
        retries=retries,
        rate_limit_per_second=rate_limit_per_second if rate_limit_per_second and rate_limit_per_second > 0 else None,
        client=http_client,
        **kwargs,
    )


def translate_http_errors(source: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call ``fn`` and convert transport failures into :class:`IntelSourceError`."""
    try:
        return fn(*args, **kwargs)
    except OutboundHTTPError as exc:
        # OutboundHTTPError messages are constructed log-safe (safe_url, no headers).
        raise IntelSourceError(source, str(exc), kind=exc.kind) from exc
    except (httpx.HTTPError, OSError) as exc:  # defensive: anything SafeHttpClient did not wrap
        raise IntelSourceError(source, f"transport error ({type(exc).__name__})", kind="network") from exc
