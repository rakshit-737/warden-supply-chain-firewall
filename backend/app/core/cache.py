"""Redis-backed cache, rate limiter, streams and locks, with an in-process fallback.

Redis is the production backend (shared across replicas). For local development, or when
``REDIS_OPTIONAL`` is set and Redis is unreachable at startup, an in-process implementation
keeps the app functional (single-process semantics only). The fallback is logged loudly so it
is never mistaken for production behaviour.

Reliability rationale — the cache is an optimisation, never a single point of failure:

* Read/write helpers degrade instead of raising when Redis errors at runtime: ``get_json``
  reports a miss, ``set_json``/``delete`` become no-ops, ``incr``/``xlen`` return ``None``,
  ``xadd`` returns ``False``. Backend errors are logged (type + redacted message, throttled).
* Rate limiting falls back to in-process counters when Redis errors, so limits keep applying
  per replica instead of silently disappearing or taking the API down. A limiter error also
  opens a short circuit breaker (``RATE_LIMIT_BREAKER_SECONDS``): during an outage requests use
  the fallback immediately instead of each paying Redis socket timeouts.
* In the in-process fallback, rate-limit window counters are kept apart from cached values and
  are evicted last and least-recently-used first, so a flood of cache writes cannot reset an
  active client's budget. Past the key cap a batch of entries is evicted at once, so eviction
  cost is amortised instead of a full sweep on every write.
* ``lock`` fails *closed* on backend errors (reports "not acquired"), so a Redis outage can
  cause a periodic job to be skipped but never to run concurrently on every replica.
* The in-process fallback is bounded (expired entries are swept, oldest entries evicted past a
  key cap) and thread-safe, so a flood of distinct client keys cannot exhaust memory.

Cache hits/misses are exported as ``cache_requests_total{cache,result}``; the ``cache`` label is
the key's namespace prefix when it is a known namespace (``verdict:…``), otherwise ``other`` —
keys are never used as labels.
"""

from __future__ import annotations

import heapq
import itertools
import json
import math
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Optional

from app.core import metrics
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.cache")

try:  # redis is optional at runtime
    import redis as _redis_lib
except Exception:  # pragma: no cover
    _redis_lib = None

KNOWN_CACHE_NAMES = frozenset({
    "verdict", "intel", "osv", "kev", "epss", "nvd", "pypi", "provenance", "depconf", "sbom", "graph", "ml",
    "monitor", "diff", "report", "container", "project",
})
LOCK_PREFIX = "warden:lock:"
_RELEASE_LOCK_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
_ERROR_LOG_INTERVAL_SECONDS = 30.0
_COUNTER_RETENTION_SECONDS = 3600.0
RATE_LIMIT_BREAKER_SECONDS = 5.0
# Fraction of the key cap evicted in one go once the cap is exceeded (amortises sweeps).
_EVICTION_BATCH_FRACTION = 10


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: float  # sliding-window estimate, this request included
    limit: int
    retry_after: int  # seconds until the estimate is back within the limit (0 when allowed)


def retry_after_seconds(previous: int, current: int, limit: int, elapsed: float, window: int) -> int:
    """Seconds until a sliding-window-counter estimate falls to ``limit`` if the client stops.

    The estimate at a moment ``f`` (fraction) into the current window is
    ``previous * (1 - f) + current``. After the window rolls over, ``current`` becomes the
    decaying previous window.
    """
    remaining = max(0.0, window - elapsed)
    if limit <= 0:
        return max(1, math.ceil(remaining + window))
    if current <= limit and previous > 0:
        needed_fraction = 1.0 - (limit - current) / previous
        wait = needed_fraction * window - elapsed
        return max(1, math.ceil(min(wait, remaining)))
    if current <= limit:
        return max(1, math.ceil(remaining))
    offset = (1.0 - limit / current) * window
    return max(1, math.ceil(remaining + offset))


class _InProcessBackend:
    """Bounded, thread-safe single-process stand-in for Redis (dev/test, or degraded mode)."""

    def __init__(self, *, clock: Callable[[], float] = time.time, max_keys: int = 50_000) -> None:
        self._kv: dict[str, tuple[str, float | None]] = {}
        self._counters: dict[str, list[float]] = {}
        # Rate-limit window counters: key -> (count, expires). Dict order is least-recently-used first.
        self._windows: dict[str, tuple[int, float]] = {}
        self._locks: dict[str, tuple[str, float]] = {}
        self._mutex = threading.Lock()
        self._clock = clock
        self._max_keys = max_keys
        self._writes = 0
        self.sweeps = 0  # full sweeps performed (observability / tests)

    # -- helpers (call with the mutex held)
    def _live(self, key: str, now: float) -> tuple[str, float | None] | None:
        item = self._kv.get(key)
        if item is None:
            return None
        if item[1] is not None and item[1] <= now:
            self._kv.pop(key, None)
            return None
        return item

    def _size(self) -> int:
        return len(self._kv) + len(self._counters) + len(self._windows)

    def _maybe_sweep(self, now: float) -> None:
        self._writes += 1
        if self._writes % 1024 and self._size() <= self._max_keys:
            return
        self.sweeps += 1
        for key in [k for k, (_, exp) in self._kv.items() if exp is not None and exp <= now]:
            del self._kv[key]
        stale_before = now - _COUNTER_RETENTION_SECONDS
        for key in [k for k, hits in self._counters.items() if not hits or hits[-1] <= stale_before]:
            del self._counters[key]
        for key in [k for k, (_, exp) in self._windows.items() if exp <= now]:
            del self._windows[key]
        for key in [k for k, (_, exp) in self._locks.items() if exp <= now]:
            del self._locks[key]
        overflow = self._size() - self._max_keys
        if overflow <= 0:
            return
        # Evict a batch, not just the overflow, so the following writes do not sweep again. Cached
        # values go first (soonest-expiring), then legacy hit lists, and only then the least recently
        # used rate-limit counters: churn in the cache must never reset a live client's budget.
        remaining = overflow + max(1, self._max_keys // _EVICTION_BATCH_FRACTION)
        if self._kv:
            victims = heapq.nsmallest(min(remaining, len(self._kv)), self._kv.items(),
                                      key=lambda item: item[1][1] if item[1][1] is not None else math.inf)
            for key, _ in victims:
                del self._kv[key]
            remaining -= len(victims)
        for store in (self._counters, self._windows):
            if remaining <= 0:
                break
            doomed = list(itertools.islice(store, remaining))
            for key in doomed:
                del store[key]
            remaining -= len(doomed)

    # -- key/value
    def get(self, key: str) -> Optional[str]:
        with self._mutex:
            item = self._live(key, self._clock())
            return item[0] if item else None

    def get_int(self, key: str) -> int:
        raw = self.get(key)
        try:
            return int(raw) if raw is not None else 0
        except ValueError:
            return 0

    def setex(self, key: str, ttl: int, value: str) -> None:
        with self._mutex:
            now = self._clock()
            self._kv[key] = (value, now + ttl)
            self._maybe_sweep(now)

    def delete(self, key: str) -> bool:
        with self._mutex:
            return self._kv.pop(key, None) is not None

    def incr(self, key: str, ttl: int, amount: int = 1) -> int:
        with self._mutex:
            now = self._clock()
            item = self._live(key, now)
            try:
                value, expires = (int(item[0]), item[1]) if item else (0, now + ttl)
            except ValueError:
                value, expires = 0, now + ttl
            value += amount
            self._kv[key] = (str(value), expires)
            self._maybe_sweep(now)
            return value

    def window_incr(self, key: str, ttl: int) -> int:
        """Increment a rate-limit window counter (created with ``ttl``); marks it most recently used."""
        with self._mutex:
            now = self._clock()
            item = self._windows.pop(key, None)
            count, expires = item if item is not None and item[1] > now else (0, now + ttl)
            self._windows[key] = (count + 1, expires)
            self._maybe_sweep(now)
            return count + 1

    def window_get(self, key: str) -> int:
        """Current value of a rate-limit window counter (0 when absent or expired); marks it used."""
        with self._mutex:
            item = self._windows.pop(key, None)
            if item is None or item[1] <= self._clock():
                return 0
            self._windows[key] = item
            return item[0]

    def sliding_window_hits(self, key: str, window_seconds: int) -> int:
        with self._mutex:
            now = self._clock()
            bucket = [t for t in self._counters.get(key, []) if t > now - window_seconds]
            bucket.append(now)
            self._counters[key] = bucket
            self._maybe_sweep(now)
            return len(bucket)

    # -- locks
    def acquire_lock(self, key: str, token: str, ttl_seconds: float) -> bool:
        with self._mutex:
            now = self._clock()
            held = self._locks.get(key)
            if held is not None and held[1] > now:
                return False
            self._locks[key] = (token, now + ttl_seconds)
            return True

    def release_lock(self, key: str, token: str) -> bool:
        with self._mutex:
            held = self._locks.get(key)
            if held is not None and held[0] == token:
                del self._locks[key]
                return True
            return False

    def ping(self) -> bool:
        return True


def _cache_metric_name(key: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    prefix = key.split(":", 1)[0].lower() if ":" in key else ""
    return prefix if prefix in KNOWN_CACHE_NAMES else "other"


class CacheClient:
    def __init__(
        self,
        *,
        redis_client: Any | None = None,
        connect: bool = True,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._redis = redis_client
        self._clock = clock
        self._monotonic = monotonic
        self._fallback = _InProcessBackend(clock=clock)
        self._error_logged_at: dict[str, float] = {}
        self._limiter_suspended_until = 0.0
        if redis_client is None and connect:
            self._connect()

    def _connect(self) -> None:
        if _redis_lib is None:
            log.warning("redis_library_missing", using="in_process_fallback")
            return
        try:
            client = _redis_lib.from_url(
                settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2, decode_responses=True
            )
            client.ping()
            self._redis = client
            log.info("redis_connected")
        except Exception as exc:  # pragma: no cover - depends on environment
            if settings.REDIS_OPTIONAL:
                log.warning("redis_unavailable_fallback", error_type=type(exc).__name__,
                            error=sanitize_text(str(exc), max_len=200))
            else:
                raise

    def _backend_error(self, op: str, exc: BaseException) -> None:
        now = time.monotonic()
        last = self._error_logged_at.get(op)
        if last is None or now - last >= _ERROR_LOG_INTERVAL_SECONDS:
            self._error_logged_at[op] = now
            log.warning("cache_backend_error", op=op, error_type=type(exc).__name__,
                        error=sanitize_text(str(exc), max_len=200))

    @property
    def backend(self) -> str:
        """``redis`` or ``in_process`` (the single-process fallback)."""
        return "redis" if self._redis is not None else "in_process"

    @property
    def healthy(self) -> bool:
        if self._redis is None:
            return settings.REDIS_OPTIONAL
        try:
            return bool(self._redis.ping())
        except Exception:
            return False

    # --- JSON cache ---------------------------------------------------------
    def get_json(self, key: str, *, cache_name: str | None = None) -> Optional[Any]:
        """Decoded JSON value for ``key``; ``None`` on a miss, a backend error or corrupt data."""
        name = _cache_metric_name(key, cache_name)
        try:
            raw = self._redis.get(key) if self._redis is not None else self._fallback.get(key)
        except Exception as exc:
            self._backend_error("get", exc)
            metrics.inc_cache(name, "error")
            return None
        if not raw:
            metrics.inc_cache(name, "miss")
            return None
        try:
            value = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
            metrics.inc_cache(name, "error")
            return None
        metrics.inc_cache(name, "hit")
        return value

    def set_json(self, key: str, value: Any, ttl: int) -> None:
        raw = json.dumps(value, default=str)
        ttl = max(1, int(ttl))
        try:
            if self._redis is not None:
                self._redis.setex(key, ttl, raw)
            else:
                self._fallback.setex(key, ttl, raw)
        except Exception as exc:
            self._backend_error("set", exc)

    def delete(self, key: str) -> bool:
        """Delete ``key``; True when something was deleted (False on a backend error)."""
        try:
            if self._redis is not None:
                return bool(self._redis.delete(key))
            return self._fallback.delete(key)
        except Exception as exc:
            self._backend_error("delete", exc)
            return False

    def incr(self, key: str, ttl: int, amount: int = 1) -> int | None:
        """Atomically add ``amount`` to an integer counter, creating it with a ``ttl`` (seconds).

        The TTL is set only when the counter is created, so it expires ``ttl`` seconds after its
        first increment. Returns the new value, or ``None`` when the Redis backend errored.
        """
        ttl = max(1, int(ttl))
        if self._redis is None:
            return self._fallback.incr(key, ttl, amount)
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.set(key, 0, ex=ttl, nx=True)  # create with TTL only if missing (works on any Redis >= 2.6.12)
            pipe.incrby(key, amount)
            _, value = pipe.execute()
            return int(value)
        except Exception as exc:
            self._backend_error("incr", exc)
            return None

    # --- Rate limiting --------------------------------------------------------
    def rate_limit_hits(self, key: str, window_seconds: int = 60) -> int:
        """Return the number of hits in the trailing window (this call inclusive).

        Kept for compatibility; new code should use :meth:`rate_limit`, whose memory use is
        constant per key.
        """
        if self._redis is not None:
            try:
                now = self._clock()
                member = f"{now}:{uuid.uuid4().hex}"
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(key, 0, now - window_seconds)
                pipe.zadd(key, {member: now})
                pipe.zcard(key)
                pipe.expire(key, window_seconds + 1)
                _, _, count, _ = pipe.execute()
                return int(count)
            except Exception as exc:
                self._backend_error("rate_limit_hits", exc)
        return self._fallback.sliding_window_hits(key, window_seconds)

    def rate_limit(self, key: str, limit: int, window_seconds: int = 60) -> RateLimitResult:
        """Sliding-window-counter rate limit: two fixed windows, weighted by overlap.

        Constant memory per key (two integers), atomic increments in Redis, and no burst at window
        boundaries. Rejected requests are counted too, so a client that keeps hammering stays
        limited. Falls back to in-process counters if Redis errors, and then skips Redis for
        ``RATE_LIMIT_BREAKER_SECONDS`` so an outage costs no per-request socket timeouts.
        """
        window = max(1, int(window_seconds))
        now = self._clock()
        index = int(now // window)
        elapsed = now - index * window
        cur_key, prev_key = f"{key}:{index}", f"{key}:{index - 1}"
        counts: tuple[int, int] | None = None
        if self._redis is not None and self._monotonic() >= self._limiter_suspended_until:
            try:
                pipe = self._redis.pipeline(transaction=True)
                pipe.set(cur_key, 0, ex=window * 2, nx=True)
                pipe.incr(cur_key)
                pipe.get(prev_key)
                _, current_raw, previous_raw = pipe.execute()
                counts = (int(current_raw), int(previous_raw or 0))
            except Exception as exc:
                self._backend_error("rate_limit", exc)
                self._limiter_suspended_until = self._monotonic() + RATE_LIMIT_BREAKER_SECONDS
        if counts is None:
            counts = (self._fallback.window_incr(cur_key, window * 2), self._fallback.window_get(prev_key))
        current, previous = counts
        estimate = previous * max(0.0, 1.0 - elapsed / window) + current
        allowed = estimate <= limit
        retry = 0 if allowed else retry_after_seconds(previous, current, limit, elapsed, window)
        return RateLimitResult(allowed=allowed, count=round(estimate, 3), limit=limit, retry_after=retry)

    # --- Streams ----------------------------------------------------------------
    def xadd(self, stream: str, fields: Mapping[str, str], maxlen: int | None = None) -> bool:
        """Append an entry to a Redis stream (trimmed to ~``maxlen``). False without Redis; never raises."""
        if self._redis is None or not fields:
            return False
        try:
            payload = {str(k): str(v) for k, v in fields.items()}
            limit = max(1, int(maxlen if maxlen is not None else settings.EVENT_STREAM_MAXLEN))
            self._redis.xadd(stream, payload, maxlen=limit, approximate=True)
            return True
        except Exception as exc:
            self._backend_error("xadd", exc)
            return False

    def xlen(self, stream: str) -> int | None:
        """Length of a Redis stream; ``None`` without Redis or on a backend error."""
        if self._redis is None:
            return None
        try:
            return int(self._redis.xlen(stream))
        except Exception as exc:
            self._backend_error("xlen", exc)
            return None

    # --- Locks --------------------------------------------------------------------
    @contextmanager
    def lock(self, name: str, ttl: float = 30.0) -> Iterator[bool]:
        """Non-blocking mutual-exclusion lock; yields whether it was acquired.

        Redis: ``SET key token NX PX ttl`` with a compare-and-delete release, so a holder whose
        lock already expired cannot release someone else's. Without Redis: an in-process lock
        (single-process exclusion only). The TTL bounds how long a crashed holder blocks others.
        """
        key = LOCK_PREFIX + name
        token = uuid.uuid4().hex
        ttl_ms = max(1, int(float(ttl) * 1000))
        if self._redis is not None:
            try:
                acquired = bool(self._redis.set(key, token, nx=True, px=ttl_ms))
            except Exception as exc:
                self._backend_error("lock", exc)
                acquired = False
        else:
            acquired = self._fallback.acquire_lock(key, token, ttl_ms / 1000.0)
        try:
            yield acquired
        finally:
            if acquired:
                self._release_lock(key, token)

    def _release_lock(self, key: str, token: str) -> None:
        if self._redis is None:
            self._fallback.release_lock(key, token)
            return
        try:
            self._redis.eval(_RELEASE_LOCK_LUA, 1, key, token)
        except Exception as exc:  # the TTL still releases it
            self._backend_error("unlock", exc)


cache = CacheClient()
