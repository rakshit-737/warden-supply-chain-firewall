"""Redis-backed cache, rate limiter, and verdict cache with an in-process fallback.

Redis is the production backend (shared across replicas). For local development or when
``REDIS_OPTIONAL`` is set and Redis is unreachable, an in-process implementation keeps the
app fully functional (single-process only). The fallback is logged loudly so it is never
mistaken for production behaviour.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("warden.cache")

try:  # redis is optional at runtime
    import redis as _redis_lib
except Exception:  # pragma: no cover
    _redis_lib = None


class _InProcessBackend:
    """Minimal single-process stand-in for Redis (dev/test only)."""

    def __init__(self) -> None:
        self._kv: dict[str, tuple[str, float | None]] = {}
        self._counters: dict[str, list[float]] = {}

    def get(self, key: str) -> Optional[str]:
        item = self._kv.get(key)
        if not item:
            return None
        value, exp = item
        if exp is not None and exp < time.time():
            self._kv.pop(key, None)
            return None
        return value

    def setex(self, key: str, ttl: int, value: str) -> None:
        self._kv[key] = (value, time.time() + ttl)

    def sliding_window_hits(self, key: str, window_seconds: int) -> int:
        now = time.time()
        bucket = [t for t in self._counters.get(key, []) if t > now - window_seconds]
        bucket.append(now)
        self._counters[key] = bucket
        return len(bucket)

    def ping(self) -> bool:
        return True


class CacheClient:
    def __init__(self) -> None:
        self._redis = None
        self._fallback = _InProcessBackend()
        self._connect()

    def _connect(self) -> None:
        if _redis_lib is None:
            log.warning("redis_library_missing", using="in_process_fallback")
            return
        try:
            client = _redis_lib.from_url(
                settings.REDIS_URL, socket_connect_timeout=2, decode_responses=True
            )
            client.ping()
            self._redis = client
            log.info("redis_connected")
        except Exception as exc:  # pragma: no cover - depends on environment
            if settings.REDIS_OPTIONAL:
                log.warning("redis_unavailable_fallback", error=str(exc))
            else:
                raise

    @property
    def healthy(self) -> bool:
        if self._redis is None:
            return settings.REDIS_OPTIONAL
        try:
            return bool(self._redis.ping())
        except Exception:  # pragma: no cover
            return False

    # --- Verdict cache ----------------------------------------------------
    def get_json(self, key: str) -> Optional[dict]:
        raw = self._redis.get(key) if self._redis else self._fallback.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key: str, value: dict, ttl: int) -> None:
        raw = json.dumps(value, default=str)
        if self._redis:
            self._redis.setex(key, ttl, raw)
        else:
            self._fallback.setex(key, ttl, raw)

    # --- Rate limiting (sliding window) -----------------------------------
    def rate_limit_hits(self, key: str, window_seconds: int = 60) -> int:
        """Return the number of hits in the trailing window (this call inclusive)."""
        if self._redis:
            now = time.time()
            member = f"{now}:{id(object())}"
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            pipe.zadd(key, {member: now})
            pipe.zcard(key)
            pipe.expire(key, window_seconds + 1)
            _, _, count, _ = pipe.execute()
            return int(count)
        return self._fallback.sliding_window_hits(key, window_seconds)


cache = CacheClient()
