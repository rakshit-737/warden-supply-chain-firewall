"""Liveness and readiness probes.

``/health/live`` answers whether the process is serving requests at all. ``/health/ready``
checks what a replica needs to serve traffic — the database and the cache — and returns
**503** when either is unavailable, so load balancers and orchestrators stop routing to it.
The ML model is reported but optional: without it the pipeline degrades to rules-only.

Probe responses contain only booleans, never exception text or connection details. Only
``/health/live`` is exempt from rate limiting (see ``app.api.middleware``). ``/health/ready`` is
public and does real backend work, so it is rate limited like any other request and its result
is computed at most once per ``READINESS_CACHE_SECONDS`` (concurrent probes wait for that one
check), which bounds database and cache load under a flood from many addresses.
"""

from __future__ import annotations

import threading
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.analysis.model_store import get_model_store
from app.core.cache import cache
from app.db.session import SessionLocal

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict:
    return {"status": "ok"}


def _database_ok() -> bool:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception:  # nosec B110 - readiness probe reports False rather than raising
        return False


def _cache_ok() -> bool:
    try:
        return bool(cache.healthy)
    except Exception:
        return False


def _model_ok() -> bool:
    try:
        return bool(get_model_store().available)
    except Exception:
        return False


READINESS_CACHE_SECONDS = 2.0
_readiness_lock = threading.Lock()
_readiness: tuple[float, dict[str, bool]] | None = None


def _checks() -> dict[str, bool]:
    global _readiness
    with _readiness_lock:
        now = time.monotonic()
        if _readiness is not None and now - _readiness[0] < READINESS_CACHE_SECONDS:
            return dict(_readiness[1])
        checks = {"database": _database_ok(), "cache": _cache_ok(), "model": _model_ok()}
        _readiness = (time.monotonic(), checks)
        return dict(checks)


def reset_readiness_cache() -> None:
    global _readiness
    with _readiness_lock:
        _readiness = None


@router.get("/ready", response_model=None)
def ready() -> JSONResponse:
    checks = _checks()
    ready_ok = checks["database"] and checks["cache"]
    return JSONResponse(
        status_code=200 if ready_ok else 503,
        content={"status": "ok" if ready_ok else "degraded", "checks": checks},
    )
