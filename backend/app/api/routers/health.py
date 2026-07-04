"""Liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.analysis.model_store import get_model_store
from app.core.cache import cache
from app.db.session import SessionLocal

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/ready")
def ready() -> dict:
    checks = {"database": False, "cache": False, "model": False}
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:  # nosec B110 - readiness probe reports False rather than raising
        pass
    checks["cache"] = cache.healthy
    checks["model"] = get_model_store().available
    # Model is optional (graceful degradation) — readiness needs DB + cache.
    ready_ok = checks["database"] and checks["cache"]
    return {"status": "ok" if ready_ok else "degraded", "checks": checks}
