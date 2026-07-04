"""FastAPI application factory and composition root."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.deps import require_admin
from app.api.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.routers import audit, auth, health, policies, scans
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.db.base import Base
from app.db.seed import seed
from app.db.session import SessionLocal, engine

log = get_logger("warden")


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging(settings.DEBUG)
    # On SQLite (dev/test) we create tables directly; production uses Alembic migrations.
    if settings.is_sqlite:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        try:
            seed(db)
        except Exception as exc:  # pragma: no cover - startup robustness
            log.error("seed_failed", error=str(exc))
    log.info("startup_complete", version=__version__, env=settings.ENV)
    yield
    log.info("shutdown")


def create_app() -> FastAPI:
    configure_logging(settings.DEBUG)
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=__version__,
        description="A behavioural software supply-chain firewall for open-source dependencies.",
        docs_url="/docs" if settings.ENV != "production" else None,
        redoc_url="/redoc" if settings.ENV != "production" else None,
        openapi_url="/openapi.json" if settings.ENV != "production" else None,
        lifespan=lifespan,
    )

    # Middleware (executed bottom-up on the request path).
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    register_exception_handlers(app)

    p = settings.API_V1_PREFIX
    app.include_router(health.router, prefix=p)
    app.include_router(auth.router, prefix=p)
    app.include_router(scans.router, prefix=p)
    app.include_router(policies.router, prefix=p)
    app.include_router(audit.router, prefix=p)

    @app.get("/", tags=["meta"])
    def root() -> dict:
        return {"name": settings.PROJECT_NAME, "version": __version__, "docs": "/docs"}

    @app.get(f"{p}/whoami", tags=["meta"], dependencies=[Depends(require_admin)])
    def whoami() -> dict:
        # Trivial admin-guarded endpoint useful for verifying RBAC wiring in demos.
        return {"ok": True}

    return app


app = create_app()
