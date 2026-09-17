"""FastAPI application factory and composition root.

Wires, in one reviewed place: middleware (order matters — see ``create_app``), exception
handlers, routers, the Prometheus ``/metrics`` endpoint, and — outside production only — the
API documentation pages with a hash-based Content-Security-Policy.

Hardening done here rather than in individual modules:

* ``/metrics`` can require ``Authorization: Bearer <METRICS_TOKEN>`` (constant-time compare).
* Wildcard CORS origins never allow credentials (a credentialed ``*`` would let any site read
  authenticated responses).
* Records from stdlib loggers that bypass structlog (uvicorn's error/access logs, httpx) pass
  through the same secret redaction as Warden's own structured logs.
* Insecure-but-valid production settings (unauthenticated metrics, in-process rate limiting,
  wildcard CORS) are logged loudly at startup.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Mapping
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html
from fastapi.responses import HTMLResponse, Response

from app import __version__
from app.api.deps import require_admin
from app.api.middleware import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    docs_csp,
)
from app.api.routers import (
    audit,
    auth,
    containers,
    diffs,
    events,
    health,
    ml,
    monitoring,
    packages,
    policies,
    projects,
    scans,
    system,
    users,
    vulnerabilities,
)
from app.core import metrics
from app.core.cache import cache
from app.core.config import settings
from app.core.errors import error_response, register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.redaction import redact_text
from app.db.base import Base
from app.db.seed import seed
from app.db.session import SessionLocal, engine

log = get_logger("warden")

OAUTH2_REDIRECT_PATH = "/docs/oauth2-redirect"
_REDACTED_STDLIB_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore")


# --------------------------------------------------------------------------- logging
class RedactingLogFilter(logging.Filter):
    """Redact secret patterns from stdlib log records (message, string args, traceback text).

    Argument tuples keep their shape because some formatters (uvicorn's access log) unpack them.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            if isinstance(record.args, tuple):
                record.args = tuple(redact_text(a) if isinstance(a, str) else a for a in record.args)
            elif isinstance(record.args, Mapping):
                record.args = {k: redact_text(v) if isinstance(v, str) else v for k, v in record.args.items()}
            if record.exc_info and not record.exc_text:
                record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
        except Exception:  # nosec B110 - a logging filter must never drop or break a record
            pass
        return True


def install_stdlib_log_redaction() -> None:
    """Attach :class:`RedactingLogFilter` to known stdlib loggers and the root handlers (idempotent)."""
    targets: list[logging.Filterer] = [logging.getLogger(name) for name in _REDACTED_STDLIB_LOGGERS]
    targets.extend(logging.getLogger().handlers)
    for name in _REDACTED_STDLIB_LOGGERS:
        targets.extend(logging.getLogger(name).handlers)
    for target in targets:
        if not any(isinstance(f, RedactingLogFilter) for f in target.filters):
            target.addFilter(RedactingLogFilter())


def _warn_on_insecure_posture() -> None:
    if settings.ENV != "production":
        return
    if settings.METRICS_ENABLED and not settings.METRICS_TOKEN:
        log.warning("metrics_endpoint_unauthenticated",
                    hint="set METRICS_TOKEN or restrict /metrics at the network layer")
    if cache.backend != "redis":
        log.warning("cache_in_process_fallback", hint="rate limits and caches are per-process; configure Redis")
    if "*" in settings.CORS_ORIGINS:
        log.warning("cors_wildcard_origin", hint="credentials are disabled for wildcard CORS origins")


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging(settings.DEBUG)
    install_stdlib_log_redaction()
    _preinitialize_metrics()
    # On SQLite (dev/test) we create tables directly; production uses Alembic migrations.
    if settings.is_sqlite:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        try:
            seed(db)
        except Exception as exc:  # pragma: no cover - startup robustness
            log.error("seed_failed", error_type=type(exc).__name__)
    _warn_on_insecure_posture()
    log.info("startup_complete", version=__version__, env=settings.ENV)
    yield
    log.info("shutdown")


# --------------------------------------------------------------------------- docs & metrics
def _with_docs_csp(response: HTMLResponse) -> HTMLResponse:
    response.headers["Content-Security-Policy"] = docs_csp(bytes(response.body).decode("utf-8"))
    return response


def _install_docs(app: FastAPI) -> None:
    """Swagger UI / ReDoc, each served with a CSP computed from its own HTML (non-production only)."""
    openapi_url = app.openapi_url or "/openapi.json"

    @app.get("/docs", include_in_schema=False)
    async def swagger_ui(request: Request) -> HTMLResponse:
        root = request.scope.get("root_path", "").rstrip("/")
        return _with_docs_csp(get_swagger_ui_html(
            openapi_url=root + openapi_url,
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=root + OAUTH2_REDIRECT_PATH,
        ))

    @app.get(OAUTH2_REDIRECT_PATH, include_in_schema=False)
    async def swagger_ui_redirect() -> HTMLResponse:
        return _with_docs_csp(get_swagger_ui_oauth2_redirect_html())

    @app.get("/redoc", include_in_schema=False)
    async def redoc(request: Request) -> HTMLResponse:
        root = request.scope.get("root_path", "").rstrip("/")
        return _with_docs_csp(get_redoc_html(openapi_url=root + openapi_url, title=f"{app.title} - ReDoc"))


def metrics_token_valid(authorization: str | None, expected: str) -> bool:
    """Constant-time check of ``Authorization: Bearer <expected>``."""
    if not authorization or not expected:
        return False
    scheme, _, credentials = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(credentials.strip().encode("utf-8"), expected.encode("utf-8"))


def _install_metrics_endpoint(app: FastAPI) -> None:
    @app.get("/metrics", include_in_schema=False)
    def prometheus_metrics(request: Request) -> Response:
        expected = settings.METRICS_TOKEN
        if expected and not metrics_token_valid(request.headers.get("authorization"), expected):
            return error_response(401, "unauthorized", "A valid metrics bearer token is required",
                                  headers={"WWW-Authenticate": 'Bearer realm="metrics"'})
        _refresh_scrape_time_gauges()
        body, content_type = metrics.render_latest()
        return Response(content=body, media_type=content_type)


def _refresh_scrape_time_gauges() -> None:
    """Gauges whose source of truth is the database are computed when Prometheus scrapes.

    The monitoring worker runs in its own process (and registry), so the API reports the number of
    watched packages itself. A database problem leaves the previous value in place; it never fails
    the scrape.
    """
    try:
        from sqlalchemy import func, select

        from app.db.models import MonitoredPackage

        with SessionLocal() as db:
            enabled = db.scalar(select(func.count(MonitoredPackage.id)).where(MonitoredPackage.enabled.is_(True)))
        metrics.set_monitored_packages(enabled or 0)
    except Exception as exc:  # observability must never break the endpoint
        log.warning("metrics_gauge_refresh_failed", error_type=type(exc).__name__)


# --------------------------------------------------------------------------- factory
def _preinitialize_metrics() -> None:
    from app.analysis import analyzers as analyzer_registry
    from app.analysis.orchestrator import CORRELATION_STAGE_NAME
    from app.events.types import EventType

    names = [str(a.name) for a in analyzer_registry.all_analyzers()] + [CORRELATION_STAGE_NAME]
    metrics.preinitialize(analyzers=names, event_types=[e.value for e in EventType])


def create_app() -> FastAPI:
    configure_logging(settings.DEBUG)
    install_stdlib_log_redaction()
    docs_enabled = settings.ENV != "production"
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=__version__,
        description="A behavioural software supply-chain firewall for open-source dependencies.",
        docs_url=None,  # served by _install_docs with a strict, hash-based CSP
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    # Middleware: add_middleware() wraps the stack, so the LAST one added is the OUTERMOST.
    # Request path: RequestContext -> SecurityHeaders -> CORS -> RateLimit -> BodySizeLimit -> routes.
    # (Rate limiting runs before any body is read; CORS wraps 429s so browsers can read them.)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)
    wildcard_origin = "*" in settings.CORS_ORIGINS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=not wildcard_origin,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)

    p = settings.API_V1_PREFIX
    for module in (
        health, auth, users, scans, packages, diffs, projects, vulnerabilities,
        policies, events, audit, monitoring, containers, system, ml,
    ):
        app.include_router(module.router, prefix=p)

    if docs_enabled:
        _install_docs(app)
    if settings.METRICS_ENABLED:
        _install_metrics_endpoint(app)

    @app.get("/", tags=["meta"])
    def root() -> dict:
        return {"name": settings.PROJECT_NAME, "version": __version__, "docs": "/docs" if docs_enabled else None}

    @app.get(f"{p}/whoami", tags=["meta"], dependencies=[Depends(require_admin)])
    def whoami() -> dict:
        # Trivial admin-guarded endpoint useful for verifying RBAC wiring in demos.
        return {"ok": True}

    return app


app = create_app()
