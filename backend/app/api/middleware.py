"""Cross-cutting middleware: request-id, access logging, security headers, rate limiting."""

from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.cache import cache
from app.core.config import settings
from app.core.logging import get_logger, request_id_ctx

log = get_logger("warden.http")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id, bind it for logging, time the request, log the outcome."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_ctx.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        duration_ms = int((time.perf_counter() - start) * 1000)
        response.headers["X-Request-ID"] = rid
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            client=request.client.host if request.client else None,
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if settings.ENV == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiting per client IP, with a stricter limit on auth routes."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or request.url.path.startswith(
            (f"{settings.API_V1_PREFIX}/health", "/docs", "/openapi", "/redoc")
        ):
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        is_auth = request.url.path.startswith(f"{settings.API_V1_PREFIX}/auth")
        limit = settings.AUTH_RATE_LIMIT_PER_MINUTE if is_auth else settings.RATE_LIMIT_PER_MINUTE
        bucket = "auth" if is_auth else "api"
        key = f"ratelimit:{bucket}:{client}"

        try:
            hits = cache.rate_limit_hits(key, window_seconds=60)
        except Exception:  # never let the limiter take down the API
            hits = 0

        if hits > limit:
            return JSONResponse(
                status_code=429,
                content={"error": {"code": "rate_limited",
                                   "message": "Too many requests",
                                   "request_id": request_id_ctx.get()}},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)
