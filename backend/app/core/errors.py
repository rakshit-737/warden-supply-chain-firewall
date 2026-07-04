"""Central error types and handlers.

Errors returned to clients are sanitised (no stack traces, no internals) and carry the
request id so a user can quote it in a support/audit request. Unexpected exceptions are
logged in full server-side but surface only as a generic 500.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_ctx

log = get_logger("warden.errors")


class WardenError(Exception):
    """Base class for expected, client-facing application errors."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class NotFoundError(WardenError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class AuthError(WardenError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(WardenError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class ConflictError(WardenError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class RateLimitedError(WardenError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60):
        super().__init__(message)
        self.retry_after = retry_after


class AnalysisError(WardenError):
    status_code = status.HTTP_502_BAD_GATEWAY
    code = "analysis_failed"


def _payload(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message, "request_id": request_id_ctx.get()}}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(WardenError)
    async def _warden_error(_: Request, exc: WardenError):
        headers = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(exc.code, exc.message),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        # Compact, non-leaky validation summary.
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_payload("validation_error", details or "Invalid request"),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload("http_error", str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        # Full detail server-side, generic message client-side.
        log.error("unhandled_exception", error=str(exc), error_type=type(exc).__name__)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_payload("internal_error", "An internal error occurred."),
        )
