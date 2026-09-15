"""Central error types, the error envelope, and exception handlers.

Every error returned to a client uses one envelope::

    {"error": {"code": "<machine code>", "message": "<human text>", "request_id": "<id>"}}

Security rationale:

* **No internals.** Unhandled exceptions surface only as a generic 500. Server-side they are
  logged with the exception *type* and a redacted, length-bounded message — never a raw
  message that could carry a credential (e.g. a URL with an API key) into log storage.
* **No echo of request input.** Validation messages are rebuilt from the schema side of
  pydantic's error (field location + message template). Parser details that quote the
  rejected input are cut, custom validator messages have occurrences of the input value
  removed, and dict keys that do not look like field names are replaced with ``<key>``. A
  hostile value therefore cannot be reflected back (reflected-content / log-forging vectors)
  and a secret pasted into the wrong field is not repeated in the response.
* **Correlatable.** Every envelope carries the request id so a user can quote it in a
  support or audit request.
"""

from __future__ import annotations

import http
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status as _starlette_status
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_ctx
from app.core.redaction import sanitize_text

log = get_logger("warden.errors")


def _status_constant(current: str, legacy: str, value: int) -> int:
    """Resolve a status constant by its current name, falling back to the legacy name.

    Starlette 1.x renamed e.g. ``HTTP_422_UNPROCESSABLE_ENTITY`` → ``HTTP_422_UNPROCESSABLE_CONTENT``
    (RFC 9110) and warns on the old name; older Starlette only has the old name.
    """
    found = getattr(_starlette_status, current, None)
    if found is None:
        found = getattr(_starlette_status, legacy, value)
    return int(found)


HTTP_422_UNPROCESSABLE = _status_constant("HTTP_422_UNPROCESSABLE_CONTENT", "HTTP_422_UNPROCESSABLE_ENTITY", 422)
HTTP_413_CONTENT_TOO_LARGE = _status_constant("HTTP_413_CONTENT_TOO_LARGE", "HTTP_413_REQUEST_ENTITY_TOO_LARGE", 413)


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


class PayloadTooLargeError(WardenError):
    status_code = HTTP_413_CONTENT_TOO_LARGE
    code = "payload_too_large"


class RateLimitedError(WardenError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60):
        super().__init__(message)
        self.retry_after = retry_after


class AnalysisError(WardenError):
    status_code = status.HTTP_502_BAD_GATEWAY
    code = "analysis_failed"


class RequestBodyTooLarge(StarletteHTTPException):
    """Raised from the request-body stream by the body-size middleware.

    It subclasses Starlette's ``HTTPException`` on purpose: FastAPI re-raises that type from
    body parsing (any other exception is converted into a generic 400), so the registered
    handler below turns it into a proper 413 envelope.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(status_code=HTTP_413_CONTENT_TOO_LARGE, detail=f"Request body exceeds the {limit}-byte limit")
        self.limit = limit


_HTTP_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    503: "service_unavailable",
}


# --------------------------------------------------------------------------- envelope helpers
def current_request_id(request: Request | None = None) -> str | None:
    """The request id bound by the request-context middleware.

    Falls back to ``scope["state"]["request_id"]`` because handlers for unhandled exceptions run
    in Starlette's outermost middleware, after the context variable has been reset.
    """
    rid = request_id_ctx.get()
    if rid is None and request is not None:
        state = request.scope.get("state")
        if isinstance(state, Mapping):
            rid = state.get("request_id")
    return rid if isinstance(rid, str) else None


def error_payload(code: str, message: str, *, request_id: str | None = None) -> dict:
    return {"error": {"code": code, "message": message, "request_id": request_id or request_id_ctx.get()}}


def _payload(code: str, message: str) -> dict:  # backwards-compatible name
    return error_payload(code, message)


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: Mapping[str, str] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error_payload(code, message, request_id=request_id),
        headers=dict(headers) if headers else None,
    )


def internal_error_response(*, request_id: str | None = None) -> JSONResponse:
    return error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", "An internal error occurred.",
                          request_id=request_id)


def log_unhandled_exception(exc: BaseException, *, request_id: str | None = None) -> None:
    """Log an unexpected exception: type plus a redacted, bounded message — nothing else."""
    extra = {"request_id": request_id} if request_id else {}
    log.error("unhandled_exception", error_type=type(exc).__name__, error=sanitize_text(str(exc), max_len=300),
              **extra)


def _status_phrase(code: int) -> str:
    try:
        return http.HTTPStatus(code).phrase
    except ValueError:
        return "HTTP error"


# --------------------------------------------------------------------------- validation messages
MAX_VALIDATION_ERRORS = 10
_LOC_SOURCES = frozenset({"body", "query", "path", "header", "cookie"})
_LOC_PART_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")
# Error types whose pydantic message appends parser detail (after a comma) that can quote input,
# e.g. "Input should be a valid UUID, invalid character: expected ..., found `x` at 1".
_DETAIL_PREFIXES = ("url_", "uuid_", "datetime_", "date_", "time_", "timedelta_", "decimal_", "complex_")


def _loc_to_str(loc: Iterable[Any]) -> str:
    parts = list(loc)
    source = parts[0] if parts and parts[0] in _LOC_SOURCES else None
    if source is not None:
        parts = parts[1:]
    out: list[str] = []
    for part in parts[:8]:
        if isinstance(part, int) and not isinstance(part, bool):
            out.append(str(part))
        elif isinstance(part, str) and _LOC_PART_RE.match(part):
            out.append(part)
        else:
            out.append("<key>")
    if len(parts) > 8:
        out.append("…")
    # Dict keys in a location can come from the request; identifier-shaped ones are kept for
    # usefulness but still pass through secret redaction.
    return sanitize_text(".".join(out), max_len=160) if out else (source or "")


_MIN_SCRUB_LENGTH = 3
_MAX_SCRUB_VALUES = 64
_MAX_SCRUB_DEPTH = 4
_EMAIL_ERROR_PREFIX = "value is not a valid email address"


def _input_values(raw: Any, out: set[str], depth: int = 0) -> None:
    """Collect scalar values from the rejected input (bounded), including inside dicts/lists.

    Model-level validators receive the whole object as ``input``, so a custom message may quote
    any field of it — not just a top-level scalar.
    """
    if len(out) >= _MAX_SCRUB_VALUES or depth > _MAX_SCRUB_DEPTH or raw is None or isinstance(raw, bool):
        return
    if isinstance(raw, (str, int, float)):
        text = str(raw)
        # Also the escaped spellings a message may use: f"{v!r}" and JSON-encoded values.
        forms = (text, text.strip(), repr(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1])
        out.update(c for c in forms if len(c) >= _MIN_SCRUB_LENGTH)
    elif isinstance(raw, Mapping):
        for value in list(raw.values())[:_MAX_SCRUB_VALUES]:
            _input_values(value, out, depth + 1)
    elif isinstance(raw, (list, tuple, set, frozenset)):
        for value in list(raw)[:_MAX_SCRUB_VALUES]:
            _input_values(value, out, depth + 1)


def _scrub_input(message: str, raw_input: Any) -> str:
    values: set[str] = set()
    _input_values(raw_input, values)
    for candidate in sorted(values, key=len, reverse=True):  # longest first: no partial leftovers
        message = re.sub(re.escape(candidate), "<input>", message, flags=re.IGNORECASE)
    return message


def _safe_error_message(err: Mapping[str, Any]) -> str:
    etype = str(err.get("type") or "")
    msg = str(err.get("msg") or "Invalid value")
    if etype == "json_invalid":
        msg = "Invalid JSON"
    elif etype.endswith("_parsing") or etype.startswith(_DETAIL_PREFIXES):
        msg = msg.split(",", 1)[0]
    elif _EMAIL_ERROR_PREFIX in msg:
        # email-validator explanations can quote fragments of the address (invalid characters).
        msg = _EMAIL_ERROR_PREFIX
    msg = _scrub_input(msg, err.get("input"))
    return sanitize_text(msg, max_len=200)


def format_validation_errors(errors: Iterable[Mapping[str, Any]]) -> str:
    """Compact, bounded, non-echoing summary of pydantic / FastAPI validation errors."""
    items = list(errors)
    parts: list[str] = []
    for err in items[:MAX_VALIDATION_ERRORS]:
        loc = _loc_to_str(err.get("loc") or ())
        msg = _safe_error_message(err)
        parts.append(f"{loc}: {msg}" if loc else msg)
    if len(items) > MAX_VALIDATION_ERRORS:
        parts.append(f"and {len(items) - MAX_VALIDATION_ERRORS} more error(s)")
    return "; ".join(parts) or "Invalid request"


# --------------------------------------------------------------------------- handlers
def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(WardenError)
    async def _warden_error(request: Request, exc: WardenError):
        headers = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(max(1, int(exc.retry_after)))
        return error_response(
            exc.status_code,
            exc.code,
            sanitize_text(exc.message, max_len=500),
            headers=headers,
            request_id=current_request_id(request),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        return error_response(
            HTTP_422_UNPROCESSABLE,
            "validation_error",
            format_validation_errors(exc.errors()),
            request_id=current_request_id(request),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        message = sanitize_text(detail, max_len=300) if isinstance(detail, str) and detail else _status_phrase(
            exc.status_code
        )
        return error_response(
            exc.status_code,
            _HTTP_ERROR_CODES.get(exc.status_code, "http_error"),
            message,
            headers=getattr(exc, "headers", None),
            request_id=current_request_id(request),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        rid = current_request_id(request)
        log_unhandled_exception(exc, request_id=rid)
        return internal_error_response(request_id=rid)
