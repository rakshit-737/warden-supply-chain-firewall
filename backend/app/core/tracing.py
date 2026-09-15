"""Optional OpenTelemetry tracing — off by default, import-guarded, never a hard dependency.

``span(name, **attrs)`` is a context manager that does nothing unless **both**
``settings.OTEL_ENABLED`` is true **and** the ``opentelemetry`` API package is importable.
OpenTelemetry is deliberately not a Warden dependency: operators who want traces install
``opentelemetry-api`` / ``-sdk`` and configure an exporter themselves; everyone else pays only
a settings lookup per span.

Privacy / security rationale
----------------------------
Spans leave the process (to a collector, often a third-party SaaS), so attributes are
sanitised before they are handed to OpenTelemetry:

* keys must be short dotted identifiers; keys that name secrets (``password``, ``token``,
  ``authorization`` ...) or package *contents* (``content``, ``source_code``, ``body``,
  ``payload``, ``snippet``, ``evidence`` ...) are dropped;
* only scalar values (and short homogeneous lists of scalars) are recorded; ``bytes``,
  mappings and arbitrary objects are dropped, so file contents cannot be attached by accident;
* strings are control-character-escaped, secret-redacted and bounded
  (:func:`app.core.redaction.sanitize_text`);
* exceptions mark the span as errored with the exception *type* only — the message and
  stack trace (which may quote package data) are not recorded.

This is designed to keep package contents and secrets out of traces; it does not make it
safe to deliberately put sensitive data into span names.
"""

from __future__ import annotations

import importlib
import math
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from functools import lru_cache
from types import ModuleType
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.tracing")

TRACER_NAME = "warden"
MAX_ATTRIBUTES = 32
MAX_STRING_LENGTH = 256
MAX_SEQUENCE_ITEMS = 16

_KEY_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
_SPAN_NAME_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_.:/ \-]")
_SECRET_KEY_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie", "credential",
    "private_key", "session",
)
_CONTENT_KEY_TOKENS = frozenset({
    "content", "contents", "body", "payload", "snippet", "evidence", "blob", "bytes", "text", "source_code",
    "file_data", "raw",
})
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1


@lru_cache(maxsize=1)
def _load_trace_api() -> ModuleType | None:
    """Import ``opentelemetry.trace`` once; ``None`` when the package is not installed."""
    try:
        return importlib.import_module("opentelemetry.trace")
    except Exception as exc:  # ImportError, or a broken installation
        log.info("otel_unavailable", error_type=type(exc).__name__)
        return None


def is_enabled() -> bool:
    """True when tracing is switched on *and* the OpenTelemetry API can be imported."""
    return bool(settings.OTEL_ENABLED) and _load_trace_api() is not None


def _key_allowed(key: str) -> bool:
    if not _KEY_RE.match(key):
        return False
    if any(part in key for part in _SECRET_KEY_PARTS):
        return False
    tokens = set(re.split(r"[._]", key))
    joined = {"_".join(pair) for pair in zip(key.split("_"), key.split("_")[1:])}
    return not (tokens | joined) & _CONTENT_KEY_TOKENS


def _scalar(value: Any) -> bool | int | float | str | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if _INT64_MIN <= value <= _INT64_MAX else None
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return sanitize_text(value, max_len=MAX_STRING_LENGTH)
    return None


def sanitize_attributes(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """Filter and bound span attributes (see module docstring for the rules)."""
    out: dict[str, Any] = {}
    for raw_key, value in attrs.items():
        if len(out) >= MAX_ATTRIBUTES:
            break
        if not isinstance(raw_key, str) or not _key_allowed(raw_key):
            continue
        if isinstance(value, (list, tuple)):
            items = [_scalar(v) for v in value[:MAX_SEQUENCE_ITEMS]]
            if items and all(v is not None for v in items) and len({type(v) for v in items}) == 1:
                out[raw_key] = items
            continue
        scalar = _scalar(value)
        if scalar is not None:
            out[raw_key] = scalar
    return out


def safe_span_name(name: object) -> str:
    cleaned = _SPAN_NAME_UNSAFE_RE.sub("_", sanitize_text(name, max_len=96))
    return cleaned or "span"


class SpanHandle:
    """What ``span()`` yields: a sanitising wrapper around a live span, or a no-op."""

    __slots__ = ("_span",)

    def __init__(self, otel_span: Any | None = None) -> None:
        self._span = otel_span

    @property
    def recording(self) -> bool:
        return self._span is not None

    def set_attribute(self, key: str, value: Any) -> None:
        if isinstance(key, str):
            self.set_attributes(**{key: value})

    def set_attributes(self, **attrs: Any) -> None:
        if self._span is None:
            return
        for key, value in sanitize_attributes(attrs).items():
            try:
                self._span.set_attribute(key, value)
            except Exception:  # nosec B110 - tracing must never break the traced code
                pass


_NOOP = SpanHandle()


def _mark_error(trace_api: ModuleType, otel_span: Any, exc: BaseException) -> None:
    try:
        otel_span.set_attribute("error.type", type(exc).__name__)
        otel_span.set_status(trace_api.Status(trace_api.StatusCode.ERROR, type(exc).__name__))
    except Exception:  # nosec B110 - best effort
        pass


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[SpanHandle]:
    """Trace a block. A no-op (yielding an inert handle) unless tracing is enabled and available.

    Exceptions from the block always propagate unchanged; failures inside OpenTelemetry itself
    are swallowed so tracing can never break the traced operation.
    """
    trace_api = _load_trace_api() if settings.OTEL_ENABLED else None
    manager = otel_span = None
    if trace_api is not None:
        try:
            tracer = trace_api.get_tracer(TRACER_NAME)
            manager = tracer.start_as_current_span(
                safe_span_name(name),
                attributes=sanitize_attributes(attrs),
                record_exception=False,  # messages/tracebacks may quote package data
                set_status_on_exception=False,
            )
            otel_span = manager.__enter__()
        except Exception as exc:
            log.debug("otel_span_start_failed", error_type=type(exc).__name__)
            manager = None
    if manager is None:
        yield _NOOP
        return
    try:
        yield SpanHandle(otel_span)
    except Exception as exc:
        _mark_error(trace_api, otel_span, exc)
        raise
    finally:
        try:
            manager.__exit__(None, None, None)
        except Exception:  # nosec B110 - ending a span must not mask the real outcome
            pass


__all__ = ["SpanHandle", "is_enabled", "safe_span_name", "sanitize_attributes", "span"]
