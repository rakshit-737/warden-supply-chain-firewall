"""Security event bus: durable rows first, best-effort stream fan-out second.

``publish`` adds a :class:`~app.db.models.SecurityEvent` to the caller's session. The row is
the source of truth and is committed (or rolled back) atomically with the change that
produced it. Only **after the transaction commits** is a copy pushed to the Redis stream
``settings.EVENT_STREAM_KEY`` (``XADD … MAXLEN ~ settings.EVENT_STREAM_MAXLEN``) for live
consumers; a rolled-back event is never streamed.

Stream delivery is best effort by design: Redis may be absent (in-process fallback), the
cache client may not provide ``xadd``, or the call may fail. None of that may break the
request that produced the event, so every stream error is swallowed and logged (error type
only). Consumers that need completeness read ``GET /events``.

Event details are attacker-influenced (package metadata, finding evidence) and are passed
through :func:`app.core.redaction.sanitize_evidence`: secret-shaped values are redacted,
control/bidi characters escaped and sizes bounded before anything is stored or streamed.

Limitations: pending stream payloads are tracked per session and discarded on any rollback,
including a rollback to a SAVEPOINT (conservative: an event may go unstreamed, never
streamed without its row).
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session

from app.core import metrics
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_evidence, sanitize_text
from app.db.base import utcnow
from app.db.models import SecurityEvent
from app.events.types import EventType, coerce_severity
from app.sbom.models import normalize_name

log = get_logger("warden.events")

_PENDING_KEY = "warden.events.pending_stream"
_HOOKED_KEY = "warden.events.hooked"
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,212}[A-Za-z0-9])?$")


def normalize_package(package: str | None) -> str | None:
    """PEP 503-normalise a valid PyPI name; otherwise store a sanitised, bounded string."""
    if package is None:
        return None
    candidate = str(package).strip()
    if not candidate:
        return None
    if _PYPI_NAME_RE.match(candidate):
        return normalize_name(candidate)
    return sanitize_text(candidate, max_len=214)


def _as_uuid(value: uuid.UUID | str | None) -> uuid.UUID | None:
    if value is None or isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def _clean_details(details: Any) -> dict:
    cleaned = sanitize_evidence(details if details is not None else {})
    if not isinstance(cleaned, dict):
        cleaned = {"value": cleaned}
    # Round-trip so the stored/streamed value is exactly JSON (UUIDs, datetimes → strings).
    return json.loads(json.dumps(cleaned, default=str))


def publish(
    db: Session,
    type: EventType | str,  # noqa: A002 - public contract name (SPEC §7)
    severity: str,
    title: str,
    *,
    package: str | None = None,
    version: str | None = None,
    project_id: uuid.UUID | str | None = None,
    scan_id: uuid.UUID | str | None = None,
    details: dict | None = None,
) -> SecurityEvent:
    """Record a security event in ``db`` (the caller commits). Raises ``ValueError`` on an
    unknown event type or severity — a programming error, not a runtime condition."""
    event_type = EventType(type)
    row = SecurityEvent(
        id=uuid.uuid4(),
        type=event_type.value,
        severity=coerce_severity(severity),
        title=sanitize_text(title, max_len=200) or event_type.value,
        package=normalize_package(package),
        version=sanitize_text(version, max_len=64) if version else None,
        project_id=_as_uuid(project_id),
        scan_id=_as_uuid(scan_id),
        details=_clean_details(details),
        created_at=utcnow(),
        acknowledged=False,
    )
    db.add(row)
    _queue_for_stream(db, _stream_fields(row))
    return row


# --------------------------------------------------------------------------- stream fan-out
def _stream_fields(row: SecurityEvent) -> dict[str, str]:
    """Flat string mapping for XADD (Redis stream fields cannot be null or nested)."""
    return {
        "id": str(row.id),
        "type": row.type,
        "severity": row.severity,
        "title": row.title,
        "package": row.package or "",
        "version": row.version or "",
        "project_id": str(row.project_id) if row.project_id else "",
        "scan_id": str(row.scan_id) if row.scan_id else "",
        "created_at": row.created_at.isoformat(),
        "details": json.dumps(row.details or {}, separators=(",", ":"), sort_keys=True),
    }


def _queue_for_stream(db: Session, fields: dict[str, str]) -> None:
    db.info.setdefault(_PENDING_KEY, []).append(fields)
    if not db.info.get(_HOOKED_KEY):
        sa_event.listen(db, "after_commit", _after_commit)
        sa_event.listen(db, "after_soft_rollback", _discard_pending)
        sa_event.listen(db, "after_transaction_end", _after_transaction_end)
        db.info[_HOOKED_KEY] = True


def _discard_pending(session: Session, *_: Any) -> None:
    session.info.pop(_PENDING_KEY, None)


def _after_transaction_end(session: Session, transaction: Any) -> None:
    # Root transaction ended without an outer commit having drained the queue (rollback or
    # close): nothing may be streamed for it.
    if getattr(transaction, "parent", None) is None:
        session.info.pop(_PENDING_KEY, None)


def _after_commit(session: Session) -> None:
    if session.in_nested_transaction():  # a SAVEPOINT release is not durable yet
        return
    pending = session.info.pop(_PENDING_KEY, None)
    if pending:
        for fields in pending:  # count durable (committed) events only
            metrics.inc_event(fields.get("type", ""), fields.get("severity", ""))
        push_to_stream(pending)


def push_to_stream(pending: list[dict[str, str]]) -> int:
    """XADD each payload to the event stream; returns how many were delivered. Never raises.

    ``CacheClient.xadd`` returns ``False`` when no Redis backend is configured; such payloads
    are not counted as delivered.
    """
    from app.core import cache as cache_module  # resolved at call time (tests swap the client)

    xadd = getattr(cache_module.cache, "xadd", None)
    if not callable(xadd):
        return 0
    pushed = 0
    for fields in pending:
        try:
            if xadd(settings.EVENT_STREAM_KEY, fields, maxlen=settings.EVENT_STREAM_MAXLEN) is not False:
                pushed += 1
        except Exception as exc:  # stream is best effort; the row is already committed
            log.warning("event_stream_publish_failed", error_type=type(exc).__name__, event_id=fields.get("id"))
            break
    return pushed
