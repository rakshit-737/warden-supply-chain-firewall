"""Security event routes: browse (``event:read``) and acknowledge (``event:ack``)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.errors import NotFoundError
from app.core.permissions import Permission
from app.db.base import as_utc, utcnow
from app.db.models import SecurityEvent, User
from app.db.session import get_db
from app.events.bus import normalize_package
from app.events.types import EventType
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.event import EventOut
from app.services import audit

router = APIRouter(prefix="/events", tags=["events"])

SeverityFilter = Literal["info", "low", "medium", "high", "critical"]


@router.get("", response_model=Page[EventOut])
def list_events(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.EVENT_READ)),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0, le=1_000_000),
    event_type: EventType | None = Query(None, alias="type"),
    severity: SeverityFilter | None = None,
    package: str | None = Query(None, max_length=214),
    project_id: uuid.UUID | None = None,
    since: datetime | None = None,
    acknowledged: bool | None = None,
) -> Page[EventOut]:
    filters = []
    if event_type is not None:
        filters.append(SecurityEvent.type == event_type.value)
    if severity is not None:
        filters.append(SecurityEvent.severity == severity)
    if package:
        filters.append(SecurityEvent.package == normalize_package(package))
    if project_id is not None:
        filters.append(SecurityEvent.project_id == project_id)
    if since is not None:
        filters.append(SecurityEvent.created_at >= as_utc(since))
    if acknowledged is not None:
        filters.append(SecurityEvent.acknowledged.is_(acknowledged))

    total = db.scalar(select(func.count(SecurityEvent.id)).where(*filters)) or 0
    rows = db.scalars(
        select(SecurityEvent).where(*filters)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id).limit(limit).offset(offset)
    ).all()
    return Page[EventOut](items=[EventOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("/{event_id}/ack", response_model=EventOut)
def acknowledge_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EVENT_ACK)),
) -> SecurityEvent:
    """Acknowledge an event. Idempotent: re-acknowledging keeps the original acknowledger."""
    row = db.get(SecurityEvent, event_id)
    if row is None:
        raise NotFoundError("Event not found")
    if not row.acknowledged:
        result = db.execute(
            update(SecurityEvent)
            .where(SecurityEvent.id == event_id, SecurityEvent.acknowledged.is_(False))
            .values(acknowledged=True, acknowledged_by=user.id, acknowledged_at=utcnow())
            .execution_options(synchronize_session=False)
        )
        if (result.rowcount or 0) == 1:
            audit.record(db, actor_id=user.id, action="event.ack", target_type="security_event",
                         target_id=str(event_id), metadata={"type": row.type, "severity": row.severity})
        db.commit()
        db.refresh(row)
    return row
