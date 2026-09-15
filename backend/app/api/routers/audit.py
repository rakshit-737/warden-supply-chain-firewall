"""Audit-trail browsing and hash-chain verification (``audit:read``: admin, auditor)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.permissions import Permission
from app.db.base import utcnow
from app.db.models import AuditEvent, User
from app.db.session import get_db
from app.schemas.audit import AuditEventOut, AuditVerifyOut
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.services.audit import verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])

_audit_reader = require_permission(Permission.AUDIT_READ)


@router.get("", response_model=Page[AuditEventOut])
def list_audit(
    db: Session = Depends(get_db),
    _: User = Depends(_audit_reader),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=80),
    actor_id: uuid.UUID | None = None,
    target_type: str | None = Query(None, max_length=40),
) -> Page[AuditEventOut]:
    filters = []
    if action:
        filters.append(AuditEvent.action == action)
    if actor_id:
        filters.append(AuditEvent.actor_id == actor_id)
    if target_type:
        filters.append(AuditEvent.target_type == target_type)
    total = db.scalar(select(func.count(AuditEvent.id)).where(*filters)) or 0
    rows = db.scalars(
        select(AuditEvent).where(*filters).order_by(AuditEvent.seq.desc()).limit(limit).offset(offset)
    ).all()
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/verify", response_model=AuditVerifyOut)
def verify_audit_chain(
    db: Session = Depends(get_db),
    _: User = Depends(_audit_reader),
) -> AuditVerifyOut:
    """Recompute the whole hash chain. ``ok=false`` identifies the first broken event."""
    return AuditVerifyOut(**verify_chain(db), verified_at=utcnow())
