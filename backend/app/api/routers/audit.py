"""Audit-log browsing (admin-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.models import AuditEvent, User
from app.db.session import get_db
from app.schemas.audit import AuditEventOut
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
def list_audit(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=80),
) -> Page[AuditEventOut]:
    stmt = select(AuditEvent)
    count_stmt = select(func.count(AuditEvent.id))
    if action:
        stmt = stmt.where(AuditEvent.action == action)
        count_stmt = count_stmt.where(AuditEvent.action == action)
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )
