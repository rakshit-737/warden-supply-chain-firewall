"""Append-only audit logging helper."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.core.logging import request_id_ctx
from app.db.models import AuditEvent


def record(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    event = AuditEvent(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata_=metadata or {},
        request_id=request_id_ctx.get(),
    )
    db.add(event)
    # Flushed/committed by the caller within the same transaction.
