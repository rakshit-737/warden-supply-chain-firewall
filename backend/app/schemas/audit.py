"""Audit event schema."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditEventOut(BaseModel):
    # Read from the ORM attribute ``metadata_`` (the column is named "metadata" in the DB,
    # but we must NOT alias the *input* to "metadata" — that name collides with
    # SQLAlchemy's built-in ``Base.metadata``). We only rename it back to "metadata" on
    # serialization.
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_id: str | None
    metadata_: dict = Field(default_factory=dict, serialization_alias="metadata")
    request_id: str | None
    created_at: datetime
