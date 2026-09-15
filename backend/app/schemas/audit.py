"""Audit event schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    seq: int | None = None
    prev_hash: str | None = None
    event_hash: str | None = None

    @field_validator("metadata_", mode="before")
    @classmethod
    def _none_to_dict(cls, v: object) -> object:
        return {} if v is None else v


class AuditVerifyOut(BaseModel):
    ok: bool
    checked: int
    first_broken_seq: int | None = None
    reason: str | None = None
    head_seq: int | None = Field(default=None, description="Last verified event; anchor externally")
    head_hash: str | None = None
    verified_at: datetime
