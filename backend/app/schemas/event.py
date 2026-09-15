"""Security event schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    type: str
    severity: str
    title: str
    package: str | None = None
    version: str | None = None
    project_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    details: dict = {}
    created_at: datetime
    acknowledged: bool
    acknowledged_by: uuid.UUID | None = None
    acknowledged_at: datetime | None = None

    @field_validator("details", mode="before")
    @classmethod
    def _none_to_dict(cls, v: object) -> object:
        return {} if v is None else v
