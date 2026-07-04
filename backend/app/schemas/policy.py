"""Policy schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    warn_threshold: int = Field(default=40, ge=0, le=100)
    block_threshold: int = Field(default=70, ge=0, le=100)
    min_package_age_days: int = Field(default=0, ge=0, le=3650)
    blocked_capabilities: list[str] = Field(default_factory=list)
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _thresholds(self) -> "PolicyBase":
        if self.warn_threshold > self.block_threshold:
            raise ValueError("warn_threshold must be <= block_threshold")
        return self


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(PolicyBase):
    pass


class PolicyOut(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime | None = None
