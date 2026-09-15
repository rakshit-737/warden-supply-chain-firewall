"""Policy schemas.

Policies are scoped to an environment (development | staging | production); exactly one
policy may be active per environment. ``document`` (policy-as-code) and ``version`` are
read-only here: they are exposed on output but not accepted on create/update until the
policy-document validator is wired into this API.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.models import DEFAULT_ENVIRONMENT
from app.schemas.scan import validate_environment

_MAX_LIST_ITEMS = 1000


class PolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    warn_threshold: int = Field(default=40, ge=0, le=100)
    block_threshold: int = Field(default=70, ge=0, le=100)
    min_package_age_days: int = Field(default=0, ge=0, le=3650)
    blocked_capabilities: list[str] = Field(default_factory=list, max_length=_MAX_LIST_ITEMS)
    allowlist: list[str] = Field(default_factory=list, max_length=_MAX_LIST_ITEMS)
    denylist: list[str] = Field(default_factory=list, max_length=_MAX_LIST_ITEMS)

    @model_validator(mode="after")
    def _thresholds(self) -> "PolicyBase":
        if self.warn_threshold > self.block_threshold:
            raise ValueError("warn_threshold must be <= block_threshold")
        return self


class PolicyCreate(PolicyBase):
    environment: str = Field(default=DEFAULT_ENVIRONMENT, description="development|staging|production")

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str) -> str:
        return validate_environment(v) or DEFAULT_ENVIRONMENT


class PolicyUpdate(PolicyBase):
    # Omitted = keep the policy's current environment (a PUT must not silently move it).
    environment: str | None = Field(default=None, description="development|staging|production")

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None) -> str | None:
        return validate_environment(v)


class PolicyOut(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime | None = None
    environment: str = DEFAULT_ENVIRONMENT
    document: dict | None = None
    version: int = 1

    @field_validator("blocked_capabilities", "allowlist", "denylist", mode="before")
    @classmethod
    def _none_to_list(cls, v: object) -> object:
        return [] if v is None else v
