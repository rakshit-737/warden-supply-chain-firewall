"""User schemas (profile output and administrative updates)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, computed_field, model_validator

from app.core.permissions import Role, permissions_for


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    role: Role
    is_active: bool
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def permissions(self) -> list[str]:
        """Effective permissions of the role (informational; the server enforces them)."""
        return sorted(p.value for p in permissions_for(self.role))


class UserUpdate(BaseModel):
    """``PATCH /users/{id}``. Unknown fields are rejected (no mass assignment)."""

    model_config = ConfigDict(extra="forbid")

    role: Role | None = None  # legacy names (analyst, viewer) accepted
    is_active: bool | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> UserUpdate:
        if self.role is None and self.is_active is None:
            raise ValueError("provide at least one of: role, is_active")
        return self
