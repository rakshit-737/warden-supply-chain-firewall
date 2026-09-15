"""Auth request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.permissions import Role
from app.schemas.user import UserOut

__all__ = ["LoginRequest", "RegisterRequest", "TokenResponse", "UserOut"]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=12, max_length=256, description="Minimum 12 characters")
    # Legacy v1 names are accepted: "analyst" -> security_analyst, "viewer" -> read_only.
    role: Role = Role.read_only


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
