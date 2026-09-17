"""Monitoring schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.scan import _PYPI_NAME_RE, _VERSION_RE

MIN_POLL_SECONDS = 300
MAX_POLL_SECONDS = 7 * 24 * 3600


def _check_version(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not _VERSION_RE.match(v):
        raise ValueError("Invalid version string")
    return v


class MonitoredPackageCreate(BaseModel):
    ecosystem: str = Field(default="pypi")
    name: str = Field(min_length=1, max_length=214)
    approved_version: str | None = Field(default=None, max_length=64)
    poll_interval_seconds: int = Field(default=3600, ge=MIN_POLL_SECONDS, le=MAX_POLL_SECONDS)
    project_id: uuid.UUID | None = None

    @field_validator("ecosystem")
    @classmethod
    def _eco(cls, v: str) -> str:
        v = v.lower().strip()
        if v != "pypi":
            raise ValueError("Only the 'pypi' ecosystem is supported in this version")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not _PYPI_NAME_RE.match(v):
            raise ValueError("Invalid PyPI package name")
        return v

    @field_validator("approved_version")
    @classmethod
    def _version(cls, v: str | None) -> str | None:
        return _check_version(v)


class MonitoredPackageUpdate(BaseModel):
    enabled: bool | None = None
    approved_version: str | None = Field(default=None, max_length=64)
    poll_interval_seconds: int | None = Field(default=None, ge=MIN_POLL_SECONDS, le=MAX_POLL_SECONDS)

    @field_validator("approved_version")
    @classmethod
    def _version(cls, v: str | None) -> str | None:
        return _check_version(v)


class MonitoredPackageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ecosystem: str
    name: str
    approved_version: str | None = None
    latest_seen_version: str | None = None
    enabled: bool
    poll_interval_seconds: int
    last_checked_at: datetime | None = None
    next_check_at: datetime | None = None
    last_risk_score: int | None = None
    snapshot: dict | None = None
    project_id: uuid.UUID | None = None
    consecutive_failures: int
    created_at: datetime


class CheckResultOut(BaseModel):
    package: str
    status: str
    version: str | None = None
    diff_id: uuid.UUID | None = None
    detail: str | None = None
