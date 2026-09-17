"""Release diff request / response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.scan import _PYPI_NAME_RE, _VERSION_RE


class DiffRequest(BaseModel):
    ecosystem: str = Field(default="pypi")
    name: str = Field(min_length=1, max_length=214)
    from_version: str = Field(min_length=1, max_length=64)
    to_version: str = Field(min_length=1, max_length=64)

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

    @field_validator("from_version", "to_version")
    @classmethod
    def _version(cls, v: str) -> str:
        v = v.strip()
        if not _VERSION_RE.match(v):
            raise ValueError("Invalid version string")
        return v

    @model_validator(mode="after")
    def _distinct(self) -> DiffRequest:
        if self.from_version == self.to_version:
            raise ValueError("from_version and to_version must differ")
        return self


class DiffSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ecosystem: str
    package: str
    old_version: str
    new_version: str
    analyzer_version: str
    drift_detected: bool
    drift_score: int
    created_at: datetime


class DiffOut(DiffSummary):
    summary: dict | None = None
    findings: list | None = None
