"""Scan request/response schemas with strict input validation.

Package-name validation happens *here*, before the value ever reaches the fetcher, so a
malformed or injection-style name cannot influence a URL or a filesystem path downstream.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import Decision, Severity

# PEP 508 project-name grammar (normalised comparison happens in the fetcher).
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,212}[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$")


class ScanRequest(BaseModel):
    ecosystem: str = Field(default="pypi")
    name: str = Field(min_length=1, max_length=214)
    version: str | None = Field(default=None, description="Omit to analyse the latest release")

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

    @field_validator("version")
    @classmethod
    def _version(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not _VERSION_RE.match(v):
            raise ValueError("Invalid version string")
        return v


class SignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    severity: Severity
    weight: float
    message: str
    evidence: dict


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ecosystem: str
    package_name: str
    version: str
    rule_score: int
    ml_score: int
    risk_score: int
    severity: Severity
    decision: Decision
    matched_policy_rules: list[str]
    feature_vector: dict
    analyzer_version: str
    duration_ms: int
    created_at: datetime
    signals: list[SignalOut] = []


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ecosystem: str
    package_name: str
    version: str
    risk_score: int
    severity: Severity
    decision: Decision
    created_at: datetime


class ScanStats(BaseModel):
    total: int
    by_decision: dict[str, int]
    by_severity: dict[str, int]
    blocked_last_30d: int
    avg_risk_score: float
    top_signals: list[dict]
