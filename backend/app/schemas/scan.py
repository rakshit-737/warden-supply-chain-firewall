"""Scan request/response schemas with strict input validation.

Package-name validation happens *here*, before the value ever reaches the fetcher, so a
malformed or injection-style name cannot influence a URL or a filesystem path downstream.

Warden fields on ``ScanOut`` / ``SignalOut`` are optional so v1 clients keep working and
rows persisted before migration 0002 (where those columns are NULL) still serialise.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import ENVIRONMENTS, Decision, Severity

# PEP 508 project-name grammar (normalised comparison happens in the fetcher).
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,212}[A-Za-z0-9])?$")
_PYPI_NAME_RE = PYPI_NAME_RE  # backwards-compatible alias
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$")


def validate_environment(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of: {', '.join(ENVIRONMENTS)}")
    return v


class ScanRequest(BaseModel):
    ecosystem: str = Field(default="pypi")
    name: str = Field(min_length=1, max_length=214)
    version: str | None = Field(default=None, description="Omit to analyse the latest release")
    environment: str | None = Field(
        default=None, description="Policy environment (development|staging|production); default production"
    )

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

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None) -> str | None:
        return validate_environment(v)


def _empty_dict(v: object) -> object:
    return {} if v is None else v


def _empty_list(v: object) -> object:
    return [] if v is None else v


class SignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    severity: Severity
    weight: float
    message: str
    evidence: dict
    # --- Warden 2 (optional) ---
    finding_id: str | None = None
    confidence: float | None = None
    category: str | None = None
    title: str | None = None
    analyzer: str | None = None
    analyzer_version: str | None = None
    capability: str | None = None
    location: dict | None = None
    cwe: list[str] | None = None
    attack: list[str] | None = None
    remediation: str | None = None
    references: list[str] | None = None
    provenance: str | None = None
    related: list[str] | None = None

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_none(cls, v: object) -> object:
        return _empty_dict(v)


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
    # --- Warden 2 (optional) ---
    environment: str | None = None
    malicious_risk: int | None = None
    vulnerability_risk: int | None = None
    risk: dict | None = None
    attack_chains: list[dict] | None = None
    analyzer_runs: list[dict] | None = None
    package_intel: dict | None = None
    provenance: dict | None = None
    vulnerabilities: list[dict] | None = None
    intel_status: dict | None = None
    model_version: str | None = None
    policy_reasons: list[dict] | None = None
    explanation: dict | None = None
    scan_options: dict | None = None

    @field_validator("matched_policy_rules", mode="before")
    @classmethod
    def _rules_none(cls, v: object) -> object:
        return _empty_list(v)

    @field_validator("feature_vector", mode="before")
    @classmethod
    def _features_none(cls, v: object) -> object:
        return _empty_dict(v)


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
    environment: str | None = None


class ScanStats(BaseModel):
    total: int
    by_decision: dict[str, int]
    by_severity: dict[str, int]
    blocked_last_30d: int
    avg_risk_score: float
    top_signals: list[dict]
