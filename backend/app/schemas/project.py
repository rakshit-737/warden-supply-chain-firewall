"""Project (manifest inventory, SBOM, dependency graph) schemas."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.scan import validate_environment

_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ \-]{0,119}$")

MAX_MANIFEST_FILES = 50
MAX_MANIFEST_BYTES = 1_000_000
MAX_TOTAL_MANIFEST_BYTES = 5_000_000


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not _PROJECT_NAME_RE.match(v):
            raise ValueError("Project names use letters, digits, spaces, '.', '_' and '-' (max 120)")
        return v


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class ProjectScanRequest(BaseModel):
    """Manifest files as ``{relative path: text}``; nothing is fetched or executed."""

    files: dict[str, str] = Field(min_length=1)
    environment: str | None = None

    @field_validator("files")
    @classmethod
    def _files(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > MAX_MANIFEST_FILES:
            raise ValueError(f"at most {MAX_MANIFEST_FILES} manifest files per scan")
        total = 0
        for path, content in v.items():
            if not path or len(path) > 300 or "\x00" in path:
                raise ValueError("invalid manifest path")
            size = len(content.encode("utf-8", "surrogatepass"))
            if size > MAX_MANIFEST_BYTES:
                raise ValueError(f"manifest larger than {MAX_MANIFEST_BYTES} bytes")
            total += size
        if total > MAX_TOTAL_MANIFEST_BYTES:
            raise ValueError(f"manifests larger than {MAX_TOTAL_MANIFEST_BYTES} bytes in total")
        return v

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None) -> str | None:
        return validate_environment(v)


class ProjectScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime
    component_count: int
    direct_count: int
    decision: str | None = None
    risk_score: int
    environment: str | None = None


class ProjectScanOut(ProjectScanSummary):
    manifests: list | None = None
    summary: dict | None = None
    policy_reasons: list | None = None


class ComponentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bom_ref: str
    name: str
    version: str | None = None
    purl: str | None = None
    direct: bool
    depth: int | None = None
    scope: str | None = None
    resolution: str | None = None
    declared_at: list | None = None
    introduced_by: list | None = None
    scan_id: uuid.UUID | None = None
    risk_score: int | None = None
    decision: str | None = None
    vulnerability_count: int
