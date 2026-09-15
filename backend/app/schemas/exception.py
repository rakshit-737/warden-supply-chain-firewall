"""Policy exception schemas.

An exception is a *risk acceptance*: it lets specific findings for a package pass policy for
a bounded time. The request is validated strictly because an overly broad or immortal
exception is itself a supply-chain risk:

* the package name must be a valid PyPI name and is stored PEP 503-normalised;
* ``expires_at`` is mandatory, must lie in the future and at most
  :data:`MAX_EXCEPTION_DAYS` days ahead;
* a justification of meaningful length is mandatory;
* codes the policy engine treats as non-overridable (known-malware IOC matches, artifact hash
  mismatches) cannot be excepted at all;
* unknown request fields (``status``, ``approved_by`` …) are rejected, never mass-assigned.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.analysis.findings import Category
from app.analysis.signals import Code
from app.core.redaction import sanitize_text
from app.sbom.models import normalize_name
from app.schemas.scan import PYPI_NAME_RE, validate_environment

MAX_EXCEPTION_DAYS = 365
MIN_JUSTIFICATION_CHARS = 10
MAX_JUSTIFICATION_CHARS = 2000
# Never waivable (SPEC §11): an allowlisted name must not whitelist active malware or a
# tampered artifact. (Critical high-confidence ATTACK_CHAIN findings are also never removed
# by the engine, but lower-confidence chains may legitimately be excepted.)
NON_OVERRIDABLE_CODES = frozenset({Code.IOC_MATCH, Code.HASH_MISMATCH})

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_CATEGORY_VALUES = frozenset(c.value for c in Category)

ExceptionStatusOut = Literal["pending", "approved", "rejected", "revoked", "expired"]


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


class ExceptionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, max_length=214)
    version_spec: str | None = Field(default=None, max_length=100, description='PEP 440 specifier, e.g. "<2.0"')
    codes: list[str] = Field(default_factory=list, max_length=50)
    categories: list[str] = Field(default_factory=list, max_length=25)
    policy_id: uuid.UUID | None = Field(default=None, description="Omit for a global exception")
    environment: str | None = Field(default=None, description="Omit to apply in every environment")
    justification: str = Field(min_length=MIN_JUSTIFICATION_CHARS, max_length=MAX_JUSTIFICATION_CHARS)
    expires_at: datetime

    @field_validator("package")
    @classmethod
    def _package(cls, v: str) -> str:
        v = v.strip()
        if not PYPI_NAME_RE.match(v):
            raise ValueError("Invalid PyPI package name")
        return normalize_name(v)

    @field_validator("version_spec")
    @classmethod
    def _version_spec(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        try:
            spec = SpecifierSet(v.strip())
        except InvalidSpecifier as exc:
            raise ValueError("version_spec must be a valid PEP 440 specifier set") from exc
        normalised = str(spec)
        if not normalised or len(normalised) > 100:
            raise ValueError("version_spec must be a non-empty specifier of at most 100 characters")
        return normalised

    @field_validator("codes")
    @classmethod
    def _codes(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v:
            code = str(raw).strip().upper()
            if not _CODE_RE.match(code):
                raise ValueError("codes must be finding codes such as NETWORK_EGRESS")
            if code in NON_OVERRIDABLE_CODES:
                raise ValueError(f"{code} findings are non-overridable and cannot be excepted")
            out.append(code)
        return _dedupe(out)

    @field_validator("categories")
    @classmethod
    def _categories(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v:
            category = str(raw).strip().lower()
            if category not in _CATEGORY_VALUES:
                raise ValueError(f"unknown finding category: {sanitize_text(category, max_len=40)}")
            out.append(category)
        return _dedupe(out)

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None) -> str | None:
        return validate_environment(v)

    @field_validator("justification")
    @classmethod
    def _justification(cls, v: str) -> str:
        v = v.strip()
        if len(v) < MIN_JUSTIFICATION_CHARS:
            raise ValueError(f"justification must be at least {MIN_JUSTIFICATION_CHARS} characters")
        return sanitize_text(v, max_len=MAX_JUSTIFICATION_CHARS, keep_newlines=True)

    @field_validator("expires_at")
    @classmethod
    def _expires_at(cls, v: datetime) -> datetime:
        v = v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if v <= now:
            raise ValueError("expires_at must be in the future")
        if v > now + timedelta(days=MAX_EXCEPTION_DAYS):
            raise ValueError(f"expires_at must be at most {MAX_EXCEPTION_DAYS} days from now")
        return v


class ExceptionTransition(BaseModel):
    """Optional body for approve / reject / revoke."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=500)

    @field_validator("comment")
    @classmethod
    def _comment(cls, v: str | None) -> str | None:
        return sanitize_text(v.strip(), max_len=500) if v and v.strip() else None


class ExceptionOut(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID | None
    package: str
    version_spec: str | None
    codes: list[str]
    categories: list[str]
    environment: str | None
    justification: str
    requested_by: uuid.UUID
    approved_by: uuid.UUID | None
    revoked_by: uuid.UUID | None
    # Effective status: "expired" whenever a pending/approved exception is past expires_at.
    status: ExceptionStatusOut
    active: bool = Field(description="True only when approved and not expired")
    expires_at: datetime
    created_at: datetime
    decided_at: datetime | None
    revoked_at: datetime | None
