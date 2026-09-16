"""Policy schemas.

Policies are scoped to an environment (development | staging | production); exactly one
policy may be active per environment.

A policy is either *legacy* (the v1 columns: thresholds, minimum release age, blocked
capabilities, allow/deny lists) or *policy-as-code* (``document``, a
:class:`~app.policy.document.PolicyDocument`). When a document is supplied on create/update it is
validated strictly and normalised, and the v1 columns are mirrored from it so v1 readers keep
seeing the same thresholds and lists. The document is then the single source of truth:

* the v1 rule fields (thresholds, minimum age, lists) must be omitted;
* ``name`` defaults to ``metadata.name`` and must equal it when both are given;
* ``environment`` must equal ``metadata.environment`` when both are given; the stored document
  always carries the resolved environment.

Every output includes ``policy_hash``: the SHA-256 of the canonical JSON of the document the
policy evaluates as (for a legacy policy, the document derived from its columns). Scan
evaluations record the same hash, which links a verdict to the exact policy content.

``POST /policies/validate`` accepts exactly one of ``document`` (an object) or ``yaml`` (YAML or
JSON text, at most :data:`~app.policy.document.MAX_POLICY_BYTES`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from app.db.models import DEFAULT_ENVIRONMENT
from app.policy.document import MAX_POLICY_BYTES, PolicyDocument, policy_hash_for
from app.schemas.scan import validate_environment

_MAX_LIST_ITEMS = 1000
LEGACY_RULE_FIELDS = (
    "warn_threshold", "block_threshold", "min_package_age_days", "blocked_capabilities", "allowlist", "denylist",
)


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


def _mirror_document(model: BaseModel, document: PolicyDocument) -> None:
    """Reject v1 rule fields next to a document, check the name, then copy the document's values."""
    conflicting = sorted(set(model.model_fields_set) & set(LEGACY_RULE_FIELDS))
    if conflicting:
        raise ValueError(f"{', '.join(conflicting)} cannot be combined with document: the document defines them")
    name = getattr(model, "name", None)
    if name is not None and name != document.metadata.name:
        raise ValueError("name must equal document metadata.name")
    spec = document.spec
    model.name = document.metadata.name
    model.warn_threshold = spec.thresholds.warn
    model.block_threshold = spec.thresholds.block
    model.min_package_age_days = spec.min_package_age_days
    model.blocked_capabilities = list(spec.deny.capabilities)
    model.allowlist = list(spec.allow.packages)
    model.denylist = list(spec.deny.packages)


class PolicyCreate(PolicyBase):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    environment: str = Field(default=DEFAULT_ENVIRONMENT, description="development|staging|production")
    document: PolicyDocument | None = Field(default=None, description="Policy-as-code document (warden.dev/v1)")

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str) -> str:
        return validate_environment(v) or DEFAULT_ENVIRONMENT

    @model_validator(mode="after")
    def _resolve_document(self) -> "PolicyCreate":
        if self.document is None:
            if self.name is None:
                raise ValueError("name is required unless a document is supplied")
            return self
        explicit_environment = "environment" in self.model_fields_set
        document_environment = self.document.metadata.environment
        if explicit_environment and document_environment is not None and document_environment != self.environment:
            raise ValueError("environment must equal document metadata.environment")
        _mirror_document(self, self.document)
        if not explicit_environment:
            self.environment = document_environment or DEFAULT_ENVIRONMENT
        self.document = self.document.with_environment(self.environment)
        return self


class PolicyUpdate(PolicyBase):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    # Omitted = keep the policy's current environment (a PUT must not silently move it).
    environment: str | None = Field(default=None, description="development|staging|production")
    # Omitted on a policy that has a document = conflict; explicit null = convert back to v1 columns.
    document: PolicyDocument | None = Field(default=None, description="Policy-as-code document (warden.dev/v1)")

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None) -> str | None:
        return validate_environment(v)

    @model_validator(mode="after")
    def _resolve_document(self) -> "PolicyUpdate":
        if self.document is None:
            if self.name is None:
                raise ValueError("name is required unless a document is supplied")
            return self
        document_environment = self.document.metadata.environment
        if self.environment is not None and document_environment is not None \
                and document_environment != self.environment:
            raise ValueError("environment must equal document metadata.environment")
        _mirror_document(self, self.document)
        if self.environment is None:
            self.environment = document_environment
        return self

    @property
    def document_supplied(self) -> bool:
        """True when the request body contained a ``document`` key (including an explicit null)."""
        return "document" in self.model_fields_set


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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_hash(self) -> str | None:
        """SHA-256 of the canonical JSON of the document this policy evaluates as."""
        return policy_hash_for(self)


class PolicyValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document: dict[str, Any] | None = Field(default=None, description="Policy document as a JSON object")
    yaml: str | None = Field(default=None, max_length=MAX_POLICY_BYTES,
                             description="Policy document as YAML (or JSON) text")

    @model_validator(mode="after")
    def _exactly_one(self) -> "PolicyValidateRequest":
        if (self.document is None) == (self.yaml is None):
            raise ValueError("provide exactly one of document or yaml")
        return self


class PolicyValidationIssue(BaseModel):
    loc: str
    msg: str
    line: int | None = None


class PolicyValidateResponse(BaseModel):
    valid: bool
    errors: list[PolicyValidationIssue] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    normalized: dict[str, Any] | None = None
    policy_hash: str | None = None
