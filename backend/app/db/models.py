"""SQLAlchemy ORM models (Warden 2 schema, Alembic revision ``0002_warden_x``).

See docs/DATA_MODEL.md for the ER diagram. Conventions:

* UUID primary keys (``GUID``) so API ids are not enumerable; JSON via ``PortableJSON``
  (JSONB on PostgreSQL).
* Every foreign key declares ``ondelete``. The choice is deliberate per relationship:
  ``CASCADE`` for owned children (signals of a scan, components of a project scan),
  ``SET NULL`` where the child is an independent record that must outlive its parent
  (scans outlive the requesting user, events outlive a scan), and ``RESTRICT`` where losing
  the link would destroy accountability (who requested / approved a policy exception).
  A policy exception's ``policy_id`` is ``CASCADE``, never ``SET NULL``: nulling it would
  silently turn a policy-scoped exception into a *global* one (privilege widening).
* Roles and other small vocabularies are stored as VARCHAR (non-native enums) so adding a
  value never requires a database type migration; values are validated in Python.
* Columns and indexes here must stay in lock-step with the Alembic migrations —
  ``tests/test_migrations.py`` fails if ``alembic upgrade head`` and this metadata diverge.
* ``audit_events`` is append-only: rows carry a SHA-256 hash chain (see
  :mod:`app.services.audit`) and, on PostgreSQL, a trigger rejects UPDATE/DELETE/TRUNCATE.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
    text,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.permissions import Role  # re-exported: ``from app.db.models import Role`` is public API
from app.db.base import Base, TimestampMixin, UUIDPrimaryKey, utcnow
from app.db.types import GUID, PortableJSON, StringEnum

__all__ = [
    "AuditEvent", "ContainerScan", "Decision", "DEFAULT_ENVIRONMENT", "DependencyEdge", "ENVIRONMENTS",
    "ExceptionStatus", "MonitoredPackage", "Policy", "PolicyException", "Project", "ProjectComponent",
    "ProjectScan", "RefreshToken", "ReleaseDiff", "Role", "Scan", "ScanJob", "SecurityEvent", "Severity",
    "Signal", "User", "VulnerabilityRecord",
]

# Policy / scan environments. Exactly one policy may be active per environment.
ENVIRONMENTS: tuple[str, ...] = ("development", "staging", "production")
DEFAULT_ENVIRONMENT = "production"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, enum.Enum):
    allow = "allow"
    warn = "warn"
    block = "block"


class ExceptionStatus(str, enum.Enum):
    """Stored lifecycle state of a policy exception.

    ``expired`` is deliberately *not* a stored state: expiry is derived from ``expires_at``
    at read time, so an exception becomes inactive exactly when it expires without relying
    on a background job having run.
    """

    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    revoked = "revoked"


# --------------------------------------------------------------------------- identity
class User(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(
        StringEnum(Role, length=32), default=Role.read_only, server_default=Role.read_only.value, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "refresh_tokens"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_refresh_token_hash"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")


# --------------------------------------------------------------------------- policy
class Policy(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "policies"
    __table_args__ = (
        # Database-enforced "exactly one active policy per environment" (partial unique index).
        Index(
            "uq_policies_active_environment", "environment", unique=True,
            sqlite_where=text("is_active = 1"), postgresql_where=text("is_active = true"),
        ),
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    warn_threshold: Mapped[int] = mapped_column(Integer, default=40, nullable=False)
    block_threshold: Mapped[int] = mapped_column(Integer, default=70, nullable=False)
    min_package_age_days: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # capability codes that force a BLOCK regardless of score
    blocked_capabilities: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=True)
    allowlist: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=True)
    denylist: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # --- Warden 2 ---
    environment: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_ENVIRONMENT, server_default=DEFAULT_ENVIRONMENT, nullable=False, index=True
    )
    # Policy-as-code document (validated by the policy document model before storage).
    document: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)


class PolicyException(Base, UUIDPrimaryKey, TimestampMixin):
    """A time-boxed, approved waiver of specific findings for a package.

    Separation of duties (approver ≠ requester) and the maximum lifetime are enforced by
    the API layer; the stored ``status`` never contains ``expired`` (derived at read time).
    """

    __tablename__ = "policy_exceptions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'revoked')", name="ck_policy_exceptions_status"
        ),
    )

    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("policies.id", ondelete="CASCADE"), nullable=True, index=True
    )
    package: Mapped[str] = mapped_column(String(214), nullable=False, index=True)  # PEP 503 normalised
    version_spec: Mapped[str | None] = mapped_column(String(100), nullable=True)
    codes: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=False)
    categories: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=False)
    environment: Mapped[str | None] = mapped_column(String(20), nullable=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default=ExceptionStatus.pending.value, nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Additive to SPEC §5: who revoked it and when (approval metadata is kept intact).
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------- package scans
class Scan(Base, UUIDPrimaryKey, TimestampMixin):
    """One verdict per (package, version, analyzer version, **environment**).

    Policy decisions are environment-dependent, so the environment is part of the identity: a
    re-scan under a laxer environment's policy can never overwrite another environment's verdict
    (Alembic revision ``0003_scan_environment``).
    """

    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package_name", "version", "analyzer_version", "environment", name="uq_scan_pkg_env"
        ),
        Index("ix_scans_package_name_created_at", "package_name", "created_at"),
    )

    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )
    ecosystem: Mapped[str] = mapped_column(String(20), default="pypi", nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(214), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)

    rule_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ml_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, nullable=False)
    decision: Mapped[Decision] = mapped_column(
        Enum(Decision), default=Decision.allow, nullable=False, index=True
    )
    feature_vector: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=True)
    matched_policy_rules: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=True)
    analyzer_version: Mapped[str] = mapped_column(String(20), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # --- Warden 2 ---
    risk: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    attack_chains: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    analyzer_runs: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    package_intel: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    provenance: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    vulnerabilities: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    intel_status: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_reasons: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    environment: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_ENVIRONMENT, server_default=DEFAULT_ENVIRONMENT, nullable=False
    )
    vulnerability_risk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    malicious_risk: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    # Additive to SPEC §5 so every AnalysisResult field is persisted (ML explanation, options).
    explanation: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    scan_options: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)

    signals: Mapped[list[Signal]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Signal(Base, UUIDPrimaryKey):
    """One persisted finding (the v1 table name is kept for compatibility)."""

    __tablename__ = "signals"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=True)
    # --- Warden 2 finding fields ---
    finding_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    category: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    title: Mapped[str | None] = mapped_column(String(160), nullable=True)
    analyzer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analyzer_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    capability: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    cwe: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    attack: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    provenance: Mapped[str | None] = mapped_column(String(64), nullable=True)
    related: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="signals")


# --------------------------------------------------------------------------- audit & events
class AuditEvent(Base, UUIDPrimaryKey, TimestampMixin):
    """Append-only, hash-chained audit record. Write only via :func:`app.services.audit.record`."""

    __tablename__ = "audit_events"

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", PortableJSON, default=dict, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # --- Warden 2 hash chain ---
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class SecurityEvent(Base, UUIDPrimaryKey):
    """A security-relevant occurrence (scan verdict, drift, new vulnerability, exception change)."""

    __tablename__ = "security_events"

    type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    package: Mapped[str | None] = mapped_column(String(214), nullable=True, index=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    details: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False,
        index=True,
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------- projects / SBOM
class Project(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("name", name="uq_projects_name"),)

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=utcnow)

    scans: Mapped[list[ProjectScan]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )


class ProjectScan(Base, UUIDPrimaryKey):
    __tablename__ = "project_scans"

    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False,
        index=True,
    )
    manifests: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    component_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    direct_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    decision: Mapped[str | None] = mapped_column(String(10), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    summary: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    sbom_cyclonedx: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    graph: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    policy_reasons: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    environment: Mapped[str | None] = mapped_column(String(20), nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    components: Mapped[list[ProjectComponent]] = relationship(
        back_populates="project_scan", cascade="all, delete-orphan", passive_deletes=True
    )
    edges: Mapped[list[DependencyEdge]] = relationship(
        back_populates="project_scan", cascade="all, delete-orphan", passive_deletes=True
    )


class ProjectComponent(Base, UUIDPrimaryKey):
    __tablename__ = "project_components"

    project_scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("project_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    bom_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    name: Mapped[str] = mapped_column(String(214), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(400), nullable=True)
    direct: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scope: Mapped[str | None] = mapped_column(String(20), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(30), nullable=True)
    hashes: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    licenses: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    declared_at: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    introduced_by: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(10), nullable=True)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    project_scan: Mapped[ProjectScan] = relationship(back_populates="components")


class DependencyEdge(Base, UUIDPrimaryKey):
    __tablename__ = "dependency_edges"

    project_scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("project_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    child_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    specifier: Mapped[str | None] = mapped_column(String(200), nullable=True)

    project_scan: Mapped[ProjectScan] = relationship(back_populates="edges")


# --------------------------------------------------------------------------- intelligence
class VulnerabilityRecord(Base):
    """Cached advisory (OSV id as primary key) enriched with KEV / EPSS."""

    __tablename__ = "vulnerability_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    aliases: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(10), default="unknown", server_default="unknown", nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    data: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )


# --------------------------------------------------------------------------- monitoring / diffs
class MonitoredPackage(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "monitored_packages"
    __table_args__ = (
        # NULL project_id rows are not covered by this constraint on either backend (NULLs
        # are distinct); the partial index below enforces uniqueness for global entries.
        UniqueConstraint("ecosystem", "name", "project_id", name="uq_monitored_package"),
        Index(
            "uq_monitored_packages_global", "ecosystem", "name", unique=True,
            sqlite_where=text("project_id IS NULL"), postgresql_where=text("project_id IS NULL"),
        ),
    )

    ecosystem: Mapped[str] = mapped_column(String(20), default="pypi", server_default="pypi", nullable=False)
    name: Mapped[str] = mapped_column(String(214), nullable=False, index=True)
    approved_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_seen_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true(), nullable=False)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, server_default="3600", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snapshot: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)


class ReleaseDiff(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "release_diffs"
    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package", "old_version", "new_version", "analyzer_version", name="uq_release_diff"
        ),
    )

    ecosystem: Mapped[str] = mapped_column(String(20), default="pypi", server_default="pypi", nullable=False)
    package: Mapped[str] = mapped_column(String(214), nullable=False, index=True)
    old_version: Mapped[str] = mapped_column(String(64), nullable=False)
    new_version: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(20), nullable=False)
    drift_detected: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    drift_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    summary: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    findings: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


# --------------------------------------------------------------------------- containers / jobs
class ContainerScan(Base, UUIDPrimaryKey):
    __tablename__ = "container_scans"

    image_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    image_digest: Mapped[str | None] = mapped_column(String(100), nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", server_default="queued", nullable=False)
    tools: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    summary: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    findings: Mapped[list | None] = mapped_column(PortableJSON, nullable=True)
    sbom: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(10), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ScanJob(Base, UUIDPrimaryKey):
    """Queued unit of background work (package | project | monitor)."""

    __tablename__ = "scan_jobs"

    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="queued", server_default="queued", nullable=False, index=True
    )
    payload: Mapped[dict | None] = mapped_column(PortableJSON, nullable=True)
    result_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
