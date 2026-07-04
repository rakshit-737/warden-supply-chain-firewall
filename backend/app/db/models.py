"""SQLAlchemy ORM models. See docs/DATA_MODEL.md for the ER diagram and rationale."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKey
from app.db.types import GUID, PortableJSON


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


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


class User(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")


class Policy(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    warn_threshold: Mapped[int] = mapped_column(Integer, default=40, nullable=False)
    block_threshold: Mapped[int] = mapped_column(Integer, default=70, nullable=False)
    min_package_age_days: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # capability codes that force a BLOCK regardless of score
    blocked_capabilities: Mapped[list] = mapped_column(PortableJSON, default=list)
    allowlist: Mapped[list] = mapped_column(PortableJSON, default=list)
    denylist: Mapped[list] = mapped_column(PortableJSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Scan(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package_name", "version", "analyzer_version", name="uq_scan_pkg"
        ),
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
    feature_vector: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    matched_policy_rules: Mapped[list] = mapped_column(PortableJSON, default=list)
    analyzer_version: Mapped[str] = mapped_column(String(20), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    signals: Mapped[list["Signal"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Signal(Base, UUIDPrimaryKey):
    __tablename__ = "signals"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="signals")


class AuditEvent(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "audit_events"

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(40), nullable=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", PortableJSON, default=dict)
    request_id: Mapped[str] = mapped_column(String(64), nullable=True)
