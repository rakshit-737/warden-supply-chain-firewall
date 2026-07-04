"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01 00:00:00
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.db.types import GUID, PortableJSON

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

role_enum = sa.Enum("admin", "analyst", "viewer", name="role")
severity_enum = sa.Enum("info", "low", "medium", "high", "critical", name="severity")
decision_enum = sa.Enum("allow", "warn", "block", name="decision")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", role_enum, nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("user_id", GUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_refresh_token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"])

    op.create_table(
        "policies",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("warn_threshold", sa.Integer(), nullable=False, server_default="40"),
        sa.Column("block_threshold", sa.Integer(), nullable=False, server_default="70"),
        sa.Column("min_package_age_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocked_capabilities", PortableJSON(), nullable=True),
        sa.Column("allowlist", PortableJSON(), nullable=True),
        sa.Column("denylist", PortableJSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_policies_is_active", "policies", ["is_active"])

    op.create_table(
        "scans",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("requested_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("policy_id", GUID(), sa.ForeignKey("policies.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ecosystem", sa.String(20), nullable=False, server_default="pypi"),
        sa.Column("package_name", sa.String(214), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("rule_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ml_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", severity_enum, nullable=False, server_default="info"),
        sa.Column("decision", decision_enum, nullable=False, server_default="allow"),
        sa.Column("feature_vector", PortableJSON(), nullable=True),
        sa.Column("matched_policy_rules", PortableJSON(), nullable=True),
        sa.Column("analyzer_version", sa.String(20), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("ecosystem", "package_name", "version", "analyzer_version", name="uq_scan_pkg"),
    )
    op.create_index("ix_scans_package_name", "scans", ["package_name"])
    op.create_index("ix_scans_decision", "scans", ["decision"])
    op.create_index("ix_scans_risk_score", "scans", ["risk_score"])
    op.create_index("ix_scans_ecosystem", "scans", ["ecosystem"])
    op.create_index("ix_scans_requested_by", "scans", ["requested_by"])

    op.create_table(
        "signals",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("scan_id", GUID(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("severity", severity_enum, nullable=False, server_default="info"),
        sa.Column("weight", sa.Float(), nullable=False, server_default="0"),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("evidence", PortableJSON(), nullable=True),
    )
    op.create_index("ix_signals_scan_id", "signals", ["scan_id"])
    op.create_index("ix_signals_code", "signals", ["code"])

    op.create_table(
        "audit_events",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("actor_id", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target_type", sa.String(40), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("metadata", PortableJSON(), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("signals")
    op.drop_table("scans")
    op.drop_table("policies")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    for enum in (decision_enum, severity_enum, role_enum):
        enum.drop(op.get_bind(), checkfirst=True)
