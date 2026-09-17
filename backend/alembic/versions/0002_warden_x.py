"""Warden 2 schema

Adds: RBAC roles (non-native VARCHAR role column), finding/scan enrichment columns, policy
environments + policy-as-code documents, policy exceptions, security events, the audit
hash chain (with a PostgreSQL append-only trigger), projects/SBOM tables, vulnerability
records, monitored packages, release diffs, container scans and scan jobs.

Supported dialects: PostgreSQL (online and offline ``--sql``) and SQLite (online; schema
changes go through ``batch_alter_table``).

Data migrations:
* ``users.role``: ``analyst`` → ``security_analyst``, ``viewer`` → ``read_only``; on
  PostgreSQL the native ``role`` ENUM column becomes VARCHAR(32) and the type is dropped.
* ``scans.malicious_risk`` is backfilled from the v1 fused ``risk_score``.
* ``policies``: all rows get environment ``production``; if several rows were active (v1
  enforced "one active policy" only in application code) the most recently updated stays
  active so the per-environment unique index can be created.
* ``audit_events``: existing rows are chained in ``(created_at, id)`` order using the frozen
  v1 canonical form from :mod:`app.services.audit`. This needs a live connection; an offline
  PostgreSQL script instead refuses to proceed if unchained rows exist.

Downgrade maps roles back (security_analyst/developer → analyst, read_only/auditor/unknown →
viewer) and drops everything this revision added (Warden 2 data in new tables is lost).

Revision ID: 0002_warden_x
Revises: 0001_initial
Create Date: 2026-09-15 00:00:00
"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import context, op
from app.db.types import GUID, PortableJSON

revision: str = "0002_warden_x"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_V1_ROLE_ENUM = sa.Enum("admin", "analyst", "viewer", name="role")
_TRIGGER_FUNCTION = "warden_audit_events_append_only"


def _is_pg() -> bool:
    return op.get_context().dialect.name == "postgresql"


def _created_at(index: bool = False) -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=index
    )


def _uuid_pk() -> sa.Column:
    return sa.Column("id", GUID(), primary_key=True)


def _user_fk(name: str, *, nullable: bool = True, ondelete: str = "SET NULL") -> sa.Column:
    return sa.Column(name, GUID(), sa.ForeignKey("users.id", ondelete=ondelete), nullable=nullable)


# =========================================================================== upgrade
def upgrade() -> None:
    if context.is_offline_mode() and not _is_pg():
        raise RuntimeError("0002_warden_x: offline (--sql) generation is supported for PostgreSQL only")
    _upgrade_users_role()
    _upgrade_signals()
    _upgrade_scans()
    _upgrade_policies()
    _upgrade_audit_events()
    _create_tables()


def _upgrade_users_role() -> None:
    if _is_pg():
        op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
        op.execute("ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(32) USING role::text")
    else:
        with op.batch_alter_table("users") as batch:
            batch.alter_column(
                "role", existing_type=_V1_ROLE_ENUM, type_=sa.String(32), existing_nullable=False,
                server_default=None,
            )
    op.execute("UPDATE users SET role = 'security_analyst' WHERE role = 'analyst'")
    op.execute("UPDATE users SET role = 'read_only' WHERE role = 'viewer'")
    if _is_pg():
        op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'read_only'")
        op.execute("DROP TYPE IF EXISTS role")
    else:
        with op.batch_alter_table("users") as batch:
            batch.alter_column("role", existing_type=sa.String(32), existing_nullable=False,
                               server_default="read_only")


def _upgrade_signals() -> None:
    with op.batch_alter_table("signals") as batch:
        batch.add_column(sa.Column("finding_id", sa.String(32), nullable=True))
        batch.add_column(sa.Column("confidence", sa.Float(), nullable=True))
        batch.add_column(sa.Column("category", sa.String(40), nullable=True))
        batch.add_column(sa.Column("title", sa.String(160), nullable=True))
        batch.add_column(sa.Column("analyzer", sa.String(64), nullable=True))
        batch.add_column(sa.Column("analyzer_version", sa.String(20), nullable=True))
        batch.add_column(sa.Column("capability", sa.String(64), nullable=True))
        batch.add_column(sa.Column("location", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("cwe", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("attack", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("remediation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("references", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("provenance", sa.String(64), nullable=True))
        batch.add_column(sa.Column("related", PortableJSON(), nullable=True))
    op.create_index("ix_signals_finding_id", "signals", ["finding_id"])
    op.create_index("ix_signals_category", "signals", ["category"])


def _upgrade_scans() -> None:
    with op.batch_alter_table("scans") as batch:
        for name in ("risk", "attack_chains", "analyzer_runs", "package_intel", "provenance", "vulnerabilities",
                     "intel_status"):
            batch.add_column(sa.Column(name, PortableJSON(), nullable=True))
        batch.add_column(sa.Column("model_version", sa.String(64), nullable=True))
        batch.add_column(sa.Column("policy_reasons", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("environment", sa.String(20), nullable=True))
        batch.add_column(sa.Column("vulnerability_risk", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("malicious_risk", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("explanation", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("scan_options", PortableJSON(), nullable=True))
    # v1 risk_score *is* the fused rule/ML (malicious) score.
    op.execute("UPDATE scans SET malicious_risk = risk_score")
    op.create_index("ix_scans_package_name_created_at", "scans", ["package_name", "created_at"])


def _upgrade_policies() -> None:
    with op.batch_alter_table("policies") as batch:
        batch.add_column(sa.Column("environment", sa.String(20), nullable=False, server_default="production"))
        batch.add_column(sa.Column("document", PortableJSON(), nullable=True))
        batch.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    op.create_index("ix_policies_environment", "policies", ["environment"])

    policies = sa.table(
        "policies",
        sa.column("id", GUID()),
        sa.column("is_active", sa.Boolean()),
        sa.column("updated_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    newest_active = (
        sa.select(policies.c.id)
        .where(policies.c.is_active == sa.true())
        .order_by(sa.func.coalesce(policies.c.updated_at, policies.c.created_at).desc())
        .limit(1)
        .scalar_subquery()
    )
    op.execute(
        policies.update()
        .where(policies.c.is_active == sa.true(), policies.c.id != newest_active)
        .values(is_active=False)
    )
    op.create_index(
        "uq_policies_active_environment", "policies", ["environment"], unique=True,
        sqlite_where=sa.text("is_active = 1"), postgresql_where=sa.text("is_active = true"),
    )


def _upgrade_audit_events() -> None:
    with op.batch_alter_table("audit_events") as batch:
        batch.add_column(sa.Column("seq", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("prev_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("event_hash", sa.String(64), nullable=True))

    if context.is_offline_mode():
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM audit_events WHERE seq IS NULL) THEN "
            "RAISE EXCEPTION 'audit_events has rows that must be hash-chained, run this migration online'; "
            "END IF; END $$"
        )
    else:
        _backfill_audit_chain()

    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column("seq", existing_type=sa.BigInteger(), nullable=False)
        batch.alter_column("prev_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("event_hash", existing_type=sa.String(64), nullable=False)
    op.create_index("ix_audit_events_seq", "audit_events", ["seq"], unique=True)

    if _is_pg():
        op.execute(
            f"CREATE OR REPLACE FUNCTION {_TRIGGER_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION USING MESSAGE = 'audit_events is append-only, ' || TG_OP || ' rejected', "
            "ERRCODE = 'insufficient_privilege'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events "
            f"FOR EACH ROW EXECUTE FUNCTION {_TRIGGER_FUNCTION}()"
        )
        op.execute(
            "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
            f"FOR EACH STATEMENT EXECUTE FUNCTION {_TRIGGER_FUNCTION}()"
        )


def _backfill_audit_chain() -> None:
    # Imported lazily: the canonical form is shared with the running application so the
    # backfilled chain verifies with app.services.audit.verify_chain.
    from app.services.audit import GENESIS_HASH, canonical_event, compute_event_hash

    audit = sa.table(
        "audit_events",
        sa.column("id", GUID()),
        sa.column("actor_id", GUID()),
        sa.column("action", sa.String(80)),
        sa.column("target_type", sa.String(40)),
        sa.column("target_id", sa.String(64)),
        sa.column("metadata", PortableJSON()),
        sa.column("request_id", sa.String(64)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("seq", sa.BigInteger()),
        sa.column("prev_hash", sa.String(64)),
        sa.column("event_hash", sa.String(64)),
    )
    bind = op.get_bind()
    rows = bind.execute(
        sa.select(
            audit.c.id, audit.c.actor_id, audit.c.action, audit.c.target_type, audit.c.target_id,
            audit.c.metadata, audit.c.request_id, audit.c.created_at,
        ).order_by(audit.c.created_at, audit.c.id)
    ).all()
    prev_hash = GENESIS_HASH
    for seq, row in enumerate(rows, start=1):
        m = row._mapping  # mapping access: "metadata" must never resolve to a Row attribute
        event_hash = compute_event_hash(
            prev_hash,
            canonical_event(
                seq=seq, event_id=m["id"], actor_id=m["actor_id"], action=m["action"],
                target_type=m["target_type"], target_id=m["target_id"], metadata=m["metadata"],
                request_id=m["request_id"], created_at=m["created_at"],
            ),
        )
        bind.execute(
            audit.update().where(audit.c.id == m["id"]).values(seq=seq, prev_hash=prev_hash, event_hash=event_hash)
        )
        prev_hash = event_hash


def _create_tables() -> None:
    op.create_table(
        "projects",
        _uuid_pk(),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        _user_fk("created_by"),
        _created_at(),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name", name="uq_projects_name"),
    )

    op.create_table(
        "project_scans",
        _uuid_pk(),
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        _user_fk("requested_by"),
        _created_at(),
        sa.Column("manifests", PortableJSON(), nullable=True),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("direct_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("decision", sa.String(10), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", PortableJSON(), nullable=True),
        sa.Column("sbom_cyclonedx", PortableJSON(), nullable=True),
        sa.Column("graph", PortableJSON(), nullable=True),
        sa.Column("policy_reasons", PortableJSON(), nullable=True),
        sa.Column("environment", sa.String(20), nullable=True),
    )
    op.create_index("ix_project_scans_project_id", "project_scans", ["project_id"])
    op.create_index("ix_project_scans_created_at", "project_scans", ["created_at"])

    op.create_table(
        "project_components",
        _uuid_pk(),
        sa.Column(
            "project_scan_id", GUID(), sa.ForeignKey("project_scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("bom_ref", sa.String(300), nullable=False),
        sa.Column("name", sa.String(214), nullable=False),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("purl", sa.String(400), nullable=True),
        sa.Column("direct", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("depth", sa.Integer(), nullable=True),
        sa.Column("scope", sa.String(20), nullable=True),
        sa.Column("resolution", sa.String(30), nullable=True),
        sa.Column("hashes", PortableJSON(), nullable=True),
        sa.Column("licenses", PortableJSON(), nullable=True),
        sa.Column("declared_at", PortableJSON(), nullable=True),
        sa.Column("introduced_by", PortableJSON(), nullable=True),
        sa.Column("scan_id", GUID(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("decision", sa.String(10), nullable=True),
        sa.Column("vulnerability_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_project_components_project_scan_id", "project_components", ["project_scan_id"])
    op.create_index("ix_project_components_name", "project_components", ["name"])

    op.create_table(
        "dependency_edges",
        _uuid_pk(),
        sa.Column(
            "project_scan_id", GUID(), sa.ForeignKey("project_scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("parent_ref", sa.String(300), nullable=False),
        sa.Column("child_ref", sa.String(300), nullable=False),
        sa.Column("specifier", sa.String(200), nullable=True),
    )
    op.create_index("ix_dependency_edges_project_scan_id", "dependency_edges", ["project_scan_id"])

    op.create_table(
        "vulnerability_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("aliases", PortableJSON(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False, server_default="unknown"),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("data", PortableJSON(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "monitored_packages",
        _uuid_pk(),
        sa.Column("ecosystem", sa.String(20), nullable=False, server_default="pypi"),
        sa.Column("name", sa.String(214), nullable=False),
        sa.Column("approved_version", sa.String(64), nullable=True),
        sa.Column("latest_seen_version", sa.String(64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("poll_interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", GUID(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_risk_score", sa.Integer(), nullable=True),
        sa.Column("snapshot", PortableJSON(), nullable=True),
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        _user_fk("created_by"),
        _created_at(),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("ecosystem", "name", "project_id", name="uq_monitored_package"),
    )
    op.create_index("ix_monitored_packages_name", "monitored_packages", ["name"])
    op.create_index("ix_monitored_packages_next_check_at", "monitored_packages", ["next_check_at"])
    op.create_index(
        "uq_monitored_packages_global", "monitored_packages", ["ecosystem", "name"], unique=True,
        sqlite_where=sa.text("project_id IS NULL"), postgresql_where=sa.text("project_id IS NULL"),
    )

    op.create_table(
        "release_diffs",
        _uuid_pk(),
        sa.Column("ecosystem", sa.String(20), nullable=False, server_default="pypi"),
        sa.Column("package", sa.String(214), nullable=False),
        sa.Column("old_version", sa.String(64), nullable=False),
        sa.Column("new_version", sa.String(64), nullable=False),
        sa.Column("analyzer_version", sa.String(20), nullable=False),
        sa.Column("drift_detected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("drift_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", PortableJSON(), nullable=True),
        sa.Column("findings", PortableJSON(), nullable=True),
        _user_fk("created_by"),
        _created_at(),
        sa.UniqueConstraint(
            "ecosystem", "package", "old_version", "new_version", "analyzer_version", name="uq_release_diff"
        ),
    )
    op.create_index("ix_release_diffs_package", "release_diffs", ["package"])

    op.create_table(
        "container_scans",
        _uuid_pk(),
        sa.Column("image_ref", sa.String(512), nullable=False),
        sa.Column("image_digest", sa.String(100), nullable=True),
        _user_fk("requested_by"),
        _created_at(),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("tools", PortableJSON(), nullable=True),
        sa.Column("summary", PortableJSON(), nullable=True),
        sa.Column("findings", PortableJSON(), nullable=True),
        sa.Column("sbom", PortableJSON(), nullable=True),
        sa.Column("decision", sa.String(10), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
    )
    op.create_index("ix_container_scans_created_at", "container_scans", ["created_at"])

    op.create_table(
        "scan_jobs",
        _uuid_pk(),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("payload", PortableJSON(), nullable=True),
        sa.Column("result_ref", sa.String(64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        _created_at(),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        _user_fk("requested_by"),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])

    op.create_table(
        "policy_exceptions",
        _uuid_pk(),
        sa.Column("policy_id", GUID(), sa.ForeignKey("policies.id", ondelete="CASCADE"), nullable=True),
        sa.Column("package", sa.String(214), nullable=False),
        sa.Column("version_spec", sa.String(100), nullable=True),
        sa.Column("codes", PortableJSON(), nullable=False),
        sa.Column("categories", PortableJSON(), nullable=False),
        sa.Column("environment", sa.String(20), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        _user_fk("requested_by", nullable=False, ondelete="RESTRICT"),
        _user_fk("approved_by", ondelete="RESTRICT"),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _created_at(),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        _user_fk("revoked_by", ondelete="RESTRICT"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'revoked')", name="ck_policy_exceptions_status"
        ),
    )
    op.create_index("ix_policy_exceptions_policy_id", "policy_exceptions", ["policy_id"])
    op.create_index("ix_policy_exceptions_package", "policy_exceptions", ["package"])
    op.create_index("ix_policy_exceptions_requested_by", "policy_exceptions", ["requested_by"])
    op.create_index("ix_policy_exceptions_status", "policy_exceptions", ["status"])
    op.create_index("ix_policy_exceptions_expires_at", "policy_exceptions", ["expires_at"])

    op.create_table(
        "security_events",
        _uuid_pk(),
        sa.Column("type", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("package", sa.String(214), nullable=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scan_id", GUID(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("details", PortableJSON(), nullable=True),
        _created_at(),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
        _user_fk("acknowledged_by"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_security_events_type", "security_events", ["type"])
    op.create_index("ix_security_events_severity", "security_events", ["severity"])
    op.create_index("ix_security_events_package", "security_events", ["package"])
    op.create_index("ix_security_events_project_id", "security_events", ["project_id"])
    op.create_index("ix_security_events_created_at", "security_events", ["created_at"])


# =========================================================================== downgrade
_NEW_TABLES = (
    "security_events", "policy_exceptions", "scan_jobs", "container_scans", "release_diffs",
    "monitored_packages", "vulnerability_records", "dependency_edges", "project_components",
    "project_scans", "projects",
)


def downgrade() -> None:
    if context.is_offline_mode() and not _is_pg():
        raise RuntimeError("0002_warden_x: offline (--sql) generation is supported for PostgreSQL only")
    for table in _NEW_TABLES:
        op.drop_table(table)
    _downgrade_audit_events()
    _downgrade_policies()
    _downgrade_scans()
    _downgrade_signals()
    _downgrade_users_role()


def _downgrade_audit_events() -> None:
    if _is_pg():
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
        op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        op.execute(f"DROP FUNCTION IF EXISTS {_TRIGGER_FUNCTION}()")
    op.drop_index("ix_audit_events_seq", table_name="audit_events")
    with op.batch_alter_table("audit_events") as batch:
        batch.drop_column("event_hash")
        batch.drop_column("prev_hash")
        batch.drop_column("seq")


def _downgrade_policies() -> None:
    op.drop_index("uq_policies_active_environment", table_name="policies")
    op.drop_index("ix_policies_environment", table_name="policies")
    # v1 allows a single active policy globally: keep only the newest active one.
    policies = sa.table(
        "policies",
        sa.column("id", GUID()),
        sa.column("is_active", sa.Boolean()),
        sa.column("updated_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    newest_active = (
        sa.select(policies.c.id)
        .where(policies.c.is_active == sa.true())
        .order_by(sa.func.coalesce(policies.c.updated_at, policies.c.created_at).desc())
        .limit(1)
        .scalar_subquery()
    )
    op.execute(
        policies.update()
        .where(policies.c.is_active == sa.true(), policies.c.id != newest_active)
        .values(is_active=False)
    )
    with op.batch_alter_table("policies") as batch:
        batch.drop_column("version")
        batch.drop_column("document")
        batch.drop_column("environment")


def _downgrade_scans() -> None:
    op.drop_index("ix_scans_package_name_created_at", table_name="scans")
    with op.batch_alter_table("scans") as batch:
        for name in ("scan_options", "explanation", "malicious_risk", "vulnerability_risk", "environment",
                     "policy_reasons", "model_version", "intel_status", "vulnerabilities", "provenance",
                     "package_intel", "analyzer_runs", "attack_chains", "risk"):
            batch.drop_column(name)


def _downgrade_signals() -> None:
    op.drop_index("ix_signals_category", table_name="signals")
    op.drop_index("ix_signals_finding_id", table_name="signals")
    with op.batch_alter_table("signals") as batch:
        for name in ("related", "provenance", "references", "remediation", "attack", "cwe", "location",
                     "capability", "analyzer_version", "analyzer", "title", "category", "confidence",
                     "finding_id"):
            batch.drop_column(name)


def _downgrade_users_role() -> None:
    if _is_pg():
        op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute("UPDATE users SET role = 'analyst' WHERE role IN ('security_analyst', 'developer')")
    op.execute("UPDATE users SET role = 'viewer' WHERE role NOT IN ('admin', 'analyst')")
    if _is_pg():
        op.execute("CREATE TYPE role AS ENUM ('admin', 'analyst', 'viewer')")
        op.execute("ALTER TABLE users ALTER COLUMN role TYPE role USING role::role")
        op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'viewer'")
    else:
        with op.batch_alter_table("users") as batch:
            batch.alter_column(
                "role", existing_type=sa.String(32), type_=_V1_ROLE_ENUM, existing_nullable=False,
                server_default="viewer",
            )
