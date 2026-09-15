"""Alembic migrations: schema parity with the ORM, data migration, downgrade and PostgreSQL SQL.

Every test migrates its own temporary SQLite file; the shared test database is never touched.

Schema parity uses ``alembic.autogenerate.compare_metadata`` with ``compare_type=True``: after
``upgrade head`` the database must match ``Base.metadata`` exactly. **No dialect noise is
filtered** — on the pinned SQLAlchemy/Alembic versions SQLite reports no spurious differences.
Server defaults are not compared (models use Python-side defaults for several v1 columns whose
0001 migration also declared a server default; that difference is intentional and harmless).
A control test drops an index to prove the comparison is not vacuous.

PostgreSQL-specific DDL (native enum -> VARCHAR conversion, the append-only trigger) cannot be
executed without a PostgreSQL server, so it is checked through offline ``--sql`` generation.
"""

from __future__ import annotations

import argparse
import io
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alembic import command
from app.db.base import Base
from app.db.models import Policy, Role, User
from app.services import audit

BACKEND = Path(__file__).resolve().parents[1]
HEAD = "0003_scan_environment"


def _config(url: str, *, x_url: str | None = None, buffer: io.StringIO | None = None) -> Config:
    # No ini file: env.py then leaves the test runner's logging configuration alone.
    cmd_opts = argparse.Namespace(x=[f"url={x_url}"]) if x_url else None
    cfg = Config(cmd_opts=cmd_opts, output_buffer=buffer)
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    return cfg


@pytest.fixture()
def database(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path / 'migrated.db'}"
    engine = create_engine(url)
    try:
        yield url, engine
    finally:
        engine.dispose()


def _schema_diff(engine) -> list:
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(context, Base.metadata)


def _revision(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()


# --------------------------------------------------------------------------- schema parity
def test_single_head():
    assert ScriptDirectory.from_config(_config("sqlite://")).get_heads() == [HEAD]


def test_upgrade_head_matches_the_orm_metadata(database):
    url, engine = database
    command.upgrade(_config(url), "head")
    assert _revision(engine) == HEAD
    assert _schema_diff(engine) == []
    tables = set(inspect(engine).get_table_names())
    assert {"policy_exceptions", "security_events", "projects", "project_scans", "project_components",
            "dependency_edges", "vulnerability_records", "monitored_packages", "release_diffs",
            "container_scans", "scan_jobs"} <= tables


def test_schema_comparison_detects_drift(database):
    url, engine = database
    command.upgrade(_config(url), "head")
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_signals_category"))
    diff = _schema_diff(engine)
    assert any(d[0] == "add_index" and d[1].name == "ix_signals_category" for d in diff), diff


def test_downgrade_to_v1_and_upgrade_again(database):
    url, engine = database
    cfg = _config(url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0001_initial")
    assert _revision(engine) == "0001_initial"
    inspector = inspect(engine)
    assert "security_events" not in inspector.get_table_names()
    assert "seq" not in {c["name"] for c in inspector.get_columns("audit_events")}
    assert "environment" not in {c["name"] for c in inspector.get_columns("policies")}
    command.upgrade(cfg, "head")
    assert _revision(engine) == HEAD
    assert _schema_diff(engine) == []


# --------------------------------------------------------------------------- data migration
_V1_USERS = (
    ("11111111-1111-1111-1111-111111111111", "admin@v1.io", "admin"),
    ("22222222-2222-2222-2222-222222222222", "analyst@v1.io", "analyst"),
    ("33333333-3333-3333-3333-333333333333", "viewer@v1.io", "viewer"),
)


def _seed_v1(engine) -> None:
    with engine.begin() as conn:
        for user_id, email, role in _V1_USERS:
            conn.execute(text("INSERT INTO users (id, email, password_hash, role, is_active) "
                              "VALUES (:id, :email, 'h', :role, 1)"), {"id": user_id, "email": email, "role": role})
        # v1 enforced "one active policy" only in application code: two active rows can exist.
        conn.execute(text(
            "INSERT INTO policies (id, name, is_active, warn_threshold, block_threshold, min_package_age_days, "
            "created_at, updated_at) VALUES "
            "('aaaaaaaa-0000-0000-0000-000000000001', 'older', 1, 40, 70, 0, '2026-01-01 00:00:00', "
            "'2026-01-01 00:00:00'), "
            "('aaaaaaaa-0000-0000-0000-000000000002', 'newer', 1, 40, 70, 0, '2026-02-01 00:00:00', "
            "'2026-02-01 00:00:00')"
        ))
        conn.execute(text(
            "INSERT INTO scans (id, ecosystem, package_name, version, rule_score, ml_score, risk_score, severity, "
            "decision, analyzer_version, duration_ms) VALUES ('bbbbbbbb-0000-0000-0000-000000000001', 'pypi', "
            "'legacy-pkg', '1.0.0', 77, 10, 77, 'high', 'block', '1.0.0', 5)"
        ))
        conn.execute(text(
            "INSERT INTO audit_events (id, actor_id, action, target_type, target_id, metadata, request_id, "
            "created_at) VALUES "
            "('cccccccc-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'policy.update', "
            "'policy', 'p1', '{\"version\": 2}', 'req-2', '2026-01-02 10:00:00'), "
            "('cccccccc-0000-0000-0000-000000000001', NULL, 'user.login', 'user', 'u1', NULL, NULL, "
            "'2026-01-01 09:00:00')"
        ))


def test_upgrade_migrates_v1_data(database):
    url, engine = database
    cfg = _config(url)
    command.upgrade(cfg, "0001_initial")
    _seed_v1(engine)
    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        roles = dict(conn.execute(text("SELECT email, role FROM users")).all())
        policies = conn.execute(text("SELECT name, is_active, environment, version FROM policies ORDER BY name")).all()
        risk = conn.execute(text("SELECT malicious_risk, vulnerability_risk, environment FROM scans")).one()
        chain = conn.execute(text("SELECT seq, action FROM audit_events ORDER BY seq")).all()
    assert roles == {"admin@v1.io": "admin", "analyst@v1.io": "security_analyst", "viewer@v1.io": "read_only"}
    assert [tuple(p) for p in policies] == [("newer", 1, "production", 1), ("older", 0, "production", 1)]
    assert tuple(risk) == (77, None, "production")  # v1 verdicts were production verdicts
    assert [tuple(r) for r in chain] == [(1, "user.login"), (2, "policy.update")]  # chained by created_at

    with Session(engine) as session:
        # Backfilled rows verify with the application's verifier, and the app can keep appending.
        assert audit.verify_chain(session) == {**audit.verify_chain(session), "ok": True, "checked": 2}
        audit.record(session, actor_id=None, action="post.migration")
        session.commit()
        assert audit.verify_chain(session)["checked"] == 3
        assert {u.email: u.role for u in session.scalars(select(User))}["viewer@v1.io"] is Role.read_only
        # The per-environment "one active policy" rule is enforced by the database itself.
        session.add(Policy(id=uuid.uuid4(), name="second active", is_active=True, environment="production",
                           updated_at=datetime.now(timezone.utc) + timedelta(days=1)))
        with pytest.raises(IntegrityError):
            session.commit()


_SCAN_INSERT = text(
    "INSERT INTO scans (id, ecosystem, package_name, version, rule_score, ml_score, risk_score, severity, decision, "
    "analyzer_version, duration_ms, malicious_risk, environment, created_at) VALUES (:id, 'pypi', 'pkg', '1.0', 0, 0, "
    ":risk, 'info', :decision, '2.0.0', 1, 0, :env, :created)"
)


def test_scan_verdicts_are_unique_per_environment_and_downgrade_keeps_the_newest(database):
    url, engine = database
    cfg = _config(url)
    command.upgrade(cfg, "head")
    rows = [("dddddddd-0000-0000-0000-000000000001", 90, "block", "production", "2026-03-01 00:00:00"),
            ("dddddddd-0000-0000-0000-000000000002", 10, "allow", "development", "2026-03-02 00:00:00")]
    with engine.begin() as conn:
        for scan_id, risk, decision, env, created in rows:
            conn.execute(_SCAN_INSERT, {"id": scan_id, "risk": risk, "decision": decision, "env": env,
                                        "created": created})
        conn.execute(text("INSERT INTO signals (id, scan_id, code, severity, weight, message) VALUES "
                          "('eeeeeeee-0000-0000-0000-000000000001', 'dddddddd-0000-0000-0000-000000000001', "
                          "'IOC_MATCH', 'critical', 12.0, 'm')"))
    with pytest.raises(IntegrityError), engine.begin() as conn:  # same environment twice is still refused
        conn.execute(_SCAN_INSERT, {"id": "dddddddd-0000-0000-0000-000000000003", "risk": 1, "decision": "allow",
                                    "env": "production", "created": "2026-03-03 00:00:00"})
    command.downgrade(cfg, "0002_warden_x")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT id, environment FROM scans")).all() == [
            ("dddddddd-0000-0000-0000-000000000002", "development")]
        assert conn.execute(text("SELECT COUNT(*) FROM signals")).scalar_one() == 0
    command.upgrade(cfg, "head")
    assert _schema_diff(engine) == []


def test_downgrade_maps_warden_x_roles_back_to_v1(database):
    url, engine = database
    cfg = _config(url)
    command.upgrade(cfg, "head")
    with engine.begin() as conn:
        for role in ("admin", "security_analyst", "developer", "auditor", "read_only"):
            conn.execute(text("INSERT INTO users (id, email, password_hash, role, is_active) "
                              "VALUES (:id, :email, 'h', :role, 1)"),
                         {"id": str(uuid.uuid4()), "email": f"{role}@x.io", "role": role})
    command.downgrade(cfg, "0001_initial")
    with engine.connect() as conn:
        roles = dict(conn.execute(text("SELECT email, role FROM users")).all())
    assert roles == {"admin@x.io": "admin", "security_analyst@x.io": "analyst", "developer@x.io": "analyst",
                     "auditor@x.io": "viewer", "read_only@x.io": "viewer"}


# --------------------------------------------------------------------------- env.py / offline SQL
def test_x_url_argument_takes_precedence_over_configured_url(tmp_path):
    attribute_db = tmp_path / "attribute.db"
    x_db = tmp_path / "x-argument.db"
    command.upgrade(_config(f"sqlite+pysqlite:///{attribute_db}", x_url=f"sqlite+pysqlite:///{x_db}"), "0001_initial")
    assert x_db.exists() and not attribute_db.exists()


def test_offline_sql_is_refused_for_sqlite(tmp_path):
    cfg = _config(f"sqlite+pysqlite:///{tmp_path / 'offline.db'}", buffer=io.StringIO())
    with pytest.raises(RuntimeError, match="PostgreSQL only"):
        command.upgrade(cfg, "0001_initial:head", sql=True)


def _postgres_sql(direction: str) -> str:
    buffer = io.StringIO()
    cfg = _config("postgresql+psycopg://warden:placeholder@localhost/warden", buffer=buffer)
    if direction == "upgrade":
        command.upgrade(cfg, f"0001_initial:{HEAD}", sql=True)
    else:
        command.downgrade(cfg, f"{HEAD}:0001_initial", sql=True)
    return buffer.getvalue()


def test_postgres_upgrade_sql_converts_the_role_enum_and_installs_the_trigger():
    sql = _postgres_sql("upgrade")
    assert "ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(32) USING role::text" in sql
    assert "UPDATE users SET role = 'security_analyst' WHERE role = 'analyst'" in sql
    assert "UPDATE users SET role = 'read_only' WHERE role = 'viewer'" in sql
    assert "DROP TYPE IF EXISTS role" in sql
    assert "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events" in sql
    assert "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events" in sql
    assert "uq_policies_active_environment" in sql and "WHERE is_active = true" in sql
    # Offline scripts cannot hash-chain existing rows, so they refuse to run over unchained data.
    assert "must be hash-chained" in sql
    # Order matters: the enum is converted before values outside the v1 enum are written.
    assert sql.index("USING role::text") < sql.index("SET role = 'security_analyst'") < sql.index("DROP TYPE")
    assert "UPDATE scans SET environment = 'production' WHERE environment IS NULL" in sql
    assert "DROP CONSTRAINT uq_scan_pkg" in sql and "uq_scan_pkg_env" in sql


def test_postgres_downgrade_sql_restores_the_v1_enum_and_drops_the_trigger():
    sql = _postgres_sql("downgrade")
    assert "DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events" in sql
    assert "CREATE TYPE role AS ENUM ('admin', 'analyst', 'viewer')" in sql
    assert "ALTER TABLE users ALTER COLUMN role TYPE role USING role::role" in sql
    assert sql.index("SET role = 'analyst'") < sql.index("CREATE TYPE role")
