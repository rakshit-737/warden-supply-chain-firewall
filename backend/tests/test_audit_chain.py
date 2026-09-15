"""Tamper-evident audit trail: hash-chain construction, verification and tamper detection.

Service-level tests run on a throwaway SQLite database per test, so deliberately corrupting the
chain never affects the shared test database. Tampering is simulated with direct SQL writes
that bypass the application, which is exactly what the chain must expose (SQLite has no
append-only trigger; the PostgreSQL trigger is covered by the migration tests' generated SQL).
"""

from __future__ import annotations

import hashlib
import inspect
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import AuditEvent, Role, User
from app.db.session import get_db
from app.main import create_app
from app.services import audit
from tests.conftest import auth


# --------------------------------------------------------------------------- fixtures
@pytest.fixture()
def session_factory(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'audit.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, future=True)
    finally:
        engine.dispose()


@pytest.fixture()
def db(session_factory):
    with session_factory() as session:
        yield session


def _append(db, count: int) -> None:
    for i in range(count):
        audit.record(db, actor_id=None, action=f"test.event{i}", target_type="thing", target_id=str(i),
                     metadata={"i": i, "nested": {"k": [1, 2]}})
    db.commit()


def _tamper(session_factory, *statements: str) -> None:
    """A direct database write that bypasses the application."""
    with session_factory() as session:
        for statement in statements:
            session.execute(text(statement))
        session.commit()


# --------------------------------------------------------------------------- construction
def test_record_signature_is_backward_compatible():
    params = inspect.signature(audit.record).parameters
    assert list(params)[0] == "db"
    for name in ("actor_id", "action", "target_type", "target_id", "metadata"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
    for name in ("target_type", "target_id", "metadata"):
        assert params[name].default is None


def test_empty_chain_verifies(db):
    assert audit.verify_chain(db) == {
        "ok": True, "checked": 0, "first_broken_seq": None, "reason": None, "head_seq": None, "head_hash": None,
    }


def test_chain_links_every_event_to_its_predecessor(db):
    _append(db, 5)
    rows = db.execute(
        select(AuditEvent.seq, AuditEvent.prev_hash, AuditEvent.event_hash).order_by(AuditEvent.seq)
    ).all()
    assert [r.seq for r in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_hash == audit.GENESIS_HASH
    for previous, current in zip(rows, rows[1:]):
        assert current.prev_hash == previous.event_hash
    assert len({r.event_hash for r in rows}) == 5
    result = audit.verify_chain(db)
    assert result["ok"] is True and result["checked"] == 5
    assert result["head_seq"] == 5 and result["head_hash"] == rows[-1].event_hash


def test_event_hash_is_sha256_over_prev_hash_and_canonical_json(db, session_factory):
    user = User(id=uuid.uuid4(), email="chain@warden.io", password_hash="x", role=Role.auditor)
    db.add(user)
    db.commit()
    event = audit.record(db, actor_id=user.id, action="user.update", target_type="user", target_id=str(user.id),
                         metadata={"b": 2, "a": [1, "x"]})
    db.commit()

    with session_factory() as fresh:
        row = fresh.scalars(select(AuditEvent).where(AuditEvent.id == event.id)).one()
        created = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=timezone.utc)
        canonical = json.dumps(
            {
                "v": 1, "seq": 1, "id": str(row.id), "actor_id": str(user.id), "action": "user.update",
                "target_type": "user", "target_id": str(user.id), "metadata": {"a": [1, "x"], "b": 2},
                "request_id": None, "created_at": created.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        assert row.event_hash == hashlib.sha256((audit.GENESIS_HASH + canonical).encode("utf-8")).hexdigest()


def test_metadata_is_sanitised_before_hashing_and_storage(db, session_factory):
    audit.record(db, actor_id=None, action="auth.test", metadata={
        "password": "hunter2-hunter2",
        "note": "leaked AKIAIOSFODNN7EXAMPLE",
        "ansi": "\x1b[31mred",
        "when": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "ids": (uuid.UUID(int=1),),
    })
    db.commit()
    with session_factory() as fresh:
        stored = fresh.scalars(select(AuditEvent)).one().metadata_
        dumped = json.dumps(stored)
        assert stored["password"] == "[REDACTED]"
        assert "hunter2" not in dumped and "AKIAIOSFODNN7EXAMPLE" not in dumped and "\x1b" not in dumped
        assert stored["ids"] == [str(uuid.UUID(int=1))]
        assert audit.verify_chain(fresh)["ok"] is True  # the hash covers exactly what was stored


def test_oversized_and_control_character_fields_are_bounded(db):
    event = audit.record(db, actor_id=None, action="a" * 500, target_type="t" * 100, target_id="evil\x1b[2Jid" * 20)
    db.commit()
    assert len(event.action) <= 80 and len(event.target_type) <= 40 and len(event.target_id) <= 64
    assert "\x1b" not in event.target_id
    assert audit.verify_chain(db)["ok"] is True


def test_rolled_back_events_leave_no_gap(db):
    _append(db, 2)
    audit.record(db, actor_id=None, action="doomed")
    db.rollback()
    audit.record(db, actor_id=None, action="kept")
    db.commit()
    rows = db.execute(select(AuditEvent.seq, AuditEvent.action).order_by(AuditEvent.seq)).all()
    assert [(r.seq, r.action) for r in rows] == [(1, "test.event0"), (2, "test.event1"), (3, "kept")]
    assert audit.verify_chain(db)["ok"] is True


# --------------------------------------------------------------------------- tamper detection
@pytest.mark.parametrize("statement", [
    pytest.param("UPDATE audit_events SET metadata = '{\"i\": 999}' WHERE seq = 3", id="metadata"),
    pytest.param("UPDATE audit_events SET metadata = NULL WHERE seq = 3", id="metadata-nulled"),
    pytest.param("UPDATE audit_events SET action = 'test.benign' WHERE seq = 3", id="action"),
    pytest.param("UPDATE audit_events SET target_id = 'someone-else' WHERE seq = 3", id="target"),
    pytest.param("UPDATE audit_events SET request_id = 'forged' WHERE seq = 3", id="request-id"),
    pytest.param("UPDATE audit_events SET created_at = '2020-01-01 00:00:00.000000' WHERE seq = 3", id="timestamp"),
    pytest.param("UPDATE audit_events SET actor_id = '11111111-1111-1111-1111-111111111111' WHERE seq = 3",
                 id="actor"),
])
def test_modifying_any_hashed_field_is_detected(db, session_factory, statement):
    _append(db, 5)
    _tamper(session_factory, statement)
    result = audit.verify_chain(db)
    assert result["ok"] is False
    assert result["first_broken_seq"] == 3 and result["checked"] == 2 and result["head_seq"] == 2
    assert "event_hash mismatch" in result["reason"]


def test_deleting_an_event_breaks_the_sequence(db, session_factory):
    _append(db, 5)
    _tamper(session_factory, "DELETE FROM audit_events WHERE seq = 2")
    result = audit.verify_chain(db)
    assert result["ok"] is False and result["first_broken_seq"] == 3
    assert "sequence gap" in result["reason"]


def test_deleting_and_renumbering_is_caught_by_the_hash_links(db, session_factory):
    _append(db, 5)
    _tamper(
        session_factory,
        "DELETE FROM audit_events WHERE seq = 2",
        "UPDATE audit_events SET seq = 2 WHERE seq = 3",
        "UPDATE audit_events SET seq = 3 WHERE seq = 4",
        "UPDATE audit_events SET seq = 4 WHERE seq = 5",
    )
    result = audit.verify_chain(db)
    assert result["ok"] is False and result["first_broken_seq"] == 2
    assert "prev_hash" in result["reason"]


def test_reordering_events_is_detected(db, session_factory):
    _append(db, 4)
    _tamper(
        session_factory,
        "UPDATE audit_events SET seq = 1000 WHERE seq = 2",
        "UPDATE audit_events SET seq = 2 WHERE seq = 3",
        "UPDATE audit_events SET seq = 3 WHERE seq = 1000",
    )
    result = audit.verify_chain(db)
    assert result["ok"] is False and result["first_broken_seq"] == 2


def test_recomputing_only_the_modified_events_hash_breaks_the_next_link(db, session_factory):
    _append(db, 4)
    with session_factory() as attacker:
        row = attacker.scalars(select(AuditEvent).where(AuditEvent.seq == 2)).one()
        forged = {"i": "forged"}
        row.metadata_ = forged
        row.event_hash = audit.compute_event_hash(row.prev_hash, audit.canonical_event(
            seq=row.seq, event_id=row.id, actor_id=row.actor_id, action=row.action, target_type=row.target_type,
            target_id=row.target_id, metadata=forged, request_id=row.request_id, created_at=row.created_at,
        ))
        attacker.commit()
    result = audit.verify_chain(db)
    assert result["ok"] is False and result["first_broken_seq"] == 3 and result["checked"] == 2
    assert "prev_hash" in result["reason"]


def test_forged_appended_event_is_detected(db, session_factory):
    _append(db, 3)
    head_seq, head_hash = audit.chain_head(db)
    with session_factory() as attacker:
        attacker.add(AuditEvent(
            id=uuid.uuid4(), actor_id=None, action="user.login", metadata_={}, created_at=datetime.now(timezone.utc),
            seq=head_seq + 1, prev_hash=head_hash, event_hash="e" * 64,
        ))
        attacker.commit()
    result = audit.verify_chain(db)
    assert result["ok"] is False and result["first_broken_seq"] == 4 and result["checked"] == 3
    assert "event_hash mismatch" in result["reason"]


def test_verification_pages_through_long_chains(db, session_factory):
    _append(db, 7)
    assert audit.verify_chain(db, batch_size=2) == {**audit.verify_chain(db), "checked": 7}
    _tamper(session_factory, "UPDATE audit_events SET action = 'x' WHERE seq = 6")
    result = audit.verify_chain(db, batch_size=2)
    assert result["ok"] is False and result["first_broken_seq"] == 6 and result["checked"] == 5


# --------------------------------------------------------------------------- concurrency
class _RecordingSession:
    def __init__(self, dialect: str) -> None:
        self.statements: list[tuple[str, object]] = []
        self._bind = SimpleNamespace(dialect=SimpleNamespace(name=dialect))

    def get_bind(self):
        return self._bind

    def execute(self, statement, params=None):
        self.statements.append((str(statement), params))


def test_postgres_appends_take_a_transaction_scoped_advisory_lock():
    session = _RecordingSession("postgresql")
    audit._lock_chain(session)
    [(sql, params)] = session.statements
    assert "pg_advisory_xact_lock" in sql
    assert params == {"key": audit.ADVISORY_LOCK_KEY}
    assert -(2**63) <= audit.ADVISORY_LOCK_KEY < 2**63  # must fit PostgreSQL bigint


def test_sqlite_appends_issue_no_advisory_lock():
    session = _RecordingSession("sqlite")
    audit._lock_chain(session)
    assert session.statements == []


def test_record_locks_before_reading_the_chain_head(db, monkeypatch):
    order: list[str] = []
    real_head = audit.chain_head

    def head(session):
        order.append("head")
        return real_head(session)

    monkeypatch.setattr(audit, "_lock_chain", lambda session: order.append("lock"))
    monkeypatch.setattr(audit, "chain_head", head)
    audit.record(db, actor_id=None, action="ordered")
    db.commit()
    assert order == ["lock", "head"]


# --------------------------------------------------------------------------- API
def test_verify_endpoint_reports_the_live_chain_intact(client, admin_token):
    resp = client.get("/api/v1/audit/verify", headers=auth(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True and body["first_broken_seq"] is None and body["reason"] is None
    assert body["checked"] >= 1 and body["head_seq"] == body["checked"]
    assert body["verified_at"]


@pytest.fixture()
def isolated_api(session_factory):
    def _get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as test_client:
        yield test_client


def test_verify_endpoint_detects_tampering(isolated_api, session_factory):
    with session_factory() as session:
        auditor = User(id=uuid.uuid4(), email="auditor@warden.io", password_hash="x", role=Role.auditor)
        session.add(auditor)
        session.commit()
        headers = auth(create_access_token(subject=str(auditor.id), role="auditor"))
        _append(session, 4)

    intact = isolated_api.get("/api/v1/audit/verify", headers=headers).json()
    assert intact["ok"] is True and intact["checked"] == 4

    _tamper(session_factory, "UPDATE audit_events SET action = 'nothing.to.see' WHERE seq = 2")
    broken = isolated_api.get("/api/v1/audit/verify", headers=headers).json()
    assert broken["ok"] is False and broken["first_broken_seq"] == 2 and broken["checked"] == 1

    listing = isolated_api.get("/api/v1/audit", headers=headers).json()
    assert [e["seq"] for e in listing["items"]] == [4, 3, 2, 1]
    assert all(len(e["event_hash"]) == 64 for e in listing["items"])
