"""Security events: vocabulary, the publish bus and the ``/events`` API.

Bus tests use a throwaway SQLite database and a fake stream client (no Redis): they check that
details are sanitised, that the stream only ever sees committed events, and that a failing or
missing stream never breaks the committing request. API tests cover every filter, bounded
pagination and idempotent, audited acknowledgement.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker

from app.core import cache as cache_module
from app.core import metrics
from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.models import AuditEvent, Project, Role, SecurityEvent, User
from app.db.session import SessionLocal
from app.events import bus
from app.events.types import EVENT_SEVERITIES, EventType, coerce_severity, max_severity
from tests.conftest import auth

EVENTS = "/api/v1/events"

# Literal transcription of SPEC section 7.
SPEC_EVENT_TYPES = (
    "PACKAGE_SCANNED", "PACKAGE_BLOCKED", "RISK_INCREASED", "RISK_DECREASED", "VULNERABILITY_DISCOVERED",
    "KEV_ADDED", "BEHAVIOR_DRIFT_DETECTED", "MAINTAINER_CHANGED", "PROVENANCE_CHANGED", "NEW_RELEASE_DETECTED",
    "POLICY_VIOLATION", "EXCEPTION_CREATED", "EXCEPTION_APPROVED", "EXCEPTION_REJECTED", "EXCEPTION_REVOKED",
    "EXCEPTION_EXPIRED", "SBOM_GENERATED", "PROJECT_SCANNED", "CONTAINER_SCANNED", "DEPENDENCY_GRAPH_CHANGED",
    "MONITOR_ERROR",
)


# =========================================================================== vocabulary
def test_event_types_match_the_spec():
    assert tuple(m.name for m in EventType) == SPEC_EVENT_TYPES
    for member in EventType:
        assert member.value == member.name.lower() and len(member.value) <= 40  # fits security_events.type


@pytest.mark.parametrize("raw", ["PACKAGE_BLOCKED", "package_blocked", " Package_Blocked "])
def test_event_type_accepts_both_spellings(raw):
    assert EventType(raw) is EventType.PACKAGE_BLOCKED


@pytest.mark.parametrize("raw", ["package blocked", "", "PACKAGE_BLOCKED;DROP", 5])
def test_unknown_event_types_are_rejected(raw):
    with pytest.raises(ValueError):
        EventType(raw)


def test_severity_helpers():
    assert EVENT_SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert coerce_severity(" HIGH ") == "high"
    assert max_severity("low", "critical", "medium") == "critical"
    with pytest.raises(ValueError):
        coerce_severity("severe")


# =========================================================================== bus
class _FakeStream:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, dict, int | None]] = []

    def xadd(self, stream, fields, maxlen=None):
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.calls.append((stream, dict(fields), maxlen))
        return True


@pytest.fixture()
def session_factory(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'events.db'}")
    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, future=True)
    finally:
        engine.dispose()


@pytest.fixture()
def db(session_factory):
    with session_factory() as session:
        yield session


@pytest.fixture()
def stream(monkeypatch):
    fake = _FakeStream()
    monkeypatch.setattr(cache_module, "cache", fake)
    return fake


# Synthetic credential-shaped values, assembled at runtime so repository secret scanners
# (and GitHub push protection) never see a literal token in the history.
_FAKE_STRIPE_KEY = "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz"


def test_publish_sanitises_attacker_controlled_fields(db, session_factory, stream):
    scan_ref = uuid.uuid4()
    row = bus.publish(
        db, EventType.POLICY_VIOLATION, "HIGH", "\x1b[2Jpwned " + "T" * 500,
        package="Evil_Package.Name", version="1.0‮",
        details={
            "password": "hunter2-plaintext",
            "nested": {"api_key": _FAKE_STRIPE_KEY},
            "note": "found AKIAIOSFODNN7EXAMPLE in setup.py",
            "ansi": "\x1b[31mred",
            "bidi": "abc‮def",
            "items": list(range(100)),
            "scan": scan_ref,
        },
    )
    db.commit()
    with session_factory() as fresh:
        stored = fresh.get(SecurityEvent, row.id)
        dumped = json.dumps(stored.details)
        assert stored.severity == "high" and stored.type == "policy_violation"
        assert stored.package == "evil-package-name"
        assert "\x1b" not in stored.title and len(stored.title) <= 200
        assert "‮" not in stored.version
        assert stored.details["password"] == "[REDACTED]"
        # The exact marker format belongs to app.core.redaction; the contract is "no secret".
        assert "REDACTED" in stored.details["nested"]["api_key"]
        for raw in ("hunter2", _FAKE_STRIPE_KEY[:8], "AKIAIOSFODNN7EXAMPLE", "\x1b", "‮"):
            assert raw not in dumped
        assert len(stored.details["items"]) == 25 and stored.details["items"][-1] == "<76 more>"
        assert stored.details["scan"] == str(scan_ref)
        assert stored.acknowledged is False
    [(_, fields, _)] = stream.calls
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(fields) and "\x1b" not in json.dumps(fields)


def test_invalid_package_names_are_stored_sanitised_not_normalised(db):
    row = bus.publish(db, EventType.MONITOR_ERROR, "low", "odd name", package="not a/valid\x07name")
    assert row.package == "not a/valid\\x07name"


@pytest.mark.parametrize("kwargs", [
    {"type": "package_exploded", "severity": "info"},
    {"type": EventType.KEV_ADDED, "severity": "catastrophic"},
    {"type": EventType.KEV_ADDED, "severity": "info", "scan_id": "not-a-uuid"},
])
def test_publish_rejects_invalid_arguments_without_adding_rows(db, kwargs):
    kwargs = dict(kwargs)
    with pytest.raises(ValueError):
        bus.publish(db, kwargs.pop("type"), kwargs.pop("severity"), "title", **kwargs)
    assert not db.new


def test_events_are_streamed_only_after_commit(db, stream):
    row = bus.publish(db, EventType.KEV_ADDED, "critical", "CVE added to KEV", package="Django",
                      version="4.2.0", scan_id=str(uuid.uuid4()), details={"cve": "CVE-2099-0001"})
    db.flush()
    assert stream.calls == []
    db.commit()
    [(stream_key, fields, maxlen)] = stream.calls
    assert stream_key == settings.EVENT_STREAM_KEY and maxlen == settings.EVENT_STREAM_MAXLEN
    assert all(isinstance(v, str) for v in fields.values())
    assert fields["id"] == str(row.id) and fields["type"] == "kev_added" and fields["package"] == "django"
    assert fields["project_id"] == ""
    assert json.loads(fields["details"]) == {"cve": "CVE-2099-0001"}
    db.commit()  # a later empty commit must not re-stream the event
    assert len(stream.calls) == 1


def test_rolled_back_events_are_never_streamed(db, session_factory, stream):
    row = bus.publish(db, EventType.RISK_INCREASED, "high", "doomed", package="doomed-pkg")
    db.rollback()
    db.commit()
    assert stream.calls == []
    with session_factory() as fresh:
        assert fresh.get(SecurityEvent, row.id) is None


def test_closing_a_session_discards_pending_stream_payloads(session_factory, stream):
    session = session_factory()
    bus.publish(session, EventType.MONITOR_ERROR, "low", "never committed")
    session.close()
    session.commit()
    assert stream.calls == []


def test_several_events_in_one_transaction_are_streamed_together(db, stream):
    for i in range(3):
        bus.publish(db, EventType.NEW_RELEASE_DETECTED, "info", f"release {i}", package="batch-pkg")
    db.commit()
    assert [c[1]["title"] for c in stream.calls] == ["release 0", "release 1", "release 2"]


def test_stream_failure_never_breaks_the_committing_request(db, session_factory, monkeypatch):
    monkeypatch.setattr(cache_module, "cache", _FakeStream(fail=True))
    row = bus.publish(db, EventType.PACKAGE_BLOCKED, "critical", "blocked", package="evil-pkg")
    db.commit()  # must not raise
    with session_factory() as fresh:
        assert fresh.get(SecurityEvent, row.id).type == "package_blocked"
    assert bus.push_to_stream([{"id": "1"}, {"id": "2"}]) == 0


def test_cache_without_stream_support_is_tolerated(db, monkeypatch):
    monkeypatch.setattr(cache_module, "cache", object())
    bus.publish(db, EventType.SBOM_GENERATED, "info", "no xadd available")
    db.commit()
    assert bus.push_to_stream([{"id": "x"}]) == 0


def test_undelivered_stream_payloads_are_not_counted(monkeypatch):
    class _NoRedis:
        def xadd(self, stream, fields, maxlen=None):
            return False  # CacheClient contract when Redis is not configured

    monkeypatch.setattr(cache_module, "cache", _NoRedis())
    assert bus.push_to_stream([{"id": "1"}]) == 0


def test_metrics_count_committed_events_only(db, stream, monkeypatch):
    seen: list[tuple[str, str]] = []
    monkeypatch.setattr(metrics, "inc_event", lambda event_type, severity: seen.append((event_type, severity)))
    bus.publish(db, EventType.MONITOR_ERROR, "medium", "rolled back")
    db.rollback()
    bus.publish(db, EventType.KEV_ADDED, "critical", "kept")
    db.commit()
    assert seen == [("kev_added", "critical")]


# =========================================================================== API
@lru_cache(maxsize=1)
def _password_hash() -> str:
    return hash_password("Events-Api-Passw0rd!")


def _principal(role: Role) -> tuple[uuid.UUID, dict[str, str]]:
    with SessionLocal() as session:
        user = User(id=uuid.uuid4(), email=f"events-{role.value}-{uuid.uuid4().hex[:10]}@warden.io",
                    password_hash=_password_hash(), role=role)
        session.add(user)
        session.commit()
        return user.id, auth(create_access_token(subject=str(user.id), role=role.value))


def _publish(event_type: EventType, severity: str, **kwargs) -> uuid.UUID:
    with SessionLocal() as session:
        row = bus.publish(session, event_type, severity, kwargs.pop("title", "api test event"), **kwargs)
        session.commit()
        return row.id


def _pkg() -> str:
    return f"events-api-{uuid.uuid4().hex[:10]}"


def test_list_filters_by_type_severity_package_and_acknowledgement(client):
    _, reader = _principal(Role.read_only)
    pkg = _pkg()
    scanned = str(_publish(EventType.PACKAGE_SCANNED, "info", package=pkg))
    blocked = str(_publish(EventType.PACKAGE_BLOCKED, "critical", package=pkg))
    _publish(EventType.PACKAGE_BLOCKED, "critical", package=pkg + "-other")

    def ids(**params) -> set[str]:
        resp = client.get(EVENTS, headers=reader, params={"package": pkg, **params})
        assert resp.status_code == 200, resp.text
        return {item["id"] for item in resp.json()["items"]}

    assert ids() == {scanned, blocked}
    assert ids(type="package_blocked") == {blocked}
    assert ids(type="PACKAGE_BLOCKED") == {blocked}
    assert ids(severity="info") == {scanned}
    assert ids(acknowledged="false") == {scanned, blocked}
    assert ids(acknowledged="true") == set()
    assert ids(package=pkg.upper().replace("-", "_")) == {scanned, blocked}  # PEP 503 normalised


def test_since_filter_honours_offsets_and_results_are_newest_first(client):
    _, reader = _principal(Role.auditor)
    pkg = _pkg()
    old = _publish(EventType.RISK_DECREASED, "low", package=pkg)
    new = _publish(EventType.RISK_INCREASED, "high", package=pkg)
    with SessionLocal() as session:
        session.execute(update(SecurityEvent).where(SecurityEvent.id == old)
                        .values(created_at=datetime.now(timezone.utc) - timedelta(days=3)))
        session.commit()

    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    ist = timezone(timedelta(hours=5, minutes=30))
    for since in (cutoff.isoformat(), cutoff.astimezone(ist).isoformat()):
        items = client.get(EVENTS, headers=reader, params={"package": pkg, "since": since}).json()["items"]
        assert [i["id"] for i in items] == [str(new)]
    items = client.get(EVENTS, headers=reader, params={"package": pkg}).json()["items"]
    assert [i["id"] for i in items] == [str(new), str(old)]


def test_project_filter(client):
    _, reader = _principal(Role.developer)
    with SessionLocal() as session:
        project = Project(id=uuid.uuid4(), name=f"events-project-{uuid.uuid4().hex[:8]}")
        session.add(project)
        session.commit()
        project_id = project.id
    in_project = _publish(EventType.PROJECT_SCANNED, "low", project_id=project_id)
    _publish(EventType.PROJECT_SCANNED, "low")
    items = client.get(EVENTS, headers=reader, params={"project_id": str(project_id)}).json()["items"]
    assert [i["id"] for i in items] == [str(in_project)]
    assert items[0]["project_id"] == str(project_id)


def test_pagination_is_bounded_and_consistent(client):
    _, reader = _principal(Role.read_only)
    pkg = _pkg()
    published = {str(_publish(EventType.VULNERABILITY_DISCOVERED, "medium", package=pkg)) for _ in range(3)}
    first = client.get(EVENTS, headers=reader, params={"package": pkg, "limit": 2}).json()
    second = client.get(EVENTS, headers=reader, params={"package": pkg, "limit": 2, "offset": 2}).json()
    assert first["total"] == second["total"] == 3 and first["limit"] == 2
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert {i["id"] for i in first["items"] + second["items"]} == published


@pytest.mark.parametrize("params", [
    {"limit": 0}, {"limit": 201}, {"offset": -1}, {"offset": 1_000_001}, {"type": "not_an_event"},
    {"severity": "severe"}, {"project_id": "nope"}, {"since": "yesterday"}, {"acknowledged": "maybe"},
    {"package": "x" * 215},
])
def test_list_rejects_invalid_or_unbounded_parameters(client, params):
    _, reader = _principal(Role.read_only)
    assert client.get(EVENTS, headers=reader, params=params).status_code == 422


def test_acknowledgement_is_attributed_audited_and_idempotent(client):
    analyst_id, analyst = _principal(Role.security_analyst)
    _, admin = _principal(Role.admin)
    pkg = _pkg()
    event_id = _publish(EventType.VULNERABILITY_DISCOVERED, "high", package=pkg)

    first = client.post(f"{EVENTS}/{event_id}/ack", headers=analyst)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["acknowledged"] is True and body["acknowledged_by"] == str(analyst_id)
    assert body["acknowledged_at"]

    again = client.post(f"{EVENTS}/{event_id}/ack", headers=admin)
    assert again.status_code == 200
    assert again.json()["acknowledged_by"] == str(analyst_id)  # original acknowledger kept
    assert again.json()["acknowledged_at"] == body["acknowledged_at"]

    with SessionLocal() as session:
        actions = session.scalars(select(AuditEvent.action).where(AuditEvent.target_id == str(event_id))).all()
    assert actions == ["event.ack"]
    listed = client.get(EVENTS, headers=analyst, params={"package": pkg, "acknowledged": "true"}).json()
    assert [i["id"] for i in listed["items"]] == [str(event_id)]


def test_acknowledging_unknown_or_malformed_ids(client):
    _, analyst = _principal(Role.security_analyst)
    assert client.post(f"{EVENTS}/{uuid.uuid4()}/ack", headers=analyst).status_code == 404
    assert client.post(f"{EVENTS}/not-a-uuid/ack", headers=analyst).status_code == 422
