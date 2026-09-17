"""Continuous monitoring: checks, drift events, failure backoff, claiming, worker heartbeat and API."""

from __future__ import annotations

import random
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.analysis.orchestrator import AnalysisResult
from app.core.config import settings
from app.core.permissions import Role
from app.core.security import create_access_token
from app.db.models import AuditEvent, MonitoredPackage, ReleaseDiff, SecurityEvent, User
from app.db.session import SessionLocal
from app.monitoring import service
from app.workers import monitor as worker
from tests.conftest import auth

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def aware(value: datetime) -> datetime:
    """SQLite returns naive UTC datetimes after a reload."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def result(name: str, version: str, *, risk: int = 5, caps=(), maintainers=("alice",)) -> AnalysisResult:
    return AnalysisResult(
        "pypi", name, version, risk, 0, risk, "high" if risk >= 60 else "info", {}, [], "2.0.0", 1, False,
        capabilities=list(caps),
        package_intel={"maintainers": {"maintainers": [{"username": m} for m in maintainers]}},
    )


class Registry:
    def __init__(self, name: str):
        self.name = name
        self.latest = "1.0.0"
        self.results = {"1.0.0": result(name, "1.0.0")}
        self.fail = False
        self.analyzed: list[str] = []

    def latest_version(self, ecosystem, name):
        if self.fail:
            raise ConnectionError("registry unreachable")
        return self.latest

    def analyze(self, ecosystem, name, version):
        self.analyzed.append(version)
        return self.results[version]


def new_row(db, **kwargs) -> MonitoredPackage:
    row = MonitoredPackage(id=uuid.uuid4(), ecosystem="pypi", name=f"mon-{uuid.uuid4().hex[:10]}",
                           poll_interval_seconds=3600, enabled=True, **kwargs)
    db.add(row)
    db.commit()
    return row


def check(db, row, registry, when=NOW):
    return service.check_package(db, row, now=when, latest_version=registry.latest_version,
                                 analyze=registry.analyze, rng=random.Random(1))


def events(db, name):
    return [e.type for e in db.scalars(select(SecurityEvent).where(SecurityEvent.package == name)
                                       .order_by(SecurityEvent.created_at))]


def test_first_check_records_a_baseline_without_events():
    with SessionLocal() as db:
        row = new_row(db)
        registry = Registry(row.name)
        outcome = check(db, row, registry)
        assert outcome.status == "baseline" and outcome.diff_id is None
        assert row.latest_seen_version == "1.0.0" and row.snapshot["risk_score"] == 5
        assert events(db, row.name) == []
        assert aware(row.next_check_at) >= NOW + timedelta(seconds=3600)
        assert check(db, row, registry, NOW + timedelta(hours=2)).status == "unchanged"
        assert registry.analyzed == ["1.0.0"]


def test_new_risky_release_publishes_drift_risk_and_maintainer_events():
    with SessionLocal() as db:
        row = new_row(db)
        registry = Registry(row.name)
        check(db, row, registry)
        registry.latest = "1.1.0"
        registry.results["1.1.0"] = result(row.name, "1.1.0", risk=75, caps=["network"], maintainers=("alice", "eve"))
        outcome = check(db, row, registry, NOW + timedelta(hours=2))
        assert outcome.status == "new_release" and outcome.diff_id
        assert set(events(db, row.name)) == {"new_release_detected", "behavior_drift_detected", "risk_increased",
                                             "maintainer_changed"}
        diff = db.get(ReleaseDiff, outcome.diff_id)
        assert diff.drift_detected and diff.old_version == "1.0.0" and diff.new_version == "1.1.0"
        assert row.last_risk_score == 75 and row.latest_seen_version == "1.1.0"


def test_approved_version_is_the_baseline():
    with SessionLocal() as db:
        row = new_row(db, approved_version="0.9.0")
        registry = Registry(row.name)
        registry.results["0.9.0"] = result(row.name, "0.9.0", risk=80)
        check(db, row, registry)
        registry.latest = "1.1.0"
        registry.results["1.1.0"] = result(row.name, "1.1.0", risk=20)
        outcome = check(db, row, registry, NOW + timedelta(hours=2))
        diff = db.get(ReleaseDiff, outcome.diff_id)
        assert diff.old_version == "0.9.0"
        assert "risk_decreased" in events(db, row.name)


def test_approved_release_is_not_diffed_against_itself():
    with SessionLocal() as db:
        row = new_row(db, approved_version="1.1.0")
        registry = Registry(row.name)
        check(db, row, registry)
        registry.latest = "1.1.0"
        registry.results["1.1.0"] = result(row.name, "1.1.0")
        outcome = check(db, row, registry, NOW + timedelta(hours=2))
        assert outcome.diff_id is None and events(db, row.name) == ["new_release_detected"]


def test_failures_back_off_and_publish_errors_sparingly():
    with SessionLocal() as db:
        row = new_row(db)
        registry = Registry(row.name)
        registry.fail = True
        delays = []
        for i in range(6):
            when = NOW + timedelta(hours=i)
            outcome = check(db, row, registry, when)
            assert outcome.status == "error" and "ConnectionError" in outcome.detail
            delays.append((aware(row.next_check_at) - when).total_seconds())
        assert row.consecutive_failures == 6
        assert delays[0] < delays[1] < delays[2]
        assert max(delays) <= 3600 + settings.MONITOR_JITTER_SECONDS
        assert events(db, row.name).count("monitor_error") == 2  # failure 1 and failure 5
        registry.fail = False
        assert check(db, row, registry, NOW + timedelta(days=1)).status == "baseline"
        assert row.consecutive_failures == 0


def test_claim_leases_rows_so_they_are_not_checked_twice():
    with SessionLocal() as db:
        for existing in db.scalars(select(MonitoredPackage)):
            existing.enabled = False
        db.commit()
        due = new_row(db)
        new_row(db, next_check_at=NOW + timedelta(hours=5))
        disabled = new_row(db)
        disabled.enabled = False
        db.commit()
        claimed = service.claim_due(db, NOW, 10)
        assert claimed == [due.id]
        assert service.claim_due(db, NOW, 10) == []
        assert service.claim_due(db, NOW + timedelta(seconds=service.CLAIM_LEASE_SECONDS + 1), 10) == [due.id]


def test_run_due_checks_claimed_rows(monkeypatch):
    with SessionLocal() as db:
        for existing in db.scalars(select(MonitoredPackage)):
            existing.enabled = False
        db.commit()
        row = new_row(db)
        registry = Registry(row.name)
        outcomes = service.run_due(db, now=NOW, latest_version=registry.latest_version, analyze=registry.analyze)
        assert [o.status for o in outcomes] == ["baseline"]


def test_worker_refuses_to_start_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "MONITOR_ENABLED", False)
    assert worker.main(threading.Event(), max_cycles=1) == 2


def test_worker_cycle_touches_the_heartbeat_even_when_a_cycle_fails(monkeypatch, tmp_path):
    beat = tmp_path / "beat"
    monkeypatch.setenv("MONITOR_HEARTBEAT_FILE", str(beat))
    monkeypatch.setattr(settings, "MONITOR_ENABLED", True)

    def broken():
        raise RuntimeError("database down")

    monkeypatch.setattr(worker, "run_cycle", broken)
    assert worker.main(threading.Event(), max_cycles=1) == 0
    assert beat.exists()


def test_worker_stops_when_asked(monkeypatch, tmp_path):
    monkeypatch.setenv("MONITOR_HEARTBEAT_FILE", str(tmp_path / "beat"))
    monkeypatch.setattr(settings, "MONITOR_ENABLED", True)
    monkeypatch.setattr(worker, "run_cycle", lambda: 0)
    monkeypatch.setattr(worker, "IDLE_SECONDS", 0.05)
    stop = threading.Event()
    thread = threading.Thread(target=worker.main, args=(stop,))
    thread.start()
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()


# --------------------------------------------------------------------------- API
def _token(role: Role) -> str:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"mon-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                    password_hash="unused", role=role)
        db.add(user)
        db.commit()
        return create_access_token(subject=str(user.id), role=role.value)


def test_api_lifecycle(client, admin_token, monkeypatch):
    name = f"api-mon-{uuid.uuid4().hex[:8]}"
    registry = Registry(name)
    monkeypatch.setattr(service, "default_latest_version", registry.latest_version)
    monkeypatch.setattr(service.check_package, "__kwdefaults__",
                        {**service.check_package.__kwdefaults__, "latest_version": registry.latest_version,
                         "analyze": registry.analyze})
    created = client.post("/api/v1/monitoring/packages", headers=auth(admin_token),
                          json={"name": name, "approved_version": "1.0.0", "poll_interval_seconds": 600})
    assert created.status_code == 201, created.text
    pid = created.json()["id"]
    dup = client.post("/api/v1/monitoring/packages", headers=auth(admin_token), json={"name": name})
    assert dup.status_code == 409

    checked = client.post(f"/api/v1/monitoring/packages/{pid}/check", headers=auth(admin_token))
    assert checked.status_code == 200 and checked.json()["status"] == "baseline"
    detail = client.get(f"/api/v1/monitoring/packages/{pid}", headers=auth(admin_token)).json()
    assert detail["latest_seen_version"] == "1.0.0"

    patched = client.patch(f"/api/v1/monitoring/packages/{pid}", headers=auth(admin_token),
                           json={"enabled": False, "poll_interval_seconds": 900})
    assert patched.json()["enabled"] is False and patched.json()["poll_interval_seconds"] == 900
    assert client.patch(f"/api/v1/monitoring/packages/{pid}", headers=auth(admin_token),
                        json={"poll_interval_seconds": 5}).status_code == 422
    listed = client.get("/api/v1/monitoring/packages?limit=200", headers=auth(admin_token)).json()
    assert any(item["id"] == pid for item in listed["items"])

    assert client.delete(f"/api/v1/monitoring/packages/{pid}", headers=auth(admin_token)).status_code == 204
    assert client.get(f"/api/v1/monitoring/packages/{pid}", headers=auth(admin_token)).status_code == 404
    with SessionLocal() as db:
        actions = set(db.scalars(select(AuditEvent.action).where(AuditEvent.target_id == name)))
        assert {"monitor.create", "monitor.check", "monitor.update", "monitor.delete"} <= actions


@pytest.mark.parametrize("payload", [
    {"name": "../x"}, {"name": "ok", "approved_version": "1.0; rm"}, {"name": "ok", "ecosystem": "npm"},
    {"name": "ok", "poll_interval_seconds": 60}, {"name": "ok", "project_id": str(uuid.uuid4())},
])
def test_api_rejects_bad_watch_requests(client, admin_token, payload):
    assert client.post("/api/v1/monitoring/packages", headers=auth(admin_token), json=payload).status_code in (404, 422)


@pytest.mark.parametrize(("role", "write", "read"), [
    (Role.admin, 201, 200), (Role.security_analyst, 201, 200), (Role.developer, 403, 200),
    (Role.auditor, 403, 200), (Role.read_only, 403, 200),
])
def test_api_role_matrix(client, role, write, read):
    token = _token(role)
    body = {"name": f"rbac-mon-{uuid.uuid4().hex[:8]}"}
    assert client.post("/api/v1/monitoring/packages", headers=auth(token), json=body).status_code == write
    assert client.get("/api/v1/monitoring/packages", headers=auth(token)).status_code == read
