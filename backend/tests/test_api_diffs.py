"""Release diff API: persistence, events, audit and authorisation (fake orchestrator, no network)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.analysis.orchestrator import AnalysisResult
from app.api.routers import diffs as diffs_router
from app.core.permissions import Role
from app.core.security import create_access_token
from app.db.models import AuditEvent, ReleaseDiff, SecurityEvent, User
from app.db.session import SessionLocal
from tests.conftest import auth


def _inventory(version: str, *extra: tuple[str, str, bool]) -> list[dict]:
    files = [("setup.py", "s1", False), ("demo/__init__.py", "i1", False), *extra]
    return [{"path": f"{version}/{p}", "size": 1, "sha256": h, "kind": "file", "executable": x}
            for p, h, x in files]


class _FakeOrchestrator:
    def __init__(self):
        self.calls = []

    def analyze(self, ecosystem, name, version, options=None):
        self.calls.append((name, version))
        if name == "drifter" and version == "2.0.0":
            signals = [{"code": "NETWORK_EGRESS", "severity": "high", "message": "posts to a host",
                        "location": {"file": "demo/__init__.py", "line": 4}}]
            return AnalysisResult(
                ecosystem, name, version, 70, 10, 70, "high", {}, signals, "2.0.0", 5, True,
                capabilities=["network"],
                package_intel={"maintainers": {"maintainers": [{"username": "alice"}, {"username": "eve"}]}},
                file_inventory=_inventory("drifter-2.0.0", ("demo/_x.so", "b1", True)),
            )
        return AnalysisResult(
            ecosystem, name, version, 5, 1, 5, "info", {}, [], "2.0.0", 5, True,
            package_intel={"maintainers": {"maintainers": [{"username": "alice"}]}},
            file_inventory=_inventory(f"{name}-{version}"),
        )


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    orchestrator = _FakeOrchestrator()
    monkeypatch.setattr(diffs_router, "_orchestrator", orchestrator)
    return orchestrator


def _token(role: Role) -> str:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"diff-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                    password_hash="unused", role=role)
        db.add(user)
        db.commit()
        return create_access_token(subject=str(user.id), role=role.value)


def test_escalated_diff_is_stored_with_events_and_audit(client, admin_token):
    resp = client.post("/api/v1/diffs", headers=auth(admin_token),
                       json={"name": "drifter", "from_version": "1.0.0", "to_version": "2.0.0"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["drift_detected"] is True and body["drift_score"] == 65
    assert body["summary"]["verdict"] == "escalated"
    assert body["summary"]["files"]["new_executable_binaries"] == ["demo/_x.so"]
    assert body["findings"][0]["code"] == "NETWORK_EGRESS"

    with SessionLocal() as db:
        types = set(db.scalars(select(SecurityEvent.type).where(SecurityEvent.package == "drifter")))
        assert {"behavior_drift_detected", "maintainer_changed"} <= types
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "diff.create",
                                                  AuditEvent.target_id == "drifter 1.0.0 -> 2.0.0"))

    listed = client.get("/api/v1/diffs?drift_only=true&package=drifter", headers=auth(admin_token)).json()
    assert listed["total"] == 1 and listed["items"][0]["id"] == body["id"]
    detail = client.get(f"/api/v1/diffs/{body['id']}", headers=auth(admin_token))
    assert detail.status_code == 200 and detail.json()["summary"]["to_version"] == "2.0.0"


def test_repeating_a_diff_updates_the_same_row(client, admin_token):
    payload = {"name": "steady", "from_version": "1.0.0", "to_version": "1.1.0"}
    first = client.post("/api/v1/diffs", headers=auth(admin_token), json=payload).json()
    second = client.post("/api/v1/diffs", headers=auth(admin_token), json=payload).json()
    assert first["id"] == second["id"] and second["drift_detected"] is False
    with SessionLocal() as db:
        assert len(db.scalars(select(ReleaseDiff).where(ReleaseDiff.package == "steady")).all()) == 1
        assert not db.scalars(select(SecurityEvent).where(SecurityEvent.package == "steady")).all()


@pytest.mark.parametrize("payload", [
    {"name": "x", "from_version": "1.0", "to_version": "1.0"},
    {"name": "../etc", "from_version": "1.0", "to_version": "2.0"},
    {"name": "x", "from_version": "1.0; rm", "to_version": "2.0"},
    {"ecosystem": "npm", "name": "x", "from_version": "1.0", "to_version": "2.0"},
])
def test_invalid_requests_are_rejected_before_analysis(client, admin_token, fake, payload):
    assert client.post("/api/v1/diffs", headers=auth(admin_token), json=payload).status_code == 422
    assert fake.calls == []


def test_unknown_diff_is_404(client, admin_token):
    assert client.get(f"/api/v1/diffs/{uuid.uuid4()}", headers=auth(admin_token)).status_code == 404


@pytest.mark.parametrize(("role", "create", "read"), [
    (Role.admin, 201, 200), (Role.security_analyst, 201, 200), (Role.developer, 201, 200),
    (Role.auditor, 403, 200), (Role.read_only, 403, 200),
])
def test_role_matrix(client, role, create, read):
    token = _token(role)
    payload = {"name": f"rbac-{role.value.replace('_', '-')}", "from_version": "1.0.0", "to_version": "1.0.1"}
    assert client.post("/api/v1/diffs", headers=auth(token), json=payload).status_code == create
    assert client.get("/api/v1/diffs", headers=auth(token)).status_code == read


def test_anonymous_requests_are_rejected(client):
    assert client.get("/api/v1/diffs").status_code == 401
    assert client.post("/api/v1/diffs", json={"name": "x", "from_version": "1", "to_version": "2"}).status_code == 401
