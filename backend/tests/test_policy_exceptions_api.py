"""Policy exception workflow API: validation, separation of duties, lifecycle and expiry.

An exception is a risk acceptance, so these tests are deliberately adversarial: self-approval by
every approver role, mass assignment of ``status`` / ``approved_by``, immortal or back-dated
expiry, non-overridable codes, decisions computed from stale reads, and control characters or
secrets in the justification. Storage and exposure only; applying exceptions during policy
evaluation is the policy engine's job (phase 2).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pytest
from packaging.specifiers import SpecifierSet
from sqlalchemy import select, update

from app.api.routers import policies as policies_router
from app.core.errors import ConflictError
from app.core.security import create_access_token, hash_password
from app.db.models import AuditEvent, ExceptionStatus, Policy, PolicyException, Role, SecurityEvent, User
from app.db.session import SessionLocal
from tests.conftest import auth

EXC = "/api/v1/policies/exceptions"
_MISSING = object()


# --------------------------------------------------------------------------- helpers
@lru_cache(maxsize=1)
def _password_hash() -> str:
    return hash_password("Exception-Api-Passw0rd!")


def _user(role: Role) -> tuple[uuid.UUID, dict[str, str]]:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"exc-{role.value}-{uuid.uuid4().hex[:10]}@warden.io",
                    password_hash=_password_hash(), role=role)
        db.add(user)
        db.commit()
        return user.id, auth(create_access_token(subject=str(user.id), role=role.value))


def _expires(days: float = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _package() -> str:
    return f"Exc_Pkg.{uuid.uuid4().hex[:10]}"


def _normalised(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _payload(**overrides) -> dict:
    body = {
        "package": _package(),
        "codes": ["NETWORK_EGRESS"],
        "categories": ["capability"],
        "justification": "Build step fetches wheels from our internal mirror over HTTPS",
        "expires_at": _expires(),
    }
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not _MISSING}


def _request(client, headers, **overrides) -> dict:
    resp = client.post(EXC, headers=headers, json=_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _list(client, headers, **params) -> list[dict]:
    resp = client.get(EXC, headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()["items"]


def _expire_now(exception_id: str) -> None:
    with SessionLocal() as db:
        db.execute(
            update(PolicyException)
            .where(PolicyException.id == uuid.UUID(exception_id))
            .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        )
        db.commit()


def _audit_actions(target_id: str) -> list[str]:
    with SessionLocal() as db:
        return list(db.scalars(
            select(AuditEvent.action).where(AuditEvent.target_id == target_id).order_by(AuditEvent.seq)
        ))


def _event_types(package: str) -> set[str]:
    with SessionLocal() as db:
        return set(db.scalars(select(SecurityEvent.type).where(SecurityEvent.package == package)))


# --------------------------------------------------------------------------- request
def test_request_is_validated_normalised_and_recorded(client):
    dev_id, dev = _user(Role.developer)
    name = _package()
    body = _request(
        client, dev, package=f"  {name} ", codes=["network_egress", "NETWORK_EGRESS", "SUBPROCESS_EXEC"],
        version_spec=" <2.0, >=1.0 ", environment="Staging",
    )
    assert body["package"] == _normalised(name)
    assert body["status"] == "pending" and body["active"] is False
    assert body["requested_by"] == str(dev_id)
    assert body["approved_by"] is None and body["decided_at"] is None and body["revoked_by"] is None
    assert body["codes"] == ["NETWORK_EGRESS", "SUBPROCESS_EXEC"]
    assert body["version_spec"] == str(SpecifierSet("<2.0,>=1.0"))
    assert body["environment"] == "staging"
    assert _audit_actions(body["id"]) == ["exception.request"]
    assert _event_types(body["package"]) == {"exception_created"}


INVALID_REQUESTS = [
    pytest.param(lambda: {"expires_at": _expires(-1 / 24)}, id="expiry-in-the-past"),
    pytest.param(lambda: {"expires_at": _expires(366)}, id="expiry-beyond-365-days"),
    pytest.param(lambda: {"expires_at": _MISSING}, id="expiry-missing"),
    pytest.param(lambda: {"expires_at": "never"}, id="expiry-not-a-date"),
    pytest.param(lambda: {"justification": _MISSING}, id="justification-missing"),
    pytest.param(lambda: {"justification": "too short"}, id="justification-too-short"),
    pytest.param(lambda: {"justification": " " * 50}, id="justification-whitespace-only"),
    pytest.param(lambda: {"justification": "x" * 2001}, id="justification-too-long"),
    pytest.param(lambda: {"package": "../../etc/passwd"}, id="package-path-traversal"),
    pytest.param(lambda: {"package": "evil pkg; rm -rf /"}, id="package-shell-metacharacters"),
    pytest.param(lambda: {"package": ""}, id="package-empty"),
    pytest.param(lambda: {"package": _MISSING}, id="package-missing"),
    pytest.param(lambda: {"codes": ["IOC_MATCH"]}, id="non-overridable-ioc-match"),
    pytest.param(lambda: {"codes": ["hash_mismatch"]}, id="non-overridable-hash-mismatch"),
    pytest.param(lambda: {"codes": ["NETWORK EGRESS'; --"]}, id="code-injection"),
    pytest.param(lambda: {"categories": ["everything"]}, id="unknown-category"),
    pytest.param(lambda: {"version_spec": "latest please"}, id="invalid-version-spec"),
    pytest.param(lambda: {"environment": "prod"}, id="unknown-environment"),
    pytest.param(lambda: {"status": "approved"}, id="mass-assign-status"),
    pytest.param(lambda: {"approved_by": str(uuid.uuid4())}, id="mass-assign-approver"),
    pytest.param(lambda: {"requested_by": str(uuid.uuid4())}, id="mass-assign-requester"),
]


@pytest.mark.parametrize("overrides", INVALID_REQUESTS)
def test_invalid_requests_are_rejected(client, overrides):
    _, dev = _user(Role.developer)
    resp = client.post(EXC, headers=dev, json=_payload(**overrides()))
    assert resp.status_code == 422, resp.text


def test_expiry_boundary_and_timezone_normalisation(client):
    _, dev = _user(Role.developer)
    assert _request(client, dev, expires_at=_expires(364))["status"] == "pending"
    ist = timezone(timedelta(hours=5, minutes=30))
    local = (datetime.now(ist) + timedelta(days=10)).replace(microsecond=0)
    body = _request(client, dev, expires_at=local.isoformat())
    assert datetime.fromisoformat(body["expires_at"]) == local  # same instant, reported in UTC
    assert datetime.fromisoformat(body["expires_at"]).utcoffset() == timedelta(0)


def test_policy_scoped_request_checks_policy_and_environment(client):
    _, dev = _user(Role.developer)
    with SessionLocal() as db:
        policy = Policy(id=uuid.uuid4(), name="exception-scope", is_active=False, environment="staging")
        db.add(policy)
        db.commit()
        policy_id = str(policy.id)
    assert client.post(EXC, headers=dev, json=_payload(policy_id=str(uuid.uuid4()))).status_code == 404
    mismatch = client.post(EXC, headers=dev, json=_payload(policy_id=policy_id, environment="production"))
    assert mismatch.status_code == 422, mismatch.text
    assert _request(client, dev, policy_id=policy_id, environment="staging")["policy_id"] == policy_id


def test_justification_is_sanitised_before_storage(client):
    _, dev = _user(Role.developer)
    body = _request(client, dev, justification="Temporary waiver \x1b[2J‮ for key AKIAIOSFODNN7EXAMPLE in CI")
    text = body["justification"]
    assert "\x1b" not in text and "‮" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text and "REDACTED" in text


# --------------------------------------------------------------------------- separation of duties
@pytest.mark.parametrize("role", [Role.admin, Role.security_analyst], ids=lambda r: r.value)
def test_requester_can_never_decide_their_own_exception(client, role):
    _, headers = _user(role)
    body = _request(client, headers)
    for action in ("approve", "reject"):
        resp = client.post(f"{EXC}/{body['id']}/{action}", headers=headers)
        assert resp.status_code == 403, resp.text
        assert resp.json()["error"]["code"] == "separation_of_duties"
    [row] = _list(client, headers, package=body["package"])
    assert row["status"] == "pending" and row["approved_by"] is None
    assert _audit_actions(body["id"]) == ["exception.request"]


def test_developer_cannot_decide_or_revoke_someone_elses_request(client):
    _, requester = _user(Role.developer)
    _, other_developer = _user(Role.developer)
    body = _request(client, requester)
    for action in ("approve", "reject", "revoke"):
        resp = client.post(f"{EXC}/{body['id']}/{action}", headers=other_developer)
        assert resp.status_code == 403, resp.text
    assert _list(client, requester, package=body["package"])[0]["status"] == "pending"


def test_second_person_approval_lifecycle(client):
    dev_id, dev = _user(Role.developer)
    analyst_id, analyst = _user(Role.security_analyst)
    body = _request(client, dev)

    resp = client.post(f"{EXC}/{body['id']}/approve", headers=analyst, json={"comment": "Reviewed with platform"})
    assert resp.status_code == 200, resp.text
    approved = resp.json()
    assert approved["status"] == "approved" and approved["active"] is True
    assert approved["approved_by"] == str(analyst_id) and approved["requested_by"] == str(dev_id)
    assert approved["decided_at"] is not None
    assert _audit_actions(body["id"]) == ["exception.request", "exception.approve"]
    assert _event_types(body["package"]) == {"exception_created", "exception_approved"}

    # Decisions are final: no second approval and no flip to rejected.
    assert client.post(f"{EXC}/{body['id']}/approve", headers=analyst).status_code == 409
    _, admin = _user(Role.admin)
    assert client.post(f"{EXC}/{body['id']}/reject", headers=admin).status_code == 409


def test_rejection_is_terminal_and_records_the_decider(client):
    _, dev = _user(Role.developer)
    admin_id, admin = _user(Role.admin)
    body = _request(client, dev)
    rejected = client.post(f"{EXC}/{body['id']}/reject", headers=admin)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected" and rejected.json()["active"] is False
    assert rejected.json()["approved_by"] == str(admin_id)
    assert client.post(f"{EXC}/{body['id']}/approve", headers=admin).status_code == 409
    assert client.post(f"{EXC}/{body['id']}/revoke", headers=admin).status_code == 409
    assert "exception_rejected" in _event_types(body["package"])


def test_transition_body_rejects_unknown_fields(client):
    _, dev = _user(Role.developer)
    _, analyst = _user(Role.security_analyst)
    body = _request(client, dev)
    resp = client.post(f"{EXC}/{body['id']}/approve", headers=analyst, json={"status": "approved", "approved_by": "x"})
    assert resp.status_code == 422
    assert _list(client, dev, package=body["package"])[0]["status"] == "pending"


# --------------------------------------------------------------------------- revoke
def test_requester_may_withdraw_and_approver_may_revoke(client):
    dev_id, dev = _user(Role.developer)
    analyst_id, analyst = _user(Role.security_analyst)

    pending = _request(client, dev)
    withdrawn = client.post(f"{EXC}/{pending['id']}/revoke", headers=dev, json={"comment": "no longer needed"})
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["status"] == "revoked" and withdrawn.json()["revoked_by"] == str(dev_id)

    approved = _request(client, dev)
    assert client.post(f"{EXC}/{approved['id']}/approve", headers=analyst).status_code == 200
    revoked = client.post(f"{EXC}/{approved['id']}/revoke", headers=analyst)
    assert revoked.status_code == 200, revoked.text
    out = revoked.json()
    assert out["status"] == "revoked" and out["active"] is False
    assert out["approved_by"] == str(analyst_id) and out["revoked_at"] is not None  # approval history kept
    assert client.post(f"{EXC}/{approved['id']}/revoke", headers=analyst).status_code == 409
    assert _audit_actions(approved["id"]) == ["exception.request", "exception.approve", "exception.revoke"]
    assert "exception_revoked" in _event_types(approved["package"])


# --------------------------------------------------------------------------- expiry
def test_expired_exceptions_read_as_expired_and_cannot_change(client):
    _, dev = _user(Role.developer)
    _, analyst = _user(Role.security_analyst)
    approved = _request(client, dev)
    assert client.post(f"{EXC}/{approved['id']}/approve", headers=analyst).status_code == 200
    pending = _request(client, dev)
    _expire_now(approved["id"])
    _expire_now(pending["id"])

    for body in (approved, pending):
        [row] = _list(client, dev, package=body["package"])
        assert row["status"] == "expired" and row["active"] is False
        assert [r["id"] for r in _list(client, dev, package=body["package"], status="expired")] == [body["id"]]
        assert _list(client, dev, package=body["package"], status="approved") == []
        assert _list(client, dev, package=body["package"], status="pending") == []

    assert client.post(f"{EXC}/{pending['id']}/approve", headers=analyst).status_code == 409
    assert client.post(f"{EXC}/{pending['id']}/revoke", headers=dev).status_code == 409
    assert client.post(f"{EXC}/{approved['id']}/revoke", headers=analyst).status_code == 409


# --------------------------------------------------------------------------- listing
@pytest.mark.parametrize("params", [
    {"limit": 0}, {"limit": 201}, {"offset": -1}, {"status": "active"}, {"package": "../etc"},
    {"environment": "qa"}, {"policy_id": "not-a-uuid"},
])
def test_list_rejects_invalid_filters(client, params):
    _, reader = _user(Role.read_only)
    assert client.get(EXC, headers=reader, params=params).status_code == 422


def test_list_package_filter_uses_normalised_names(client):
    _, dev = _user(Role.developer)
    body = _request(client, dev)
    variant = body["package"].replace("-", "_").upper()
    assert [r["id"] for r in _list(client, dev, package=variant)] == [body["id"]]


def test_unknown_or_malformed_exception_ids(client):
    _, analyst = _user(Role.security_analyst)
    assert client.post(f"{EXC}/{uuid.uuid4()}/approve", headers=analyst).status_code == 404
    assert client.post(f"{EXC}/{uuid.uuid4()}/revoke", headers=analyst).status_code == 404
    assert client.post(f"{EXC}/not-a-uuid/approve", headers=analyst).status_code == 422


# --------------------------------------------------------------------------- stale reads
def _detached(exception_id: uuid.UUID) -> PolicyException:
    with SessionLocal() as db:
        row = db.get(PolicyException, exception_id)
        db.expunge(row)
        return row


def test_decision_from_a_stale_read_is_not_written(client, monkeypatch):
    """Another approver acted between load and write: the conditional UPDATE refuses."""
    _, requester = _user(Role.developer)
    body = _request(client, requester)
    exception_id = uuid.UUID(body["id"])
    stale = _detached(exception_id)  # still "pending" in memory

    _, other_admin = _user(Role.admin)
    assert client.post(f"{EXC}/{body['id']}/reject", headers=other_admin).status_code == 200

    monkeypatch.setattr(policies_router, "_load_exception", lambda _db, _id: stale)
    analyst_id, _ = _user(Role.security_analyst)
    with SessionLocal() as db:
        with pytest.raises(ConflictError):
            policies_router._decide(db, exception_id, db.get(User, analyst_id), ExceptionStatus.approved, None)
    with SessionLocal() as db:
        assert db.get(PolicyException, exception_id).status == "rejected"


def test_separation_of_duties_is_reasserted_in_the_database_write(client, monkeypatch):
    """Even if the loaded row lied about its requester, the UPDATE still refuses self-approval."""
    analyst_id, analyst = _user(Role.security_analyst)
    body = _request(client, analyst)
    exception_id = uuid.UUID(body["id"])
    forged = _detached(exception_id)
    forged.requested_by = uuid.uuid4()  # in-memory only

    monkeypatch.setattr(policies_router, "_load_exception", lambda _db, _id: forged)
    with SessionLocal() as db:
        with pytest.raises(ConflictError):
            policies_router._decide(db, exception_id, db.get(User, analyst_id), ExceptionStatus.approved, None)
    with SessionLocal() as db:
        row = db.get(PolicyException, exception_id)
        assert row.status == "pending" and row.approved_by is None
