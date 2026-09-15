"""Policy changes must be provable from the tamper-evident audit chain.

Runs on an isolated SQLite database so activating policies cannot affect other tests.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers.policies import AUDIT_LIST_ITEMS, policy_digest, policy_snapshot
from app.core import security
from app.db.base import Base
from app.db.models import AuditEvent, Policy, Role, User
from app.db.session import get_db
from app.main import create_app
from tests.conftest import auth

API = "/api/v1"


@pytest.fixture()
def api(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'policies.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    with factory() as db:
        admin = User(id=uuid.uuid4(), email="policy-audit@warden.io", password_hash="unused", role=Role.admin)
        db.add(admin)
        db.commit()
        headers = auth(security.create_access_token(subject=str(admin.id), role="admin"))
    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    try:
        with TestClient(app) as client:
            yield client, factory, headers
    finally:
        engine.dispose()


def _events(factory, target_id: str) -> list[tuple[str, dict]]:
    with factory() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.target_id == target_id).order_by(AuditEvent.seq))
        return [(row.action, row.metadata_) for row in rows]


def test_allowlist_add_then_remove_is_provable_from_the_audit_chain(api):
    """Regression: policy.update logged only {version, environment}, so a temporary allowlist entry left no trace."""
    client, factory, headers = api
    base = {"name": "prod-strict", "warn_threshold": 40, "block_threshold": 70, "environment": "production"}
    pid = client.post(f"{API}/policies", headers=headers, json=base).json()["id"]
    for change in ({"allowlist": ["evil-pkg"]}, {"allowlist": []}, {"block_threshold": 90}):
        assert client.put(f"{API}/policies/{pid}", headers=headers, json={**base, **change}).status_code == 200

    events = _events(factory, pid)
    assert [action for action, _ in events] == ["policy.create"] + ["policy.update"] * 3
    create, add, remove, threshold = (metadata for _, metadata in events)
    assert create["settings"] == {"name": "prod-strict", "environment": "production", "warn_threshold": 40,
                                  "block_threshold": 70, "min_package_age_days": 0}
    assert create["lists"]["allowlist"] == [] and create["list_counts"]["allowlist"] == 0
    assert add["changes"] == {"allowlist": {"added": ["evil-pkg"], "removed": [], "added_count": 1,
                                            "removed_count": 0}}
    assert remove["changes"] == {"allowlist": {"added": [], "removed": ["evil-pkg"], "added_count": 0,
                                               "removed_count": 1}}
    assert threshold["changes"] == {"block_threshold": {"before": 70, "after": 90}}
    # The digests link every change to the previous content; identical content has an identical digest.
    assert add["policy_sha256_before"] == create["policy_sha256"]
    assert remove["policy_sha256_before"] == add["policy_sha256"] != create["policy_sha256"]
    assert remove["policy_sha256"] == create["policy_sha256"]
    with factory() as db:
        assert policy_digest(policy_snapshot(db.get(Policy, uuid.UUID(pid)))) == threshold["policy_sha256"]
    assert client.get(f"{API}/audit/verify", headers=headers).json()["ok"] is True


def test_long_lists_are_bounded_in_the_audit_row_but_covered_by_the_digest(api):
    client, factory, headers = api
    denylist = [f"bad-pkg-{i}" for i in range(AUDIT_LIST_ITEMS + 10)]
    body = {"name": "long", "warn_threshold": 40, "block_threshold": 70, "environment": "staging", "denylist": denylist}
    pid = client.post(f"{API}/policies", headers=headers, json=body).json()["id"]
    [(_, create)] = _events(factory, pid)
    assert create["lists"]["denylist"] == denylist[:AUDIT_LIST_ITEMS]
    assert create["list_counts"]["denylist"] == len(denylist)
    with factory() as db:
        assert policy_digest(policy_snapshot(db.get(Policy, uuid.UUID(pid)))) == create["policy_sha256"]


def test_activation_records_the_digest_and_the_policies_it_deactivated(api):
    client, factory, headers = api
    body = {"warn_threshold": 40, "block_threshold": 70, "environment": "development"}
    first = client.post(f"{API}/policies", headers=headers, json={**body, "name": "first"}).json()["id"]
    second = client.post(f"{API}/policies", headers=headers, json={**body, "name": "second"}).json()["id"]
    assert client.post(f"{API}/policies/{first}/activate", headers=headers).status_code == 200
    assert client.post(f"{API}/policies/{second}/activate", headers=headers).status_code == 200
    first_activation = _events(factory, first)[-1]
    second_activation = _events(factory, second)[-1]
    assert first_activation[0] == second_activation[0] == "policy.activate"
    assert first_activation[1]["deactivated_policy_ids"] == []
    assert second_activation[1]["deactivated_policy_ids"] == [first]
    with factory() as db:
        assert second_activation[1]["policy_sha256"] == policy_digest(policy_snapshot(db.get(Policy,
                                                                                            uuid.UUID(second))))
