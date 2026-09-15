"""Authentication and user administration.

The first five tests are the v1 behaviour (login, /me, RBAC denial, refresh rotation). The rest
cover Warden X hardening: constant-work login, audited failed logins that never contain the
password, refresh-token reuse detection, legacy role names on input, forged and invalid tokens,
and the users API including the "never remove the last active admin" invariant (tested on an
isolated database so the shared admin account is never at risk).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers import auth as auth_router
from app.core import security
from app.core.config import settings
from app.core.permissions import permissions_for
from app.db.base import Base
from app.db.models import AuditEvent, RefreshToken, Role, User
from app.db.session import SessionLocal, get_db
from app.main import create_app
from tests.conftest import auth


def test_login_success_and_me(client, admin_token):
    resp = client.get("/api/v1/auth/me", headers=auth(admin_token))
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_login_wrong_password_rejected(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_rbac_viewer_cannot_create_policy(client, admin_token):
    # Create a viewer, log in as them, attempt an admin-only action.
    client.post(
        "/api/v1/auth/register",
        headers=auth(admin_token),
        json={"email": "viewer@warden.io", "password": "ViewerPassw0rd!2026", "role": "viewer"},
    )
    tok = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@warden.io", "password": "ViewerPassw0rd!2026"},
    ).json()["access_token"]

    resp = client.post(
        "/api/v1/policies",
        headers=auth(tok),
        json={"name": "x", "warn_threshold": 10, "block_threshold": 20},
    )
    assert resp.status_code == 403


def test_refresh_rotation(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "AdminPassw0rd!2026"},
    )
    assert "warden_refresh" in login.cookies
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]


# =========================================================================== helpers
API = "/api/v1"
_PASSWORD = "Auth-Tests-Passw0rd!2026"
_COOKIE = "warden_refresh"


@lru_cache(maxsize=1)
def _password_hash() -> str:
    return security.hash_password(_PASSWORD)


def _make_user(role: Role = Role.developer, *, active: bool = True, email: str | None = None,
               session_factory=SessionLocal) -> User:
    with session_factory() as db:
        user = User(id=uuid.uuid4(), email=email or f"auth-{role.value}-{uuid.uuid4().hex[:10]}@warden.io",
                    password_hash=_password_hash(), role=role, is_active=active)
        db.add(user)
        db.commit()
        db.refresh(user)
        db.expunge(user)
        return user


def _headers(user: User) -> dict[str, str]:
    return auth(security.create_access_token(subject=str(user.id), role=user.role.value))


def _login(client, email: str, password: str = _PASSWORD):
    return client.post(f"{API}/auth/login", json={"email": email, "password": password})


def _refresh_with(client, raw_token: str):
    client.cookies.clear()
    client.cookies.set(_COOKIE, raw_token)
    try:
        return client.post(f"{API}/auth/refresh")
    finally:
        client.cookies.clear()


def _audit_rows(action: str, target_id: str | None = None) -> list[AuditEvent]:
    with SessionLocal() as db:
        stmt = select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
        if target_id is not None:
            stmt = stmt.where(AuditEvent.target_id == target_id)
        return list(db.scalars(stmt))


# =========================================================================== registration
@pytest.mark.parametrize("submitted,stored", [
    ("analyst", "security_analyst"), ("viewer", "read_only"), ("Security_Analyst", "security_analyst"),
    ("auditor", "auditor"), ("developer", "developer"),
])
def test_register_accepts_legacy_and_canonical_role_names(client, admin_token, submitted, stored):
    email = f"reg-{uuid.uuid4().hex[:10]}@warden.io"
    resp = client.post(f"{API}/auth/register", headers=auth(admin_token),
                       json={"email": email, "password": _PASSWORD, "role": submitted})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["role"] == stored
    assert set(body["permissions"]) == {p.value for p in permissions_for(stored)}
    assert "password" not in json.dumps(body)
    with SessionLocal() as db:
        assert db.scalar(select(User.role).where(User.email == email)) is Role(stored)
    [event] = _audit_rows("user.register", body["id"])
    assert event.metadata_ == {"email": email, "role": stored}


@pytest.mark.parametrize("override", [
    {"role": "superadmin"}, {"role": "root"}, {"role": ""}, {"password": "short"}, {"email": "not-an-email"},
    {"is_active": False}, {"permissions": ["user:manage"]},
])
def test_register_rejects_invalid_or_unexpected_input(client, admin_token, override):
    payload = {"email": f"reg-{uuid.uuid4().hex[:10]}@warden.io", "password": _PASSWORD, "role": "developer",
               **override}
    assert client.post(f"{API}/auth/register", headers=auth(admin_token), json=payload).status_code == 422


def test_register_duplicate_email_conflicts_case_insensitively(client, admin_token):
    email = f"dup-{uuid.uuid4().hex[:10]}@warden.io"
    first = client.post(f"{API}/auth/register", headers=auth(admin_token), json={"email": email, "password": _PASSWORD})
    assert first.status_code == 201 and first.json()["role"] == "read_only"  # least privilege by default
    again = client.post(f"{API}/auth/register", headers=auth(admin_token),
                        json={"email": email.upper(), "password": _PASSWORD})
    assert again.status_code == 409


def test_register_requires_user_manage(client):
    analyst = _make_user(Role.security_analyst)
    resp = client.post(f"{API}/auth/register", headers=_headers(analyst),
                       json={"email": f"x-{uuid.uuid4().hex[:8]}@warden.io", "password": _PASSWORD, "role": "admin"})
    assert resp.status_code == 403


# =========================================================================== login hardening
def test_login_does_one_verification_and_never_consults_a_disabled_accounts_hash(client, monkeypatch):
    active = _make_user(Role.developer)
    inactive = _make_user(Role.developer, active=False)
    seen: list[str | None] = []
    real = auth_router.verify_password_constant_work

    def spy(password, password_hash):
        seen.append(password_hash)
        return real(password, password_hash)

    monkeypatch.setattr(auth_router, "verify_password_constant_work", spy)
    cases = {
        "unknown": (f"ghost-{uuid.uuid4().hex[:10]}@warden.io", _PASSWORD, None),
        "inactive-correct-password": (inactive.email, _PASSWORD, None),
        "wrong-password": (active.email, "Wrong-Passw0rd!2026", active.password_hash),
    }
    errors = set()
    for email, password, expected_hash in cases.values():
        seen.clear()
        resp = _login(client, email, password)
        assert resp.status_code == 401
        assert seen == [expected_hash]
        error = resp.json()["error"]
        errors.add((error["code"], error["message"]))
    assert errors == {("unauthorized", "Invalid credentials")}  # indistinguishable responses


def test_constant_work_helper_runs_the_dummy_verification_when_there_is_no_usable_hash(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(security, "_dummy_verify", calls.append)
    assert security.verify_password_constant_work("pw", None) is False
    assert security.verify_password_constant_work("pw", "") is False
    assert security.verify_password_constant_work("pw", "not-an-argon2-hash") is False
    assert len(calls) == 3
    calls.clear()
    assert security.verify_password_constant_work(_PASSWORD, _password_hash()) is True
    assert security.verify_password_constant_work("Wrong-Passw0rd", _password_hash()) is False
    assert calls == []


def test_dummy_hash_uses_the_production_work_factor():
    dummy = security._DUMMY_PASSWORD_HASH
    assert dummy.startswith("$argon2id$")
    assert security.needs_rehash(dummy) is False
    assert security.verify_password("", dummy) is False


def test_failed_logins_are_audited_without_the_password(client, admin_token):
    canary = f"Canary-Passw0rd-{uuid.uuid4().hex}"
    user = _make_user(Role.developer)
    inactive = _make_user(Role.read_only, active=False)
    ghost = f"ghost-{uuid.uuid4().hex[:10]}@warden.io"
    for email in (ghost, user.email, inactive.email):
        resp = _login(client, email, canary)
        assert resp.status_code == 401 and canary not in resp.text

    by_email = {row.metadata_.get("email"): row for row in _audit_rows("user.login_failed")}
    assert by_email[ghost].metadata_["reason"] == "unknown_user"
    assert by_email[ghost].target_id is None and by_email[ghost].actor_id is None
    assert by_email[user.email].metadata_["reason"] == "bad_password"
    assert by_email[user.email].target_id == str(user.id)
    assert by_email[inactive.email].metadata_["reason"] == "inactive_user"
    with SessionLocal() as db:
        everything = json.dumps([[e.action, e.target_id, e.metadata_] for e in db.scalars(select(AuditEvent))])
    assert canary not in everything
    assert client.get(f"{API}/audit/verify", headers=auth(admin_token)).json()["ok"] is True


# =========================================================================== refresh tokens
def test_refresh_token_reuse_revokes_every_token_of_the_user(client):
    user = _make_user(Role.developer)
    token_a = _login(client, user.email).cookies[_COOKIE]
    token_c = _login(client, user.email).cookies[_COOKIE]  # a second device
    client.cookies.clear()

    rotated = _refresh_with(client, token_a)
    assert rotated.status_code == 200, rotated.text
    token_b = rotated.cookies[_COOKIE]
    assert token_b not in (token_a, token_c)

    replay = _refresh_with(client, token_a)
    assert replay.status_code == 401

    with SessionLocal() as db:
        tokens = db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()
        assert len(tokens) == 3 and all(t.revoked for t in tokens)
    [event] = _audit_rows("auth.refresh_reuse_detected", str(user.id))
    assert event.metadata_ == {"revoked_tokens": 2} and event.actor_id is None

    for survivor in (token_b, token_c):
        assert _refresh_with(client, survivor).status_code == 401


def test_expired_or_unknown_refresh_tokens_do_not_revoke_the_family(client):
    user = _make_user(Role.developer)
    live = _login(client, user.email).cookies[_COOKIE]
    expired = security.generate_refresh_token()
    with SessionLocal() as db:
        db.add(RefreshToken(user_id=user.id, token_hash=security.hash_refresh_token(expired),
                            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
        db.commit()
    for raw in (expired, "not-a-token-we-issued"):
        assert _refresh_with(client, raw).status_code == 401
    with SessionLocal() as db:
        live_row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == security.hash_refresh_token(live)))
        assert live_row.revoked is False
    assert _audit_rows("auth.refresh_reuse_detected", str(user.id)) == []


def test_replaying_a_long_expired_revoked_token_does_not_force_a_logout(client):
    """Regression: the revoked check ran before the expiry check, so any token ever rotated stayed a
    permanent trigger that revoked every current session of the user."""
    user = _make_user(Role.developer)
    live = _login(client, user.email).cookies[_COOKIE]
    ancient = security.generate_refresh_token()
    with SessionLocal() as db:
        db.add(RefreshToken(user_id=user.id, token_hash=security.hash_refresh_token(ancient), revoked=True,
                            expires_at=datetime.now(timezone.utc) - timedelta(days=193)))
        db.commit()
    for _ in range(2):
        assert _refresh_with(client, ancient).status_code == 401
    assert _audit_rows("auth.refresh_reuse_detected", str(user.id)) == []
    assert _refresh_with(client, live).status_code == 200


def test_rotation_and_reuse_handling_take_the_user_row_lock_first(client, monkeypatch):
    """Regression (PostgreSQL READ COMMITTED race): a revoke-all could miss the token a concurrent rotation
    inserted. Both paths must lock the user row before touching refresh tokens. SQLite cannot reproduce the
    race, so this checks the ordering and the emitted lock clause."""
    from sqlalchemy.dialects import postgresql

    calls: list[str] = []
    real_lock, real_revoke, real_issue = (auth_router.lock_user, auth_router.revoke_all_refresh_tokens,
                                          auth_router._issue_refresh)

    def lock(db, user_id):
        calls.append("lock_user")
        return real_lock(db, user_id)

    def revoke(db, user_id):
        calls.append("revoke_all")
        return real_revoke(db, user_id)

    def issue(db, user, response):
        calls.append("issue")
        return real_issue(db, user, response)

    monkeypatch.setattr(auth_router, "lock_user", lock)
    monkeypatch.setattr(auth_router, "revoke_all_refresh_tokens", revoke)
    monkeypatch.setattr(auth_router, "_issue_refresh", issue)
    user = _make_user(Role.developer)
    token = _login(client, user.email).cookies[_COOKIE]
    calls.clear()
    assert _refresh_with(client, token).status_code == 200
    assert calls == ["lock_user", "issue"]
    calls.clear()
    assert _refresh_with(client, token).status_code == 401  # replay of the rotated token
    assert calls == ["lock_user", "revoke_all"]
    compiled = str(auth_router.user_lock_statement(user.id).compile(dialect=postgresql.dialect()))
    assert compiled.rstrip().endswith("FOR UPDATE")


def test_logout_revokes_the_refresh_token(client):
    user = _make_user(Role.read_only)
    raw = _login(client, user.email).cookies[_COOKIE]
    client.cookies.clear()
    client.cookies.set(_COOKIE, raw)
    assert client.post(f"{API}/auth/logout").status_code == 204
    assert _refresh_with(client, raw).status_code == 401


def test_inactive_user_cannot_refresh(client):
    user = _make_user(Role.developer)
    raw = _login(client, user.email).cookies[_COOKIE]
    with SessionLocal() as db:
        db.get(User, user.id).is_active = False
        db.commit()
    assert _refresh_with(client, raw).status_code == 401


# =========================================================================== access tokens
def test_forged_role_claim_does_not_grant_permissions(client):
    viewer = _make_user(Role.read_only)
    forged = security.create_access_token(subject=str(viewer.id), role="admin")
    assert client.get(f"{API}/users", headers=auth(forged)).status_code == 403


def _claims(user_id: str, **overrides) -> dict:
    now = datetime.now(timezone.utc)
    claims = {"sub": user_id, "role": "admin", "type": "access", "iat": int(now.timestamp()),
              "exp": int((now + timedelta(minutes=5)).timestamp())}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


@pytest.mark.parametrize("factory", [
    pytest.param(lambda uid: jwt.encode(_claims(uid), None, algorithm="none"), id="alg-none"),
    pytest.param(lambda uid: jwt.encode(_claims(uid), "wrong-secret-" * 4, algorithm="HS256"), id="wrong-key"),
    pytest.param(lambda uid: jwt.encode(_claims(uid, type="refresh"), settings.SECRET_KEY, algorithm="HS256"),
                 id="wrong-type"),
    pytest.param(lambda uid: jwt.encode(_claims(uid, exp=1), settings.SECRET_KEY, algorithm="HS256"), id="expired"),
    pytest.param(lambda uid: jwt.encode(_claims(uid, sub=None), settings.SECRET_KEY, algorithm="HS256"),
                 id="no-subject"),
    pytest.param(lambda uid: jwt.encode(_claims("not-a-uuid"), settings.SECRET_KEY, algorithm="HS256"),
                 id="malformed-subject"),
    pytest.param(lambda uid: jwt.encode(_claims(str(uuid.uuid4())), settings.SECRET_KEY, algorithm="HS256"),
                 id="unknown-user"),
    pytest.param(lambda uid: "not.a.jwt", id="garbage"),
])
def test_invalid_access_tokens_are_rejected(client, factory):
    user = _make_user(Role.admin)
    resp = client.get(f"{API}/auth/me", headers=auth(factory(str(user.id))))
    assert resp.status_code == 401, resp.text


def test_deactivation_ends_existing_sessions_and_is_audited(client, admin_token):
    user = _make_user(Role.developer)
    login = _login(client, user.email)
    access, raw = login.json()["access_token"], login.cookies[_COOKIE]
    client.cookies.clear()
    assert client.get(f"{API}/auth/me", headers=auth(access)).status_code == 200

    resp = client.patch(f"{API}/users/{user.id}", headers=auth(admin_token), json={"is_active": False})
    assert resp.status_code == 200 and resp.json()["is_active"] is False
    assert client.get(f"{API}/auth/me", headers=auth(access)).status_code == 401
    with SessionLocal() as db:
        assert all(t.revoked for t in db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)))
    [event] = _audit_rows("user.update", str(user.id))
    assert event.metadata_ == {"changes": {"is_active": [True, False]}, "revoked_refresh_tokens": 1}
    assert _refresh_with(client, raw).status_code == 401


# =========================================================================== users API
def test_users_listing_filters_and_matches_like_wildcards_literally(client, admin_token):
    tag = uuid.uuid4().hex[:8]
    literal = _make_user(Role.auditor, email=f"like_{tag}@warden.io")
    _make_user(Role.auditor, email=f"likex{tag}@warden.io")  # would match an unescaped "_" wildcard

    def emails(**params) -> list[str]:
        resp = client.get(f"{API}/users", headers=auth(admin_token), params=params)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert all("password_hash" not in item for item in items)
        return [item["email"] for item in items]

    assert emails(q=f"LIKE_{tag}") == [literal.email]
    assert emails(q="%") == []
    assert len(emails(q=tag, role="auditor")) == 2
    assert emails(q=tag, role="analyst") == []  # legacy name accepted as a filter value
    assert emails(q=tag, is_active="false") == []
    assert client.get(f"{API}/users", headers=auth(admin_token), params={"role": "god"}).status_code == 422
    assert client.get(f"{API}/users", headers=auth(admin_token), params={"limit": 201}).status_code == 422


@pytest.mark.parametrize("body", [
    {}, {"email": "x@warden.io"}, {"password_hash": "x"}, {"role": "owner"}, {"is_active": "sometimes"},
    {"role": None, "is_active": None},
])
def test_user_update_rejects_invalid_bodies(client, admin_token, body):
    target = _make_user(Role.read_only)
    assert client.patch(f"{API}/users/{target.id}", headers=auth(admin_token), json=body).status_code == 422


def test_user_role_change_accepts_legacy_names_and_is_audited(client, admin_token):
    target = _make_user(Role.read_only)
    resp = client.patch(f"{API}/users/{target.id}", headers=auth(admin_token), json={"role": "analyst"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "security_analyst"
    [event] = _audit_rows("user.update", str(target.id))
    assert event.metadata_["changes"] == {"role": ["read_only", "security_analyst"]}
    missing = client.patch(f"{API}/users/{uuid.uuid4()}", headers=auth(admin_token), json={"role": "developer"})
    assert missing.status_code == 404


@pytest.fixture()
def isolated(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'users.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    try:
        with TestClient(app) as api:
            yield api, factory
    finally:
        engine.dispose()


def test_last_active_admin_can_never_be_removed(isolated):
    api, factory = isolated
    only = _make_user(Role.admin, session_factory=factory)
    for body in ({"role": "security_analyst"}, {"is_active": False}, {"role": "viewer", "is_active": False}):
        resp = api.patch(f"{API}/users/{only.id}", headers=_headers(only), json=body)
        assert resp.status_code == 409, resp.text
        assert resp.json()["error"]["code"] == "last_admin"

    _make_user(Role.admin, active=False, session_factory=factory)  # an inactive admin does not count
    assert api.patch(f"{API}/users/{only.id}", headers=_headers(only), json={"role": "developer"}).status_code == 409

    second = _make_user(Role.admin, session_factory=factory)
    demoted = api.patch(f"{API}/users/{only.id}", headers=_headers(second), json={"role": "developer"})
    assert demoted.status_code == 200 and demoted.json()["role"] == "developer"

    # `second` is now the last active admin, including against self-deactivation ...
    assert api.patch(f"{API}/users/{second.id}", headers=_headers(second), json={"is_active": False}).status_code == 409
    # ... and the demoted user lost user:manage at once (authorisation reads the database role,
    # not the role claim in their still-valid token).
    assert api.patch(f"{API}/users/{second.id}", headers=_headers(only), json={"role": "developer"}).status_code == 403
    with factory() as db:
        remaining = db.get(User, second.id)
        assert remaining.role is Role.admin and remaining.is_active is True
