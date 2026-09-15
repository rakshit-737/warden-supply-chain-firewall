"""Server-side RBAC: the permission matrix and a role x endpoint authorisation matrix.

Two independent layers are checked:

1. ``ROLE_PERMISSIONS`` is compared with a literal transcription of the SPEC section 6 table,
   so an accidental grant in the code cannot silently "agree with itself".
2. Every route of the auth, users, audit, scans, policies and events routers is called once
   per role. Allowed roles must receive the route's success status; every other role must
   receive 403 with the standard error envelope. A route-introspection test fails when a
   route is added to those routers without an authentication/permission dependency or
   without a row in this matrix, or when a route's guard disagrees with its matrix row.

Resources a call needs (a scan, a pending exception requested by someone else, an event ...)
are created fresh for every call, so a successful mutation never influences another test.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pytest
from fastapi.routing import APIRoute

from app.analysis.orchestrator import AnalysisResult
from app.api.deps import get_current_user, require_admin, require_analyst, require_permission, require_viewer
from app.api.routers import audit as audit_routes
from app.api.routers import auth as auth_routes
from app.api.routers import events as events_routes
from app.api.routers import policies as policies_routes
from app.api.routers import scans as scans_router
from app.api.routers import users as users_routes
from app.core.permissions import (
    ADMIN_ONLY_PERMISSIONS,
    ROLE_PERMISSIONS,
    Permission,
    Role,
    coerce_role,
    has_permissions,
    permissions_for,
    roles_with,
)
from app.core.security import create_access_token, hash_password
from app.db.models import Decision, Policy, PolicyException, Scan, Severity, User
from app.db.session import SessionLocal
from app.events import bus
from app.events.types import EventType
from app.main import create_app
from tests.conftest import auth

API = "/api/v1"

ALL = frozenset(r.value for r in Role)
ENGINEERING = frozenset({"admin", "security_analyst", "developer"})
SECOPS = frozenset({"admin", "security_analyst"})
ADMIN = frozenset({"admin"})
OVERSIGHT = frozenset({"admin", "auditor"})

# Literal transcription of SPEC section 6 (do not derive this from app code).
SPEC_TABLE: dict[str, frozenset[str]] = {
    "scan:create": ENGINEERING, "project:write": ENGINEERING, "container:scan": ENGINEERING,
    "diff:create": ENGINEERING,
    "scan:read": ALL, "project:read": ALL, "event:read": ALL, "monitor:read": ALL, "policy:read": ALL,
    "report:read": ALL, "ml:read": ALL, "vuln:read": ALL,
    "exception:request": ENGINEERING,
    "exception:approve": SECOPS,
    "event:ack": SECOPS, "monitor:write": SECOPS,
    "policy:write": ADMIN, "user:manage": ADMIN, "system:write": ADMIN,
    "audit:read": OVERSIGHT, "system:read": OVERSIGHT,
}


# =========================================================================== permission table
def test_permission_catalogue_matches_spec():
    assert {p.value for p in Permission} == set(SPEC_TABLE)


@pytest.mark.parametrize("role", list(Role), ids=lambda r: r.value)
def test_role_permissions_match_spec_table(role):
    expected = {perm for perm, roles in SPEC_TABLE.items() if role.value in roles}
    assert {p.value for p in ROLE_PERMISSIONS[role]} == expected


def test_admin_only_permissions_are_held_by_admin_alone():
    assert ADMIN_ONLY_PERMISSIONS == {Permission.POLICY_WRITE, Permission.USER_MANAGE, Permission.SYSTEM_WRITE}
    for perm in ADMIN_ONLY_PERMISSIONS:
        assert roles_with(perm) == [Role.admin]


@pytest.mark.parametrize(
    "submitted,canonical",
    [("analyst", "security_analyst"), ("viewer", "read_only"), (" Viewer ", "read_only"), ("ADMIN", "admin")],
)
def test_legacy_and_case_variant_role_names_map_to_canonical_roles(submitted, canonical):
    assert coerce_role(submitted) is Role(canonical)
    assert permissions_for(submitted) == ROLE_PERMISSIONS[Role(canonical)]


@pytest.mark.parametrize("bogus", ["root", "superadmin", "", "admin;--", "admin\x00", None, 1])
def test_unknown_roles_hold_no_permissions(bogus):
    assert coerce_role(bogus) is None
    assert permissions_for(bogus) == frozenset()
    assert not has_permissions(bogus, [Permission.SCAN_READ])


def test_has_permissions_requires_every_listed_permission():
    assert has_permissions(Role.developer, [Permission.SCAN_CREATE, Permission.SCAN_READ])
    assert not has_permissions(Role.developer, [Permission.SCAN_CREATE, Permission.EXCEPTION_APPROVE])


def test_require_permission_refuses_unknown_or_missing_permissions():
    with pytest.raises(ValueError):
        require_permission("scan:delete")
    with pytest.raises(ValueError):
        require_permission()


def test_legacy_guard_names_keep_their_meaning():
    assert require_analyst.required_permissions == {Permission.SCAN_CREATE}
    assert require_viewer.required_permissions == {Permission.SCAN_READ}
    assert require_admin.required_roles == {Role.admin}


# =========================================================================== fixtures & resources
class _CleanOrchestrator:
    """Offline stand-in: every package is clean (no network, deterministic)."""

    def analyze(self, ecosystem, name, version, options=None):
        return AnalysisResult(ecosystem, name, version or "1.0.0", 1, 0, 1, "info", {}, [], "rbac-matrix", 5, False)


@pytest.fixture(autouse=True)
def _offline_orchestrator(monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _CleanOrchestrator())


@lru_cache(maxsize=1)
def _password_hash() -> str:
    return hash_password("Rbac-Matrix-Passw0rd!")


def _unique(label: str) -> str:
    return f"{label}-{uuid.uuid4().hex[:12]}"


def _create_user(role: Role, label: str) -> uuid.UUID:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"{_unique('rbac-' + label)}@warden.io",
                    password_hash=_password_hash(), role=role)
        db.add(user)
        db.commit()
        return user.id


def _create_scan() -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(id=uuid.uuid4(), ecosystem="pypi", package_name=_unique("rbac-scan"), version="1.0.0",
                    analyzer_version="rbac-matrix", severity=Severity.info, decision=Decision.allow)
        db.add(scan)
        db.commit()
        return scan.id


def _create_policy() -> uuid.UUID:
    with SessionLocal() as db:
        policy = Policy(id=uuid.uuid4(), name=_unique("rbac-policy"), is_active=False, environment="development")
        db.add(policy)
        db.commit()
        return policy.id


def _create_pending_exception(requester_id: uuid.UUID) -> uuid.UUID:
    with SessionLocal() as db:
        exc = PolicyException(
            id=uuid.uuid4(), package=_unique("rbac-exc"), codes=["NETWORK_EGRESS"], categories=[],
            justification="RBAC matrix fixture exception", requested_by=requester_id, status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.add(exc)
        db.commit()
        return exc.id


def _create_event() -> uuid.UUID:
    with SessionLocal() as db:
        row = bus.publish(db, EventType.PACKAGE_SCANNED, "info", "RBAC matrix event", package=_unique("rbac-event"))
        db.commit()
        return row.id


def _expires(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@dataclass(frozen=True)
class Principals:
    tokens: dict[Role, str]
    requester_id: uuid.UUID  # a developer owning the exceptions approvers decide in the matrix


@pytest.fixture(scope="module")
def principals() -> Principals:
    tokens = {}
    for role in Role:
        user_id = _create_user(role, role.value)
        tokens[role] = create_access_token(subject=str(user_id), role=role.value)
    return Principals(tokens=tokens, requester_id=_create_user(Role.developer, "requester"))


# =========================================================================== endpoint matrix
Builder = Callable[[Principals], tuple[str, "dict | None"]]


@dataclass(frozen=True)
class Endpoint:
    method: str
    route: str  # path template as registered, without the API prefix
    allowed: frozenset[str]
    success: int
    build: Builder

    @property
    def id(self) -> str:
        return f"{self.method} {self.route}"


def _static(path: str) -> Builder:
    return lambda _p: (path, None)


ENDPOINTS: tuple[Endpoint, ...] = (
    # --- auth / users -------------------------------------------------------------------
    Endpoint("GET", "/auth/me", ALL, 200, _static("/auth/me")),
    Endpoint("POST", "/auth/register", SPEC_TABLE["user:manage"], 201, lambda _p: (
        "/auth/register",
        {"email": f"{_unique('rbac-register')}@warden.io", "password": "Register-Passw0rd!", "role": "developer"},
    )),
    Endpoint("GET", "/users", SPEC_TABLE["user:manage"], 200, _static("/users")),
    Endpoint("PATCH", "/users/{user_id}", SPEC_TABLE["user:manage"], 200,
             lambda _p: (f"/users/{_create_user(Role.read_only, 'target')}", {"role": "developer"})),
    # --- audit -----------------------------------------------------------------------------
    Endpoint("GET", "/audit", SPEC_TABLE["audit:read"], 200, _static("/audit")),
    Endpoint("GET", "/audit/verify", SPEC_TABLE["audit:read"], 200, _static("/audit/verify")),
    # --- scans -----------------------------------------------------------------------------
    Endpoint("POST", "/scans", SPEC_TABLE["scan:create"], 201,
             lambda _p: ("/scans", {"ecosystem": "pypi", "name": _unique("rbac-scan"), "version": "1.0.0"})),
    Endpoint("GET", "/scans", SPEC_TABLE["scan:read"], 200, _static("/scans")),
    Endpoint("GET", "/scans/stats/overview", SPEC_TABLE["scan:read"], 200, _static("/scans/stats/overview")),
    Endpoint("GET", "/scans/{scan_id}", SPEC_TABLE["scan:read"], 200, lambda _p: (f"/scans/{_create_scan()}", None)),
    # --- policies --------------------------------------------------------------------------
    Endpoint("GET", "/policies", SPEC_TABLE["policy:read"], 200, _static("/policies")),
    Endpoint("GET", "/policies/active", SPEC_TABLE["policy:read"], 200, _static("/policies/active")),
    Endpoint("POST", "/policies", SPEC_TABLE["policy:write"], 201,
             lambda _p: ("/policies", {"name": _unique("rbac-policy"), "environment": "staging"})),
    Endpoint("PUT", "/policies/{policy_id}", SPEC_TABLE["policy:write"], 200, lambda _p: (
        f"/policies/{_create_policy()}", {"name": "rbac-policy-v2", "warn_threshold": 30, "block_threshold": 60},
    )),
    Endpoint("POST", "/policies/{policy_id}/activate", SPEC_TABLE["policy:write"], 200,
             lambda _p: (f"/policies/{_create_policy()}/activate", None)),
    # --- policy exceptions -----------------------------------------------------------------
    Endpoint("GET", "/policies/exceptions", SPEC_TABLE["policy:read"], 200, _static("/policies/exceptions")),
    Endpoint("POST", "/policies/exceptions", SPEC_TABLE["exception:request"], 201, lambda _p: (
        "/policies/exceptions",
        {"package": _unique("rbac-exc"), "codes": ["NETWORK_EGRESS"],
         "justification": "Needed for the RBAC matrix test", "expires_at": _expires()},
    )),
    Endpoint("POST", "/policies/exceptions/{exception_id}/approve", SPEC_TABLE["exception:approve"], 200,
             lambda p: (f"/policies/exceptions/{_create_pending_exception(p.requester_id)}/approve", None)),
    Endpoint("POST", "/policies/exceptions/{exception_id}/reject", SPEC_TABLE["exception:approve"], 200,
             lambda p: (f"/policies/exceptions/{_create_pending_exception(p.requester_id)}/reject", None)),
    # Revoking *someone else's* exception needs exception:approve; a requester may only withdraw
    # their own (covered in test_policy_exceptions_api.py).
    Endpoint("POST", "/policies/exceptions/{exception_id}/revoke", SPEC_TABLE["exception:approve"], 200,
             lambda p: (f"/policies/exceptions/{_create_pending_exception(p.requester_id)}/revoke", None)),
    # --- events ----------------------------------------------------------------------------
    Endpoint("GET", "/events", SPEC_TABLE["event:read"], 200, _static("/events")),
    Endpoint("POST", "/events/{event_id}/ack", SPEC_TABLE["event:ack"], 200,
             lambda _p: (f"/events/{_create_event()}/ack", None)),
)


@pytest.mark.parametrize("role", list(Role), ids=lambda r: r.value)
@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.id)
def test_role_endpoint_matrix(client, principals, endpoint, role):
    path, body = endpoint.build(principals)
    resp = client.request(endpoint.method, API + path, headers=auth(principals.tokens[role]), json=body)
    if role.value in endpoint.allowed:
        assert resp.status_code == endpoint.success, resp.text
    else:
        assert resp.status_code == 403, resp.text
        assert resp.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.id)
def test_matrix_endpoints_reject_anonymous_callers(client, endpoint):
    path = re.sub(r"\{[a-z_]+\}", str(uuid.uuid4()), endpoint.route)
    resp = client.request(endpoint.method, API + path)
    assert resp.status_code == 401, resp.text


# =========================================================================== route coverage
# The routers are read directly (their paths already carry the router prefix) instead of walking
# ``app.routes``, whose structure for included routers is a FastAPI implementation detail.
# test_router_mounting below checks that each of them is served under the API prefix.
_MATRIX_ROUTERS = (auth_routes, users_routes, audit_routes, scans_router, policies_routes, events_routes)
_PUBLIC_ROUTES = {("POST", "/auth/login"), ("POST", "/auth/refresh"), ("POST", "/auth/logout")}


def _dependency_calls(dependant) -> Iterator[Callable]:
    for dep in dependant.dependencies:
        yield dep.call
        yield from _dependency_calls(dep)


def _matrix_routes() -> Iterator[tuple[str, str, APIRoute]]:
    for module in _MATRIX_ROUTERS:
        for route in module.router.routes:
            assert isinstance(route, APIRoute), f"unexpected route type in {module.__name__}: {route!r}"
            for method in sorted(route.methods):
                yield method, route.path, route


def test_router_mounting():
    paths = set(create_app().openapi()["paths"])
    for module in _MATRIX_ROUTERS:
        for route in module.router.routes:
            assert API + route.path in paths, f"{route.path} is not served under {API}"


def test_every_owned_route_is_guarded_and_covered_by_the_matrix():
    matrix = {(e.method, e.route): e for e in ENDPOINTS}
    seen: set[tuple[str, str]] = set()
    for method, path, route in _matrix_routes():
        seen.add((method, path))
        if (method, path) in _PUBLIC_ROUTES:
            continue
        calls = list(_dependency_calls(route.dependant))
        guards = [c for c in calls if getattr(c, "required_permissions", None)]
        assert guards or get_current_user in calls, f"{method} {path} has no authentication dependency"
        assert (method, path) in matrix, f"{method} {path} is not covered by the RBAC matrix"
        for guard in guards:
            if getattr(guard, "any_of", False):
                continue  # data-dependent route (revoke); behaviour is asserted by the HTTP matrix
            holders = {r.value for r in Role if guard.required_permissions <= permissions_for(r)}
            assert holders == matrix[(method, path)].allowed, f"{method} {path}: guard and matrix disagree"
    assert set(matrix) <= seen, f"matrix rows without a route: {sorted(set(matrix) - seen)}"
