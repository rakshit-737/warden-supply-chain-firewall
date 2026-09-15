"""Reusable FastAPI dependencies: DB session, current user, and RBAC guards.

Authorisation is permission-based (see :mod:`app.core.permissions`). Every protected route
declares its requirement with :func:`require_permission`; the caller's role is always read
from the database (never from the JWT ``role`` claim), so a role change or deactivation
takes effect on the very next request.
"""

from __future__ import annotations

import uuid

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AuthError, ForbiddenError
from app.core.permissions import Permission, Role, coerce_role, permissions_for
from app.core.security import decode_access_token
from app.db.models import User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None or not creds.credentials:
        raise AuthError("Missing bearer token")
    try:
        payload = decode_access_token(creds.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired", code="token_expired") from exc
    except jwt.PyJWTError as exc:
        raise AuthError("Invalid token") from exc

    if payload.get("type") != "access":
        raise AuthError("Invalid token type")

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError) as exc:
        raise AuthError("Malformed token subject") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive")
    return user


def require_permission(*perms: Permission | str):
    """Dependency factory: the caller must hold **every** permission in ``perms``.

    Unknown permission names raise ``ValueError`` at import time (a typo must never turn
    into an unguarded route). The returned guard exposes ``required_permissions`` so tests
    can assert that every route is protected.
    """
    if not perms:
        raise ValueError("require_permission() needs at least one permission")
    required = frozenset(Permission(p) for p in perms)

    def _guard(user: User = Depends(get_current_user)) -> User:
        missing = required - permissions_for(user.role)
        if missing:
            raise ForbiddenError("Missing required permission: " + ", ".join(sorted(p.value for p in missing)))
        return user

    _guard.required_permissions = required  # type: ignore[attr-defined]
    _guard.__name__ = "require_" + "__".join(sorted(p.value.replace(":", "_") for p in required))
    return _guard


def require_any_permission(*perms: Permission | str):
    """Dependency factory: the caller must hold **at least one** permission in ``perms``.

    Used where a route performs a finer, data-dependent check itself (e.g. an exception may
    be revoked by an approver *or* by its own requester).
    """
    if not perms:
        raise ValueError("require_any_permission() needs at least one permission")
    accepted = frozenset(Permission(p) for p in perms)

    def _guard(user: User = Depends(get_current_user)) -> User:
        if not accepted & permissions_for(user.role):
            raise ForbiddenError("Requires one of permissions: " + ", ".join(sorted(p.value for p in accepted)))
        return user

    _guard.required_permissions = accepted  # type: ignore[attr-defined]
    _guard.any_of = True  # type: ignore[attr-defined]
    return _guard


def require_role(*allowed: Role | str):
    """Dependency factory enforcing that the caller has one of ``allowed`` roles.

    Prefer :func:`require_permission`; this remains for compatibility.
    """
    roles = frozenset(r for r in (coerce_role(a) for a in allowed) if r is not None)
    if not roles:
        raise ValueError("require_role() needs at least one valid role")

    def _guard(user: User = Depends(get_current_user)) -> User:
        if coerce_role(user.role) not in roles:
            raise ForbiddenError(f"Requires one of roles: {', '.join(sorted(r.value for r in roles))}")
        return user

    _guard.required_roles = roles  # type: ignore[attr-defined]
    return _guard


# Compatibility guards (v1 names). require_admin is role-based by definition; the other two
# map to the permissions that v1 "analyst" and "viewer" routes needed.
require_admin = require_role(Role.admin)
require_analyst = require_permission(Permission.SCAN_CREATE)
require_viewer = require_permission(Permission.SCAN_READ)
