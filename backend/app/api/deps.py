"""Reusable FastAPI dependencies: DB session, current user, and RBAC guards."""

from __future__ import annotations

import uuid

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AuthError, ForbiddenError
from app.core.security import decode_access_token
from app.db.models import Role, User
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
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise AuthError("Malformed token subject") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive")
    return user


def require_role(*allowed: Role):
    """Dependency factory enforcing that the caller has one of ``allowed`` roles."""

    def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise ForbiddenError(
                f"Requires one of roles: {', '.join(r.value for r in allowed)}"
            )
        return user

    return _guard


# Convenience guards (role hierarchy is explicit, not implicit).
require_admin = require_role(Role.admin)
require_analyst = require_role(Role.admin, Role.analyst)
require_viewer = require_role(Role.admin, Role.analyst, Role.viewer)
