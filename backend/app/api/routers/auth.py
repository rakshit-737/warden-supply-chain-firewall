"""Authentication routes: register, login, refresh, logout, me.

Hardening:

* **Constant-work login** — exactly one argon2 verification happens whether the account
  exists, is inactive, or the password is wrong, and every failure returns the same
  message, so neither timing nor response reveals which case occurred.
* **Failed logins are audited** as ``user.login_failed`` with the submitted email and a
  server-side reason. The submitted password is never logged, stored or echoed.
* **Refresh-token rotation with reuse detection** — each refresh atomically revokes the
  presented token and issues a new one. Presenting a token that was already revoked
  (a replayed, possibly stolen token — or, benignly, two tabs racing a refresh) revokes
  *every* refresh token of that user and is audited as ``auth.refresh_reuse_detected``;
  the user must log in again. This follows the OAuth 2.0 Security BCP refresh-token
  rotation guidance and deliberately prefers forcing a re-login over leaving a stolen
  token family alive.
* **Per-user serialisation** — rotation and reuse handling both take the user's row lock
  (``SELECT … FOR UPDATE`` on PostgreSQL) before touching refresh tokens. Without it, a
  revoke-all ``UPDATE`` running under READ COMMITTED could wait on a token that a concurrent
  rotation had consumed and never see the token that rotation inserted, leaving the stolen
  family alive. SQLite serialises writers itself and ignores ``FOR UPDATE``.
* **Expiry before reuse** — an expired token is rejected before the revoked check, so replaying
  a long-dead token (an old device, a leaked log) cannot repeatedly force a logout of all the
  user's current sessions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_permission
from app.core.config import settings
from app.core.errors import AuthError, ConflictError
from app.core.logging import get_logger
from app.core.permissions import Permission
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    verify_password_constant_work,
)
from app.db.base import as_utc
from app.db.models import RefreshToken, User
from app.db.session import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])
log = get_logger("warden.auth")

_REFRESH_COOKIE = "warden_refresh"
_INVALID_REFRESH = "Invalid or expired refresh token"


def _issue_refresh(db: Session, user: User, response: Response) -> None:
    raw = generate_refresh_token()
    token = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS),
    )
    db.add(token)
    response.set_cookie(
        _REFRESH_COOKIE,
        raw,
        max_age=settings.REFRESH_TOKEN_TTL_DAYS * 86400,
        httponly=True,
        secure=settings.ENV == "production",
        samesite="strict",
        path=f"{settings.API_V1_PREFIX}/auth",
    )


def _access_token_response(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(subject=str(user.id), role=user.role.value),
        expires_in=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
    )


def user_lock_statement(user_id: uuid.UUID):
    """``SELECT … FROM users WHERE id = :user_id FOR UPDATE`` (the lock clause is a no-op on SQLite)."""
    return select(User).where(User.id == user_id).with_for_update().execution_options(populate_existing=True)


def lock_user(db: Session, user_id: uuid.UUID) -> User | None:
    """Lock the user's row for the rest of the transaction; serialises refresh-token operations per user."""
    return db.execute(user_lock_statement(user_id)).scalar_one_or_none()


def revoke_all_refresh_tokens(db: Session, user_id: uuid.UUID) -> int:
    """Revoke every still-valid refresh token of ``user_id``; returns how many were revoked."""
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .values(revoked=True)
        .execution_options(synchronize_session=False)
    )
    return int(result.rowcount or 0)


@router.post("/register", response_model=UserOut, status_code=201)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_permission(Permission.USER_MANAGE)),
) -> User:
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise ConflictError("A user with that email already exists")
    user = User(id=uuid.uuid4(), email=email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    audit.record(db, actor_id=admin.id, action="user.register", target_type="user", target_id=str(user.id),
                 metadata={"email": email, "role": payload.role.value})
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    email = payload.email.lower()
    user = db.scalar(select(User).where(User.email == email))
    # Always exactly one argon2 verification. A missing *or inactive* account is verified
    # against the dummy hash, so the stored hash of a disabled account is never consulted
    # and the timing does not depend on which failure case occurred.
    usable = user is not None and user.is_active
    password_ok = verify_password_constant_work(payload.password, user.password_hash if usable else None)

    if user is None or not user.is_active or not password_ok:
        reason = "unknown_user" if user is None else ("inactive_user" if not user.is_active else "bad_password")
        audit.record(db, actor_id=None, action="user.login_failed", target_type="user",
                     target_id=str(user.id) if user else None, metadata={"email": email, "reason": reason})
        db.commit()
        raise AuthError("Invalid credentials")

    # Opportunistic rehash if argon2 parameters changed.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    _issue_refresh(db, user, response)
    audit.record(db, actor_id=user.id, action="user.login", target_type="user", target_id=str(user.id))
    db.commit()
    return _access_token_response(user)


def _handle_refresh_reuse(db: Session, user_id: uuid.UUID) -> None:
    db.rollback()
    # Wait for any in-flight rotation of this user to commit, so the revoke-all below also sees
    # (and revokes) the token that rotation issued.
    lock_user(db, user_id)
    revoked = revoke_all_refresh_tokens(db, user_id)
    audit.record(db, actor_id=None, action="auth.refresh_reuse_detected", target_type="user",
                 target_id=str(user_id), metadata={"revoked_tokens": revoked})
    db.commit()
    log.warning("refresh_token_reuse_detected", user_id=str(user_id), revoked_tokens=revoked)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> TokenResponse:
    raw = request.cookies.get(_REFRESH_COOKIE)
    if not raw:
        raise AuthError("Missing refresh token")
    token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw)))
    if token is None:
        raise AuthError(_INVALID_REFRESH)
    user_id = token.user_id
    if as_utc(token.expires_at) < datetime.now(timezone.utc):
        raise AuthError(_INVALID_REFRESH)  # checked first: a long-expired token never triggers revoke-all
    if token.revoked:
        _handle_refresh_reuse(db, user_id)
        raise AuthError(_INVALID_REFRESH)

    user = lock_user(db, user_id)
    if user is None or not user.is_active:
        raise AuthError("User inactive")

    # Rotate atomically: only one concurrent request can consume a given token.
    consumed = db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == token.id, RefreshToken.revoked.is_(False))
        .values(revoked=True)
        .execution_options(synchronize_session=False)
    )
    if (consumed.rowcount or 0) != 1:
        _handle_refresh_reuse(db, user_id)
        raise AuthError(_INVALID_REFRESH)

    _issue_refresh(db, user, response)
    db.commit()
    return _access_token_response(user)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    raw = request.cookies.get(_REFRESH_COOKIE)
    if raw:
        token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw)))
        if token is not None and not token.revoked:
            token.revoked = True
            audit.record(db, actor_id=token.user_id, action="user.logout", target_type="user",
                         target_id=str(token.user_id))
            db.commit()
    response.delete_cookie(_REFRESH_COOKIE, path=f"{settings.API_V1_PREFIX}/auth")
    return Response(status_code=204)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
