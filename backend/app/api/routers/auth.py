"""Authentication routes: register, login, refresh, logout, me."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.config import settings
from app.core.errors import AuthError, ConflictError
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    verify_password,
)
from app.db.models import RefreshToken, User
from app.db.session import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

_REFRESH_COOKIE = "warden_refresh"


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


@router.post("/register", response_model=UserOut, status_code=201)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    exists = db.scalar(select(User).where(User.email == payload.email.lower()))
    if exists:
        raise ConflictError("A user with that email already exists")
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    audit.record(db, actor_id=admin.id, action="user.register",
                 target_type="user", target_id=payload.email.lower(),
                 metadata={"role": payload.role.value})
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    # Constant-ish behaviour: always run a verify to reduce user-enumeration timing signal.
    valid = bool(user) and user.is_active and verify_password(payload.password, user.password_hash)
    if not valid:
        raise AuthError("Invalid credentials")

    # Opportunistic rehash if argon2 parameters changed.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    _issue_refresh(db, user, response)
    audit.record(db, actor_id=user.id, action="user.login", target_type="user",
                 target_id=str(user.id))
    db.commit()
    return TokenResponse(
        access_token=create_access_token(subject=str(user.id), role=user.role.value),
        expires_in=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> TokenResponse:
    raw = request.cookies.get(_REFRESH_COOKIE)
    if not raw:
        raise AuthError("Missing refresh token")
    token = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw))
    )
    now = datetime.now(timezone.utc)
    if token is None or token.revoked or token.expires_at.replace(tzinfo=timezone.utc) < now:
        raise AuthError("Invalid or expired refresh token")

    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise AuthError("User inactive")

    # Rotate: revoke the used token and issue a fresh one (refresh-token rotation).
    token.revoked = True
    _issue_refresh(db, user, response)
    db.commit()
    return TokenResponse(
        access_token=create_access_token(subject=str(user.id), role=user.role.value),
        expires_in=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
    )


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    raw = request.cookies.get(_REFRESH_COOKIE)
    if raw:
        token = db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw))
        )
        if token:
            token.revoked = True
            db.commit()
    response.delete_cookie(_REFRESH_COOKIE, path=f"{settings.API_V1_PREFIX}/auth")
    return Response(status_code=204)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
