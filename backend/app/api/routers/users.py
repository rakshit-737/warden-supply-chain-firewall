"""User administration (``user:manage``: admin only).

Invariant: the system always keeps at least one *active* admin. Demoting or deactivating the
last one is refused (409), including an admin acting on their own account. On PostgreSQL the
remaining admin rows are locked (``SELECT … FOR UPDATE``) while the check runs so two admins
cannot concurrently demote each other; SQLite serialises writers itself.

Deactivating a user revokes all their refresh tokens; access tokens stop working on the
next request because every request re-reads the user from the database.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.api.routers.auth import revoke_all_refresh_tokens
from app.core.errors import ConflictError, NotFoundError
from app.core.permissions import Permission, Role
from app.db.models import User
from app.db.session import get_db
from app.schemas.common import MAX_PAGE_LIMIT, Page, escape_like
from app.schemas.user import UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])

_user_manager = require_permission(Permission.USER_MANAGE)


@router.get("", response_model=Page[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(_user_manager),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    role: Role | None = None,
    is_active: bool | None = None,
    q: str | None = Query(None, max_length=320, description="Case-insensitive email substring"),
) -> Page[UserOut]:
    filters = []
    if role is not None:
        filters.append(User.role == role)
    if is_active is not None:
        filters.append(User.is_active.is_(is_active))
    if q:
        filters.append(func.lower(User.email).like(f"%{escape_like(q.lower())}%", escape="\\"))
    total = db.scalar(select(func.count(User.id)).where(*filters)) or 0
    rows = db.scalars(select(User).where(*filters).order_by(User.created_at, User.email).limit(limit).offset(offset))
    return Page[UserOut](items=[UserOut.model_validate(u) for u in rows], total=total, limit=limit, offset=offset)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(_user_manager),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")

    new_role = payload.role if payload.role is not None else user.role
    new_active = payload.is_active if payload.is_active is not None else user.is_active

    removes_active_admin = user.role == Role.admin and user.is_active and (new_role != Role.admin or not new_active)
    if removes_active_admin:
        other_admins = db.scalars(
            select(User.id)
            .where(User.role == Role.admin, User.is_active.is_(True), User.id != user.id)
            .with_for_update()
        ).all()
        if not other_admins:
            raise ConflictError("Refusing to remove the last active admin", code="last_admin")

    changes: dict[str, list] = {}
    if new_role != user.role:
        changes["role"] = [user.role.value, new_role.value]
        user.role = new_role
    if new_active != user.is_active:
        changes["is_active"] = [user.is_active, new_active]
        user.is_active = new_active

    if changes:
        revoked = revoke_all_refresh_tokens(db, user.id) if changes.get("is_active") == [True, False] else 0
        audit.record(db, actor_id=admin.id, action="user.update", target_type="user", target_id=str(user.id),
                     metadata={"changes": changes, "revoked_refresh_tokens": revoked})
        db.commit()
        db.refresh(user)
    return user
