"""Policy management routes (admin-only mutations)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_viewer
from app.core.errors import NotFoundError
from app.db.models import Policy, User
from app.db.session import get_db
from app.schemas.policy import PolicyCreate, PolicyOut, PolicyUpdate
from app.services import audit

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db), _: User = Depends(require_viewer)) -> list[Policy]:
    return db.scalars(select(Policy).order_by(Policy.created_at.desc())).all()


@router.get("/active", response_model=PolicyOut)
def active_policy(db: Session = Depends(get_db), _: User = Depends(require_viewer)) -> Policy:
    policy = db.scalar(select(Policy).where(Policy.is_active.is_(True)))
    if policy is None:
        raise NotFoundError("No active policy configured")
    return policy


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Policy:
    policy = Policy(**payload.model_dump(), updated_at=datetime.now(timezone.utc))
    db.add(policy)
    audit.record(db, actor_id=admin.id, action="policy.create", target_type="policy",
                 target_id=payload.name)
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: uuid.UUID,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise NotFoundError("Policy not found")
    for k, v in payload.model_dump().items():
        setattr(policy, k, v)
    policy.updated_at = datetime.now(timezone.utc)
    audit.record(db, actor_id=admin.id, action="policy.update", target_type="policy",
                 target_id=str(policy_id))
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/{policy_id}/activate", response_model=PolicyOut)
def activate_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise NotFoundError("Policy not found")
    # Exactly one active policy at a time.
    db.execute(update(Policy).values(is_active=False))
    policy.is_active = True
    policy.updated_at = datetime.now(timezone.utc)
    audit.record(db, actor_id=admin.id, action="policy.activate", target_type="policy",
                 target_id=str(policy_id))
    db.commit()
    db.refresh(policy)
    return policy
