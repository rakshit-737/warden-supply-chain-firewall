"""Continuous dependency monitoring routes.

Watching a package, changing its baseline and running a check on demand are security operations
(``monitor:write``); every role can read the watch list (``monitor:read``). Checks normally run in the
monitoring worker (``python -m app.workers.monitor``); ``POST /monitoring/packages/{id}/check`` runs
one immediately, in the request, with the same code.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import require_permission
from app.core.errors import NotFoundError, WardenError
from app.core.permissions import Permission
from app.db.models import MonitoredPackage, Project, User
from app.db.session import get_db
from app.monitoring import service as monitoring
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.monitoring import CheckResultOut, MonitoredPackageCreate, MonitoredPackageOut, MonitoredPackageUpdate
from app.services import audit

router = APIRouter(prefix="/monitoring", tags=["monitoring"])

_reader = require_permission(Permission.MONITOR_READ)
_writer = require_permission(Permission.MONITOR_WRITE)


def _row(db: Session, package_id: uuid.UUID) -> MonitoredPackage:
    row = db.get(MonitoredPackage, package_id)
    if row is None:
        raise NotFoundError("Monitored package not found")
    return row


@router.post("/packages", response_model=MonitoredPackageOut, status_code=201)
def watch_package(payload: MonitoredPackageCreate, db: Session = Depends(get_db),
                  user: User = Depends(_writer)) -> MonitoredPackage:
    if payload.project_id is not None and db.get(Project, payload.project_id) is None:
        raise NotFoundError("Project not found")
    duplicate = db.scalar(select(MonitoredPackage).where(
        MonitoredPackage.ecosystem == payload.ecosystem, MonitoredPackage.name == payload.name,
        MonitoredPackage.project_id.is_(None) if payload.project_id is None
        else MonitoredPackage.project_id == payload.project_id,
    ))
    if duplicate is not None:
        raise WardenError("This package is already monitored", code="conflict", status_code=409)
    row = MonitoredPackage(id=uuid.uuid4(), ecosystem=payload.ecosystem, name=payload.name,
                           approved_version=payload.approved_version,
                           poll_interval_seconds=payload.poll_interval_seconds, project_id=payload.project_id,
                           created_by=user.id, enabled=True)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise WardenError("This package is already monitored", code="conflict", status_code=409) from exc
    audit.record(db, actor_id=user.id, action="monitor.create", target_type="package", target_id=row.name,
                 metadata={"monitored_package_id": str(row.id), "approved_version": row.approved_version})
    db.commit()
    db.refresh(row)
    return row


@router.get("/packages", response_model=Page[MonitoredPackageOut])
def list_watched(
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    failing: bool = False,
) -> Page[MonitoredPackageOut]:
    filters = [MonitoredPackage.consecutive_failures > 0] if failing else []
    total = db.scalar(select(func.count(MonitoredPackage.id)).where(*filters)) or 0
    rows = db.scalars(select(MonitoredPackage).where(*filters).order_by(MonitoredPackage.name)
                      .limit(limit).offset(offset)).all()
    return Page[MonitoredPackageOut](items=[MonitoredPackageOut.model_validate(r) for r in rows], total=total,
                                     limit=limit, offset=offset)


@router.get("/packages/{package_id}", response_model=MonitoredPackageOut)
def get_watched(package_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(_reader)) -> MonitoredPackage:
    return _row(db, package_id)


@router.patch("/packages/{package_id}", response_model=MonitoredPackageOut)
def update_watched(package_id: uuid.UUID, payload: MonitoredPackageUpdate, db: Session = Depends(get_db),
                   user: User = Depends(_writer)) -> MonitoredPackage:
    row = _row(db, package_id)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "enabled" and value is None:
            continue
        setattr(row, key, value)
    if changes.get("enabled") or "poll_interval_seconds" in changes:
        row.next_check_at = None  # re-evaluate on the next worker cycle
    audit.record(db, actor_id=user.id, action="monitor.update", target_type="package", target_id=row.name,
                 metadata={"monitored_package_id": str(row.id), "changes": sorted(changes)})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/packages/{package_id}", status_code=204)
def unwatch(package_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(_writer)) -> None:
    row = _row(db, package_id)
    audit.record(db, actor_id=user.id, action="monitor.delete", target_type="package", target_id=row.name,
                 metadata={"monitored_package_id": str(row.id)})
    db.delete(row)
    db.commit()


@router.post("/packages/{package_id}/check", response_model=CheckResultOut)
async def check_now(package_id: uuid.UUID, db: Session = Depends(get_db),
                    user: User = Depends(_writer)) -> CheckResultOut:
    row = _row(db, package_id)
    outcome = await run_in_threadpool(monitoring.check_package, db, row)
    audit.record(db, actor_id=user.id, action="monitor.check", target_type="package", target_id=outcome.package,
                 metadata={"status": outcome.status, "version": outcome.version})
    db.commit()
    return CheckResultOut(package=outcome.package, status=outcome.status, version=outcome.version,
                          diff_id=outcome.diff_id, detail=outcome.detail)
