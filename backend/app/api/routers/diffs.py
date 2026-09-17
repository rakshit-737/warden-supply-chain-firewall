"""Release differential analysis routes.

``POST /diffs`` analyses both releases through the normal pipeline (verdict cache included) and
stores the comparison from :func:`app.analysis.diff.diff_results`. One row is kept per
(package, old version, new version, analyzer version); a repeated request refreshes it.

An ``escalated`` diff publishes ``behavior_drift_detected``; a newly declared maintainer
additionally publishes ``maintainer_changed``. Both are committed with the diff and its audit
record.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.analyzers.base import ScanOptions
from app.analysis.diff import diff_results
from app.analysis.orchestrator import Orchestrator
from app.api.deps import require_permission
from app.core.errors import NotFoundError
from app.core.permissions import Permission
from app.db.models import ReleaseDiff, User
from app.db.session import get_db
from app.events import bus as event_bus
from app.events.types import EventType
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.diff import DiffOut, DiffRequest, DiffSummary
from app.services import audit

router = APIRouter(prefix="/diffs", tags=["diffs"])

_orchestrator = Orchestrator()

_diff_creator = require_permission(Permission.DIFF_CREATE)
_diff_reader = require_permission(Permission.SCAN_READ)

_VERDICT_SEVERITY = {"escalated": "high", "reduced": "info", "unchanged": "info"}


@router.post("", response_model=DiffOut, status_code=201)
def create_diff(
    payload: DiffRequest,
    db: Session = Depends(get_db),
    user: User = Depends(_diff_creator),
) -> ReleaseDiff:
    options = ScanOptions()
    old = _orchestrator.analyze(payload.ecosystem, payload.name, payload.from_version, options)
    new = _orchestrator.analyze(payload.ecosystem, payload.name, payload.to_version, options)
    diff = diff_results(old, new)
    drift = diff["verdict"] == "escalated"

    row = db.scalar(select(ReleaseDiff).where(
        ReleaseDiff.ecosystem == payload.ecosystem,
        ReleaseDiff.package == new.name,
        ReleaseDiff.old_version == old.version,
        ReleaseDiff.new_version == new.version,
        ReleaseDiff.analyzer_version == new.analyzer_version,
    ))
    if row is None:
        row = ReleaseDiff(
            id=uuid.uuid4(), ecosystem=payload.ecosystem, package=new.name,
            old_version=old.version, new_version=new.version, analyzer_version=new.analyzer_version,
        )
        db.add(row)
    row.created_by = user.id
    row.drift_detected = drift
    row.drift_score = max(0, min(100, int(diff["risk"]["delta"])))
    row.summary = {k: v for k, v in diff.items() if k != "findings"}
    row.findings = diff["findings"]["added"]
    db.flush()

    ref = f"{new.name} {old.version} -> {new.version}"
    audit.record(
        db, actor_id=user.id, action="diff.create", target_type="package", target_id=ref,
        metadata={"verdict": diff["verdict"], "risk_delta": diff["risk"]["delta"]},
    )
    if drift:
        event_bus.publish(
            db, EventType.BEHAVIOR_DRIFT_DETECTED, _VERDICT_SEVERITY["escalated"], f"Behaviour drift: {ref}",
            package=new.name, version=new.version,
            details={"diff_id": str(row.id), "from_version": old.version, "reasons": diff["reasons"][:10]},
        )
    if diff["maintainers"].get("added"):
        event_bus.publish(
            db, EventType.MAINTAINER_CHANGED, "medium", f"Maintainers changed: {ref}",
            package=new.name, version=new.version,
            details={"diff_id": str(row.id), "added": diff["maintainers"]["added"][:20],
                     "removed": diff["maintainers"].get("removed", [])[:20]},
        )
    db.commit()
    db.refresh(row)
    return row


@router.get("", response_model=Page[DiffSummary])
def list_diffs(
    db: Session = Depends(get_db),
    _: User = Depends(_diff_reader),
    limit: int = Query(25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    package: str | None = Query(None, max_length=214),
    drift_only: bool = False,
) -> Page[DiffSummary]:
    filters = []
    if package:
        filters.append(ReleaseDiff.package == package.strip())
    if drift_only:
        filters.append(ReleaseDiff.drift_detected.is_(True))
    total = db.scalar(select(func.count(ReleaseDiff.id)).where(*filters)) or 0
    rows = db.scalars(
        select(ReleaseDiff).where(*filters).order_by(ReleaseDiff.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[DiffSummary](
        items=[DiffSummary.model_validate(r) for r in rows], total=total, limit=limit, offset=offset,
    )


@router.get("/{diff_id}", response_model=DiffOut)
def get_diff(
    diff_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(_diff_reader),
) -> ReleaseDiff:
    row = db.get(ReleaseDiff, diff_id)
    if row is None:
        raise NotFoundError("Diff not found")
    return row
