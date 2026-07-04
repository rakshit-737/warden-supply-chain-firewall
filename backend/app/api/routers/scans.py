"""Scan routes — submit an analysis, browse history, dashboard stats."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.analysis.orchestrator import AnalysisResult, Orchestrator
from app.api.deps import require_analyst, require_viewer
from app.core.errors import NotFoundError
from app.db.models import Decision, Policy, Scan, Severity, Signal, User
from app.db.session import get_db
from app.policy.engine import evaluate
from app.schemas.common import Page
from app.schemas.scan import ScanOut, ScanRequest, ScanStats, ScanSummary
from app.services import audit

router = APIRouter(prefix="/scans", tags=["scans"])

_orchestrator = Orchestrator()


def _active_policy(db: Session) -> Policy | None:
    return db.scalar(select(Policy).where(Policy.is_active.is_(True)))


def _persist(db: Session, result: AnalysisResult, decision, user: User, policy: Policy | None) -> Scan:
    # Idempotent upsert: one authoritative verdict per (package, version, analyzer
    # version). A re-scan refreshes the existing row and its signals rather than
    # violating the uniqueness constraint.
    scan = db.scalar(
        select(Scan).where(
            Scan.ecosystem == result.ecosystem,
            Scan.package_name == result.name,
            Scan.version == result.version,
            Scan.analyzer_version == result.analyzer_version,
        )
    )
    if scan is None:
        scan = Scan(
            ecosystem=result.ecosystem,
            package_name=result.name,
            version=result.version,
            analyzer_version=result.analyzer_version,
        )
        db.add(scan)
    else:
        scan.signals.clear()
        db.flush()

    scan.requested_by = user.id
    scan.policy_id = policy.id if policy else None
    scan.rule_score = result.rule_score
    scan.ml_score = result.ml_score
    scan.risk_score = result.risk_score
    scan.severity = Severity(result.severity)
    scan.decision = decision.decision
    scan.feature_vector = result.features
    scan.matched_policy_rules = decision.matched_rules
    scan.duration_ms = result.duration_ms
    for s in result.signals:
        scan.signals.append(Signal(
            code=s["code"],
            severity=Severity(s["severity"]),
            weight=s["weight"],
            message=s["message"],
            evidence=s["evidence"],
        ))
    audit.record(
        db, actor_id=user.id, action="scan.create", target_type="package",
        target_id=f"{result.name}=={result.version}",
        metadata={"decision": decision.decision.value, "risk": result.risk_score},
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
) -> Scan:
    result = _orchestrator.analyze(payload.ecosystem, payload.name, payload.version)
    policy = _active_policy(db)
    decision = evaluate(result, policy)
    return _persist(db, result, decision, user, policy)


@router.get("", response_model=Page[ScanSummary])
def list_scans(
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    decision: Decision | None = None,
    severity: Severity | None = None,
    q: str | None = Query(None, max_length=214),
) -> Page[ScanSummary]:
    stmt = select(Scan)
    count_stmt = select(func.count(Scan.id))
    if decision:
        stmt = stmt.where(Scan.decision == decision)
        count_stmt = count_stmt.where(Scan.decision == decision)
    if severity:
        stmt = stmt.where(Scan.severity == severity)
        count_stmt = count_stmt.where(Scan.severity == severity)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(Scan.package_name).like(like))
        count_stmt = count_stmt.where(func.lower(Scan.package_name).like(like))

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[ScanSummary](
        items=[ScanSummary.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/stats/overview", response_model=ScanStats)
def stats(db: Session = Depends(get_db), _: User = Depends(require_viewer)) -> ScanStats:
    total = db.scalar(select(func.count(Scan.id))) or 0

    by_decision = {d.value: 0 for d in Decision}
    for decision_val, cnt in db.execute(
        select(Scan.decision, func.count(Scan.id)).group_by(Scan.decision)
    ):
        by_decision[decision_val.value] = cnt

    by_severity = {s.value: 0 for s in Severity}
    for sev_val, cnt in db.execute(
        select(Scan.severity, func.count(Scan.id)).group_by(Scan.severity)
    ):
        by_severity[sev_val.value] = cnt

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    blocked_30d = db.scalar(
        select(func.count(Scan.id)).where(
            Scan.decision == Decision.block, Scan.created_at >= cutoff
        )
    ) or 0

    avg_risk = db.scalar(select(func.avg(Scan.risk_score))) or 0.0

    top_signals = [
        {"code": code, "count": cnt}
        for code, cnt in db.execute(
            select(Signal.code, func.count(Signal.id))
            .group_by(Signal.code)
            .order_by(func.count(Signal.id).desc())
            .limit(8)
        )
    ]

    return ScanStats(
        total=total,
        by_decision=by_decision,
        by_severity=by_severity,
        blocked_last_30d=blocked_30d,
        avg_risk_score=round(float(avg_risk), 1),
        top_signals=top_signals,
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer),
) -> Scan:
    scan = db.scalar(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.signals))
    )
    if scan is None:
        raise NotFoundError("Scan not found")
    return scan
