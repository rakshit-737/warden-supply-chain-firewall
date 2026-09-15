"""Scan routes — submit an analysis, browse history, dashboard stats.

Persistence tolerates both v1 and Warden X analysis results: new ``AnalysisResult`` fields
are read with ``getattr`` defaults and new finding keys with ``dict.get`` defaults, and
string values are clipped to their column sizes so an oversized value can never fail the
insert on PostgreSQL.

Every scan publishes ``package_scanned``; a ``warn`` or ``block`` decision additionally
publishes ``policy_violation``, and a ``block`` publishes ``package_blocked``. Events are
committed in the same transaction as the scan.

Policy selection: the active policy of the requested environment; when that environment
has none, the active *production* policy (usually the strictest) is used rather than the
permissive built-in default; with no active policy at all the engine's default applies.

Verdicts are stored per environment: the upsert key is (ecosystem, package, version, analyzer
version, environment), so a re-scan under one environment's policy never overwrites the
decision recorded for another (a developer scanning under a permissive ``development`` policy
cannot turn a ``production`` block into an allow). ``/scans`` listings and statistics count
verdicts, i.e. one row per environment a package version was evaluated for.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.analysis.analyzers.base import ScanOptions
from app.analysis.orchestrator import AnalysisResult, Orchestrator
from app.api.deps import require_permission
from app.core import metrics
from app.core.errors import NotFoundError, WardenError
from app.core.permissions import Permission
from app.db.models import DEFAULT_ENVIRONMENT, Decision, Policy, Scan, Severity, Signal, User
from app.db.session import get_db
from app.events import bus as event_bus
from app.events.types import EventType, max_severity
from app.policy.engine import evaluate
from app.schemas.common import MAX_PAGE_LIMIT, Page, escape_like
from app.schemas.scan import ScanOut, ScanRequest, ScanStats, ScanSummary, validate_environment
from app.services import audit

router = APIRouter(prefix="/scans", tags=["scans"])

_orchestrator = Orchestrator()

_scan_reader = require_permission(Permission.SCAN_READ)
_scan_creator = require_permission(Permission.SCAN_CREATE)


def _active_policy(db: Session, environment: str = DEFAULT_ENVIRONMENT) -> Policy | None:
    policy = db.scalar(select(Policy).where(Policy.is_active.is_(True), Policy.environment == environment))
    if policy is None and environment != DEFAULT_ENVIRONMENT:
        policy = db.scalar(
            select(Policy).where(Policy.is_active.is_(True), Policy.environment == DEFAULT_ENVIRONMENT)
        )
    return policy


# --------------------------------------------------------------------------- value coercion
def _clip(value: Any, size: int) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:size]


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return int(value)


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _dict_or_none(value: Any) -> dict | None:
    return value if isinstance(value, dict) else None


def _list_or_none(value: Any) -> list | None:
    if isinstance(value, (list, tuple)):
        return list(value)
    return None


def _signal_row(s: dict) -> Signal:
    return Signal(
        code=_clip(s["code"], 64),
        severity=Severity(s["severity"]),
        weight=_as_float(s.get("weight")) or 0.0,
        message=_clip(s.get("message", ""), 500) or "",
        evidence=s.get("evidence") or {},
        finding_id=_clip(s.get("finding_id"), 32),
        confidence=_as_float(s.get("confidence")),
        category=_clip(s.get("category"), 40),
        title=_clip(s.get("title"), 160),
        analyzer=_clip(s.get("analyzer"), 64),
        analyzer_version=_clip(s.get("analyzer_version"), 20),
        capability=_clip(s.get("capability"), 64),
        location=_dict_or_none(s.get("location")),
        cwe=_list_or_none(s.get("cwe")),
        attack=_list_or_none(s.get("attack")),
        remediation=s.get("remediation") if isinstance(s.get("remediation"), str) else None,
        references=_list_or_none(s.get("references")),
        provenance=_clip(s.get("provenance"), 64),
        related=_list_or_none(s.get("related")),
    )


def _apply_result(scan: Scan, result: AnalysisResult, decision: Any, environment: str) -> None:
    risk = getattr(result, "risk", None)
    risk = risk if isinstance(risk, dict) else None
    scan.rule_score = result.rule_score
    scan.ml_score = result.ml_score
    scan.risk_score = result.risk_score
    scan.severity = Severity(result.severity)
    scan.decision = decision.decision
    scan.feature_vector = result.features
    scan.matched_policy_rules = decision.matched_rules
    scan.duration_ms = result.duration_ms
    scan.environment = environment
    scan.risk = risk
    scan.attack_chains = _list_or_none(getattr(result, "attack_chains", None))
    scan.analyzer_runs = _list_or_none(getattr(result, "analyzer_runs", None))
    scan.package_intel = _dict_or_none(getattr(result, "package_intel", None))
    scan.provenance = _dict_or_none(getattr(result, "provenance", None))
    scan.vulnerabilities = _list_or_none(getattr(result, "vulnerabilities", None))
    scan.intel_status = _dict_or_none(getattr(result, "intel_status", None))
    scan.model_version = _clip(getattr(result, "model_version", None), 64)
    scan.explanation = _dict_or_none(getattr(result, "explanation", None))
    scan.scan_options = _dict_or_none(getattr(result, "scan_options", None))
    scan.policy_reasons = _list_or_none(getattr(decision, "reasons", None)) or []
    malicious = _as_int((risk or {}).get("malicious_risk"))
    scan.malicious_risk = malicious if malicious is not None else result.risk_score
    scan.vulnerability_risk = _as_int((risk or {}).get("vulnerability_risk"))


def _publish_scan_events(db: Session, scan: Scan, result: AnalysisResult, decision: Any, environment: str) -> None:
    ref = f"{result.name}=={result.version}"
    verdict = decision.decision.value
    common = {
        "decision": verdict,
        "risk_score": result.risk_score,
        "environment": environment,
        "policy_id": str(scan.policy_id) if scan.policy_id else None,
        "cached": bool(getattr(result, "cached", False)),
    }
    event_bus.publish(
        db, EventType.PACKAGE_SCANNED, result.severity, f"Scanned {ref}: {verdict}",
        package=result.name, version=result.version, scan_id=scan.id, details=common,
    )
    if decision.decision in (Decision.warn, Decision.block):
        floor = "high" if decision.decision == Decision.block else "medium"
        event_bus.publish(
            db, EventType.POLICY_VIOLATION, max_severity(result.severity, floor), f"Policy {verdict} for {ref}",
            package=result.name, version=result.version, scan_id=scan.id,
            details={**common, "matched_rules": list(decision.matched_rules)},
        )
    if decision.decision == Decision.block:
        event_bus.publish(
            db, EventType.PACKAGE_BLOCKED, max_severity(result.severity, "high"), f"Blocked {ref}",
            package=result.name, version=result.version, scan_id=scan.id,
            details={**common, "matched_rules": list(decision.matched_rules)},
        )


def _persist(
    db: Session,
    result: AnalysisResult,
    decision,
    user: User,
    policy: Policy | None,
    environment: str = DEFAULT_ENVIRONMENT,
) -> Scan:
    # Idempotent upsert: one authoritative verdict per (package, version, analyzer version,
    # environment). A re-scan refreshes the existing row of *that* environment and its signals
    # rather than violating the uniqueness constraint or touching other environments' verdicts.
    scan = db.scalar(
        select(Scan).where(
            Scan.ecosystem == result.ecosystem,
            Scan.package_name == result.name,
            Scan.version == result.version,
            Scan.analyzer_version == result.analyzer_version,
            Scan.environment == environment,
        )
    )
    if scan is None:
        scan = Scan(
            id=uuid.uuid4(),
            ecosystem=result.ecosystem,
            package_name=result.name,
            version=result.version,
            analyzer_version=result.analyzer_version,
            environment=environment,
        )
        db.add(scan)
    else:
        scan.signals.clear()
        db.flush()

    scan.requested_by = user.id
    scan.policy_id = policy.id if policy else None
    _apply_result(scan, result, decision, environment)
    for s in result.signals:
        scan.signals.append(_signal_row(s))
    audit.record(
        db, actor_id=user.id, action="scan.create", target_type="package",
        target_id=f"{result.name}=={result.version}",
        metadata={"decision": decision.decision.value, "risk": result.risk_score, "environment": environment},
    )
    _publish_scan_events(db, scan, result, decision, environment)
    db.commit()
    # Metrics only after the verdict is durable (the helpers never raise).
    metrics.observe_scan(decision.decision.value, result.ecosystem, (result.duration_ms or 0) / 1000.0)
    metrics.inc_policy(decision.decision.value, environment)
    db.refresh(scan)
    return scan


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(_scan_creator),
) -> Scan:
    environment = payload.environment or DEFAULT_ENVIRONMENT
    options = ScanOptions(environment=environment)
    result = _orchestrator.analyze(payload.ecosystem, payload.name, payload.version, options)
    policy = _active_policy(db, environment)
    decision = evaluate(result, policy)
    return _persist(db, result, decision, user, policy, environment)


@router.get("", response_model=Page[ScanSummary])
def list_scans(
    db: Session = Depends(get_db),
    _: User = Depends(_scan_reader),
    limit: int = Query(25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    decision: Decision | None = None,
    severity: Severity | None = None,
    q: str | None = Query(None, max_length=214),
    environment: str | None = Query(None, max_length=20),
) -> Page[ScanSummary]:
    filters = []
    if decision:
        filters.append(Scan.decision == decision)
    if severity:
        filters.append(Scan.severity == severity)
    if q:
        # User input is matched literally: LIKE wildcards in q are escaped.
        filters.append(func.lower(Scan.package_name).like(f"%{escape_like(q.lower())}%", escape="\\"))
    if environment:
        try:
            filters.append(Scan.environment == validate_environment(environment))
        except ValueError as exc:
            raise WardenError(str(exc), code="validation_error", status_code=422) from exc

    total = db.scalar(select(func.count(Scan.id)).where(*filters)) or 0
    rows = db.scalars(
        select(Scan).where(*filters).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[ScanSummary](
        items=[ScanSummary.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/stats/overview", response_model=ScanStats)
def stats(db: Session = Depends(get_db), _: User = Depends(_scan_reader)) -> ScanStats:
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
    _: User = Depends(_scan_reader),
) -> Scan:
    scan = db.scalar(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.signals))
    )
    if scan is None:
        raise NotFoundError("Scan not found")
    return scan
