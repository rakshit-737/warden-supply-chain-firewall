"""Monitoring checks for :class:`~app.db.models.MonitoredPackage` rows.

One check of a watched package:

1. look up the latest release on the registry;
2. when it differs from the last version seen, analyse it with the normal pipeline (the verdict
   cache applies) and compare it with the baseline - the approved version when one is set, otherwise
   the previously seen version - using :func:`app.analysis.diff.diff_results`;
3. store the comparison as a :class:`~app.db.models.ReleaseDiff`, update the row's snapshot and
   publish events: ``new_release_detected`` always, ``behavior_drift_detected`` for an escalated
   diff, ``risk_increased`` / ``risk_decreased`` for a score change of at least
   :data:`RISK_CHANGE_THRESHOLD`, and ``maintainer_changed`` for newly declared maintainers;
4. schedule the next check (``poll_interval_seconds`` plus a small jitter).

A failed check never looks like "no news": ``consecutive_failures`` grows, the next attempt backs off
exponentially (capped at the poll interval), and ``monitor_error`` is published on the first failure
and again every :data:`ERROR_EVENT_EVERY` failures. The first successful check of a new row only
records a baseline.
"""

from __future__ import annotations

import random
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.analysis.diff import diff_results
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text
from app.db.models import MonitoredPackage, ReleaseDiff
from app.events import bus as event_bus
from app.events.types import EventType

log = get_logger("warden.monitoring")

RISK_CHANGE_THRESHOLD = 10
ERROR_EVENT_EVERY = 5
MIN_RETRY_SECONDS = 60
CLAIM_LEASE_SECONDS = 900

LatestVersion = Callable[[str, str], str]
Analyze = Callable[[str, str, str], Any]


@dataclass
class CheckOutcome:
    package: str
    status: str  # baseline | unchanged | new_release | error
    version: str | None = None
    diff_id: uuid.UUID | None = None
    detail: str | None = None


def _as_dict(result: Any) -> dict:
    return asdict(result) if is_dataclass(result) and not isinstance(result, type) else dict(result)


def default_latest_version(ecosystem: str, name: str) -> str:
    from app.analysis.acquisition.pypi import PyPIClient, bounded_str

    if ecosystem != "pypi":
        raise ValueError(f"unsupported ecosystem {ecosystem!r}")
    client = PyPIClient()
    try:
        version = bounded_str(client.project(name)["info"].get("version"), 64)
    finally:
        client.close()
    if not version:
        raise ValueError("registry did not report a latest version")
    return version


def default_analyze(ecosystem: str, name: str, version: str) -> Any:
    from app.analysis.orchestrator import Orchestrator

    return Orchestrator().analyze(ecosystem, name, version)


def _snapshot(result: dict) -> dict:
    return {
        "version": result.get("version"),
        "risk_score": result.get("risk_score"),
        "severity": result.get("severity"),
        "capabilities": list(result.get("capabilities") or [])[:50],
        "analyzer_version": result.get("analyzer_version"),
    }


def _schedule(row: MonitoredPackage, now: datetime, rng: random.Random) -> None:
    interval = max(MIN_RETRY_SECONDS, int(row.poll_interval_seconds or settings.MONITOR_POLL_INTERVAL_SECONDS))
    jitter = rng.randint(0, max(0, int(settings.MONITOR_JITTER_SECONDS)))
    if row.consecutive_failures:
        delay = min(interval, MIN_RETRY_SECONDS * 2 ** min(row.consecutive_failures - 1, 16))
    else:
        delay = interval
    row.next_check_at = now + timedelta(seconds=delay + jitter)


def check_package(
    db: Session,
    row: MonitoredPackage,
    *,
    now: datetime | None = None,
    latest_version: LatestVersion = default_latest_version,
    analyze: Analyze = default_analyze,
    rng: random.Random | None = None,
) -> CheckOutcome:
    """Run one check and commit it. Never raises for registry or analysis problems."""
    now = now or datetime.now(timezone.utc)
    rng = rng or random.Random()  # nosec B311 - scheduling jitter, not security relevant
    name = row.name
    try:
        latest = latest_version(row.ecosystem, name)
        previous_seen = row.latest_seen_version
        if previous_seen == latest and row.snapshot:
            outcome = CheckOutcome(name, "unchanged", latest)
        else:
            new_result = _as_dict(analyze(row.ecosystem, name, latest))
            baseline_version = row.approved_version or previous_seen
            outcome = CheckOutcome(name, "baseline" if previous_seen is None else "new_release", latest)
            if previous_seen is not None and baseline_version != latest:
                old_result = _as_dict(analyze(row.ecosystem, name, baseline_version))
                diff = diff_results(old_result, new_result)
                outcome.diff_id = _record_diff(db, row, diff, old_result, new_result)
                _publish(db, row, diff, previous_seen, latest, outcome.diff_id)
            elif previous_seen is not None:
                # The new release is the approved one: nothing to compare against.
                event_bus.publish(db, EventType.NEW_RELEASE_DETECTED, "info", f"New release {name} {latest}",
                                  package=name, version=latest, project_id=row.project_id,
                                  details={"monitored_package_id": str(row.id), "previous_version": previous_seen,
                                           "approved": True})
            row.snapshot = _snapshot(new_result)
            row.last_risk_score = new_result.get("risk_score")
            row.latest_seen_version = latest
    except Exception as exc:  # any registry / analysis failure is recorded, never swallowed silently
        db.rollback()
        row = db.get(MonitoredPackage, row.id) or row
        row.consecutive_failures = (row.consecutive_failures or 0) + 1
        detail = sanitize_text(f"{type(exc).__name__}: {exc}", max_len=200)
        log.warning("monitor_check_failed", package=name, error_type=type(exc).__name__,
                    failures=row.consecutive_failures)
        if row.consecutive_failures == 1 or row.consecutive_failures % ERROR_EVENT_EVERY == 0:
            event_bus.publish(db, EventType.MONITOR_ERROR, "medium", f"Monitoring check failed for {name}",
                              package=name, project_id=row.project_id,
                              details={"monitored_package_id": str(row.id), "error_type": type(exc).__name__,
                                       "consecutive_failures": row.consecutive_failures})
        row.last_checked_at = now
        _schedule(row, now, rng)
        db.commit()
        return CheckOutcome(name, "error", detail=detail)

    row.consecutive_failures = 0
    row.last_checked_at = now
    _schedule(row, now, rng)
    db.commit()
    return outcome


def _record_diff(db: Session, row: MonitoredPackage, diff: dict, old: dict, new: dict) -> uuid.UUID:
    analyzer_version = str(new.get("analyzer_version") or "unknown")[:20]
    record = db.scalar(select(ReleaseDiff).where(
        ReleaseDiff.ecosystem == row.ecosystem, ReleaseDiff.package == row.name,
        ReleaseDiff.old_version == str(old.get("version")), ReleaseDiff.new_version == str(new.get("version")),
        ReleaseDiff.analyzer_version == analyzer_version,
    ))
    if record is None:
        record = ReleaseDiff(id=uuid.uuid4(), ecosystem=row.ecosystem, package=row.name,
                             old_version=str(old.get("version")), new_version=str(new.get("version")),
                             analyzer_version=analyzer_version)
        db.add(record)
    record.drift_detected = diff["verdict"] == "escalated"
    record.drift_score = max(0, min(100, int(diff["risk"]["delta"])))
    record.summary = {k: v for k, v in diff.items() if k != "findings"}
    record.findings = diff["findings"]["added"]
    db.flush()
    return record.id


def _publish(db: Session, row: MonitoredPackage, diff: dict, previous: str | None, latest: str,
             diff_id: uuid.UUID) -> None:
    common = {"monitored_package_id": str(row.id), "diff_id": str(diff_id), "previous_version": previous,
              "baseline_version": diff["from_version"]}
    kwargs = {"package": row.name, "version": latest, "project_id": row.project_id}
    event_bus.publish(db, EventType.NEW_RELEASE_DETECTED, "info", f"New release {row.name} {latest}",
                      details=common, **kwargs)
    if diff["verdict"] == "escalated":
        event_bus.publish(db, EventType.BEHAVIOR_DRIFT_DETECTED, "high", f"Behaviour drift in {row.name} {latest}",
                          details={**common, "reasons": diff["reasons"][:10]}, **kwargs)
    delta = diff["risk"]["delta"]
    if delta >= RISK_CHANGE_THRESHOLD:
        event_bus.publish(db, EventType.RISK_INCREASED, "medium", f"Risk of {row.name} rose by {delta}",
                          details={**common, "from": diff["risk"]["from"], "to": diff["risk"]["to"]}, **kwargs)
    elif delta <= -RISK_CHANGE_THRESHOLD:
        event_bus.publish(db, EventType.RISK_DECREASED, "info", f"Risk of {row.name} fell by {-delta}",
                          details={**common, "from": diff["risk"]["from"], "to": diff["risk"]["to"]}, **kwargs)
    if diff["maintainers"].get("added"):
        event_bus.publish(db, EventType.MAINTAINER_CHANGED, "medium", f"Maintainers changed for {row.name}",
                          details={**common, "added": diff["maintainers"]["added"][:20]}, **kwargs)


def claim_due(db: Session, now: datetime, limit: int) -> list[uuid.UUID]:
    """Claim up to ``limit`` due rows by pushing their next check out by :data:`CLAIM_LEASE_SECONDS`.

    The claim is committed before any check runs, so a second worker (or a crashed one) cannot pick
    the same row until the lease expires; on PostgreSQL the claim query also skips rows another
    worker is claiming at the same moment.
    """
    stmt = (
        select(MonitoredPackage)
        .where(MonitoredPackage.enabled.is_(True),
               or_(MonitoredPackage.next_check_at.is_(None), MonitoredPackage.next_check_at <= now))
        .order_by(MonitoredPackage.next_check_at.asc().nullsfirst(), MonitoredPackage.name)
        .limit(limit)
    )
    if db.get_bind().dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    rows = list(db.scalars(stmt))
    for row in rows:
        row.next_check_at = now + timedelta(seconds=CLAIM_LEASE_SECONDS)
    db.commit()
    return [row.id for row in rows]


def run_due(db: Session, *, now: datetime | None = None, limit: int | None = None, **kwargs: Any) -> list[CheckOutcome]:
    now = now or datetime.now(timezone.utc)
    outcomes = []
    for row_id in claim_due(db, now, limit or int(settings.MONITOR_BATCH_SIZE)):
        row = db.get(MonitoredPackage, row_id)
        if row is not None and row.enabled:
            outcomes.append(check_package(db, row, now=now, **kwargs))
    return outcomes
