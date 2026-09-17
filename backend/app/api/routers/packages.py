"""Package intelligence: everything Warden has stored about one package.

``GET /packages/{ecosystem}/{name}`` combines the stored verdicts (one row per version and policy
environment), the monitoring state and the release diffs for the package. It reads the database
only; nothing is fetched. Package names are compared in PEP 503 normalised form.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.errors import NotFoundError
from app.core.permissions import Permission
from app.db.models import MonitoredPackage, ReleaseDiff, Scan, User
from app.db.session import get_db
from app.schemas.common import MAX_PAGE_LIMIT

router = APIRouter(prefix="/packages", tags=["packages"])

_reader = require_permission(Permission.SCAN_READ)
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _canonical_sql(column):  # noqa: ANN001, ANN202 - SQLAlchemy expression helper
    return func.lower(func.replace(func.replace(column, "_", "-"), ".", "-"))


@router.get("/{ecosystem}/{name}")
def package_overview(
    ecosystem: str = Path(pattern="^pypi$"),
    name: str = Path(pattern=_NAME_PATTERN),
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
) -> dict:
    canonical = normalize(name)
    scans = db.scalars(
        select(Scan).where(Scan.ecosystem == ecosystem, _canonical_sql(Scan.package_name) == canonical)
        .order_by(Scan.created_at.desc()).limit(limit)
    ).all()
    monitored = db.scalars(
        select(MonitoredPackage).where(MonitoredPackage.ecosystem == ecosystem,
                                       _canonical_sql(MonitoredPackage.name) == canonical)
    ).all()
    diffs = db.scalars(
        select(ReleaseDiff).where(ReleaseDiff.ecosystem == ecosystem, _canonical_sql(ReleaseDiff.package) == canonical)
        .order_by(ReleaseDiff.created_at.desc()).limit(limit)
    ).all()
    if not scans and not monitored and not diffs:
        raise NotFoundError("Warden has no data for this package")

    latest = scans[0] if scans else None
    advisories: dict[str, dict] = {}
    for scan in scans:
        for vuln in scan.vulnerabilities or []:
            if isinstance(vuln, dict) and vuln.get("id"):
                entry = advisories.setdefault(str(vuln["id"]), {"id": vuln["id"], "severity": vuln.get("severity"),
                                                                "kev": bool(vuln.get("kev")), "versions": set()})
                entry["versions"].add(scan.version)
    return {
        "ecosystem": ecosystem,
        "name": latest.package_name if latest else (monitored[0].name if monitored else diffs[0].package),
        "latest_verdict": None if latest is None else {
            "scan_id": str(latest.id), "version": latest.version, "environment": latest.environment,
            "decision": latest.decision.value, "risk_score": latest.risk_score, "severity": latest.severity.value,
            "scanned_at": latest.created_at, "package_intel": latest.package_intel, "provenance": latest.provenance,
        },
        "verdicts": [{
            "scan_id": str(s.id), "version": s.version, "environment": s.environment, "decision": s.decision.value,
            "risk_score": s.risk_score, "severity": s.severity.value, "scanned_at": s.created_at,
        } for s in scans],
        "vulnerabilities": sorted(({**v, "versions": sorted(v["versions"])} for v in advisories.values()),
                                  key=lambda v: v["id"]),
        "monitoring": [{
            "id": str(m.id), "enabled": m.enabled, "approved_version": m.approved_version,
            "latest_seen_version": m.latest_seen_version, "last_checked_at": m.last_checked_at,
            "consecutive_failures": m.consecutive_failures, "project_id": str(m.project_id) if m.project_id else None,
        } for m in monitored],
        "release_diffs": [{
            "id": str(d.id), "old_version": d.old_version, "new_version": d.new_version,
            "drift_detected": d.drift_detected, "drift_score": d.drift_score, "created_at": d.created_at,
        } for d in diffs],
    }
