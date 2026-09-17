"""Vulnerability intelligence routes.

* ``GET /vulnerabilities`` - advisories found in stored verdicts, aggregated by advisory id, with
  the affected package versions. Database only.
* ``GET /vulnerabilities/lookup`` - a live lookup for one package version through the intelligence
  service (OSV, CISA KEV, FIRST EPSS, optional NVD). The response always carries the lookup
  ``status``; ``unavailable`` or ``partial`` means "not known", never "no vulnerabilities". Results
  are cached in ``vulnerability_records``.
* ``GET /vulnerabilities/{id}`` - one cached advisory record.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import require_permission
from app.core.errors import NotFoundError, WardenError
from app.core.permissions import Permission
from app.db.models import Scan, User, VulnerabilityRecord
from app.db.session import get_db
from app.schemas.common import MAX_PAGE_LIMIT
from app.schemas.scan import _PYPI_NAME_RE, _VERSION_RE

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

_reader = require_permission(Permission.VULN_READ)
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_SCANS_AGGREGATED = 5000


@router.get("")
def list_vulnerabilities(
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    kev: bool | None = None,
    min_severity: str = Query("unknown", pattern="^(unknown|low|medium|high|critical)$"),
    limit: int = Query(100, ge=1, le=MAX_PAGE_LIMIT),
) -> dict:
    floor = _SEVERITY_RANK[min_severity]
    advisories: dict[str, dict[str, Any]] = {}
    scans = db.scalars(select(Scan).where(Scan.vulnerabilities.is_not(None))
                       .order_by(Scan.created_at.desc()).limit(MAX_SCANS_AGGREGATED))
    for scan in scans:
        for vuln in scan.vulnerabilities or []:
            if not isinstance(vuln, dict) or not vuln.get("id"):
                continue
            severity = str(vuln.get("severity") or "unknown")
            if _SEVERITY_RANK.get(severity, 0) < floor or (kev is not None and bool(vuln.get("kev")) != kev):
                continue
            entry = advisories.setdefault(str(vuln["id"]), {
                "id": vuln["id"], "severity": severity, "cvss_score": vuln.get("cvss_score"),
                "kev": bool(vuln.get("kev")), "epss_score": vuln.get("epss_score"),
                "fixed_versions": vuln.get("fixed_versions") or [], "affected": set(),
            })
            entry["affected"].add((scan.package_name, scan.version))
    items = sorted(advisories.values(), key=lambda v: (-_SEVERITY_RANK.get(v["severity"], 0), not v["kev"], v["id"]))
    return {
        "total": len(items),
        "items": [{**v, "affected": [{"package": p, "version": ver} for p, ver in sorted(v["affected"])]}
                  for v in items[:limit]],
    }


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cache(db: Session, vulns: list[Any]) -> None:
    now = datetime.now(timezone.utc)
    for vuln in vulns:
        record = db.get(VulnerabilityRecord, vuln.id[:64]) or VulnerabilityRecord(id=vuln.id[:64])
        record.aliases = list(vuln.aliases)[:50]
        record.summary = (vuln.summary or "")[:2000] or None
        record.severity = vuln.severity
        record.cvss_score = vuln.cvss_score
        record.cvss_vector = (vuln.cvss_vector or "")[:200] or None
        record.kev = bool(vuln.kev)
        record.epss_score = vuln.epss_score
        record.published = _parse_time(vuln.published)
        record.modified = _parse_time(vuln.modified)
        record.data = vuln.to_dict(bounded=True)
        record.fetched_at = now
        db.add(record)
    db.commit()


@router.get("/lookup")
async def lookup(
    name: str = Query(min_length=1, max_length=214),
    version: str = Query(min_length=1, max_length=64),
    ecosystem: str = Query("pypi", pattern="^pypi$"),
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
) -> dict:
    from app.intel.service import get_intel_service  # imported lazily: builds network clients

    if not _PYPI_NAME_RE.match(name) or not _VERSION_RE.match(version):
        raise WardenError("Invalid package name or version", code="validation_error", status_code=422)
    result = await run_in_threadpool(get_intel_service().package_vulnerabilities, ecosystem, name, version)
    if result.vulnerabilities:
        _cache(db, result.vulnerabilities)
    return result.to_dict()


@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db), _: User = Depends(_reader)) -> dict:
    record = db.get(VulnerabilityRecord, vuln_id[:64])
    if record is None:
        raise NotFoundError("Advisory not in the local cache (use /vulnerabilities/lookup first)")
    return {
        "id": record.id, "aliases": record.aliases or [], "summary": record.summary, "severity": record.severity,
        "cvss_score": record.cvss_score, "cvss_vector": record.cvss_vector, "kev": record.kev,
        "epss_score": record.epss_score, "published": record.published, "modified": record.modified,
        "fetched_at": record.fetched_at, "data": record.data,
    }
