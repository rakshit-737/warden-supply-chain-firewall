"""Container image scan routes.

``POST /containers/scans`` takes the image archive (``docker save`` or an OCI layout tarball) as the
raw request body (``application/octet-stream``, at most ``MAX_IMAGE_UPLOAD_BYTES``). Authorisation
is checked before the body is read. The image is analysed in memory (see
:mod:`app.containers.service`); scans run one at a time so concurrent uploads cannot multiply the
memory bound. The stored record keeps the summary, findings and the CycloneDX component list, not
the archive.
"""

from __future__ import annotations

import threading
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.api.deps import require_permission
from app.containers.service import scan_image
from app.core.config import settings
from app.core.errors import NotFoundError, WardenError
from app.core.permissions import Permission
from app.core.redaction import sanitize_text
from app.db.models import ContainerScan, User
from app.db.session import get_db
from app.events import bus as event_bus
from app.events.types import EventType
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.container import ContainerScanOut, ContainerScanSummary
from app.services import audit

router = APIRouter(prefix="/containers", tags=["containers"])

_scanner = require_permission(Permission.CONTAINER_SCAN)
_reader = require_permission(Permission.SCAN_READ)
_scan_lock = threading.Lock()

_SEVERITY_BY_DECISION = {"block": "high", "warn": "medium", "allow": "info"}


async def _read_body(request: Request) -> bytes:
    limit = int(settings.MAX_IMAGE_UPLOAD_BYTES)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise WardenError(f"Image archive larger than {limit} bytes", code="payload_too_large", status_code=413)
        chunks.append(chunk)
    if not size:
        raise WardenError("Send the image archive as the request body", code="validation_error", status_code=422)
    return b"".join(chunks)


@router.post("/scans", response_model=ContainerScanOut, status_code=201)
async def create_container_scan(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(_scanner),
    image_ref: str | None = Query(None, max_length=512, description="Label for the image (e.g. repo:tag)"),
    vulnerabilities: bool = Query(True, description="Run Trivy when it is installed"),
) -> ContainerScan:
    data = await _read_body(request)

    def run() -> Any:
        with _scan_lock:
            return scan_image(data, vulnerabilities=vulnerabilities, offline=bool(settings.INTEL_OFFLINE),
                              tool_version=__version__)

    result = await run_in_threadpool(run)
    report = result.report
    label = sanitize_text(image_ref or (report.image_refs[0] if report.image_refs else "uploaded-image"), max_len=512)
    row = ContainerScan(
        id=uuid.uuid4(), image_ref=label, image_digest=report.config_digest, requested_by=user.id,
        status="completed" if report.complete else "incomplete",
        tools={"trivy": result.vulnerability_scan.to_dict()},
        summary=result.summary(), findings=[f.to_dict() for f in result.findings], sbom=result.sbom,
        decision=result.decision, risk_score=result.risk_score,
    )
    db.add(row)
    db.flush()
    audit.record(db, actor_id=user.id, action="container.scan", target_type="image", target_id=label[:200],
                 metadata={"container_scan_id": str(row.id), "decision": result.decision,
                           "digest": report.config_digest, "complete": report.complete})
    event_bus.publish(db, EventType.CONTAINER_SCANNED, _SEVERITY_BY_DECISION[result.decision],
                      f"Image {label} scanned: {result.decision}",
                      details={"container_scan_id": str(row.id), "decision": result.decision,
                               "risk_score": result.risk_score, "findings": len(result.findings)})
    db.commit()
    db.refresh(row)
    return row


@router.get("/scans", response_model=Page[ContainerScanSummary])
def list_container_scans(
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
) -> Page[ContainerScanSummary]:
    total = db.scalar(select(func.count(ContainerScan.id))) or 0
    rows = db.scalars(select(ContainerScan).order_by(ContainerScan.created_at.desc()).limit(limit).offset(offset)).all()
    return Page[ContainerScanSummary](items=[ContainerScanSummary.model_validate(r) for r in rows], total=total,
                                      limit=limit, offset=offset)


@router.get("/scans/{scan_id}", response_model=ContainerScanOut)
def get_container_scan(scan_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(_reader)) -> ContainerScan:
    return _container_scan(db, scan_id)


@router.get("/scans/{scan_id}/sbom")
def get_container_sbom(scan_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(_reader)) -> dict:
    return _container_scan(db, scan_id).sbom or {}


def _container_scan(db: Session, scan_id: uuid.UUID) -> ContainerScan:
    row = db.get(ContainerScan, scan_id)
    if row is None:
        raise NotFoundError("Container scan not found")
    return row
