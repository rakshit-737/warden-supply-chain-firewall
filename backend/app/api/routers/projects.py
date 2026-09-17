"""Project routes: manifest inventory, dependency hygiene, dependency confusion, graph and SBOM.

A project scan takes manifest files in the request body (``{path: text}``, bounded by
:mod:`app.schemas.project`). Nothing is fetched and nothing is executed: the manifests are parsed
with the same engine the ``warden project scan`` CLI uses, and Dockerfiles / Compose files among
the submitted files are linted (:mod:`app.containers.dockerfile`).

Components are enriched with the most recent stored package verdict for the same name and version
in the scan's environment (``scans`` table), when one exists; components without a verdict keep
``risk_score`` / ``decision`` empty rather than looking clean.

The project decision is derived from the project-level findings: ``block`` for a high or
critical finding, ``warn`` for a medium one, otherwise ``allow``, raised to the worst stored
component decision. ``risk_score`` is the highest known component risk, or the severity floor of
the worst project finding when that is higher.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import __version__
from app.analysis.depconf.project import project_confusion_findings
from app.api.deps import require_permission
from app.containers.dockerfile import is_compose_file, is_dockerfile
from app.containers.dockerfile import lint_files as lint_container_files
from app.core.errors import NotFoundError, WardenError
from app.core.permissions import Permission
from app.db.models import (
    DEFAULT_ENVIRONMENT,
    DependencyEdge,
    Project,
    ProjectComponent,
    ProjectScan,
    Scan,
    User,
)
from app.db.session import get_db
from app.events import bus as event_bus
from app.events.types import EventType
from app.graph.engine import build_graph
from app.sbom import build_cyclonedx, build_spdx, hygiene_findings, parse_project
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.project import (
    ComponentOut,
    ProjectCreate,
    ProjectOut,
    ProjectScanOut,
    ProjectScanRequest,
    ProjectScanSummary,
)
from app.services import audit

router = APIRouter(prefix="/projects", tags=["projects"])

_reader = require_permission(Permission.PROJECT_READ)
_writer = require_permission(Permission.PROJECT_WRITE)

_DECISION_RANK = {"allow": 0, "warn": 1, "block": 2}
_SEVERITY_FLOOR = {"info": 0, "low": 15, "medium": 35, "high": 60, "critical": 80}


def _project(db: Session, project_id: uuid.UUID) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError("Project not found")
    return project


def _project_scan(db: Session, project_id: uuid.UUID, scan_id: uuid.UUID) -> ProjectScan:
    row = db.get(ProjectScan, scan_id)
    if row is None or row.project_id != project_id:
        raise NotFoundError("Project scan not found")
    return row


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(_writer)) -> Project:
    project = Project(id=uuid.uuid4(), name=payload.name, description=payload.description, created_by=user.id)
    db.add(project)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise WardenError("A project with this name already exists", code="conflict", status_code=409) from exc
    audit.record(db, actor_id=user.id, action="project.create", target_type="project", target_id=str(project.id),
                 metadata={"name": project.name})
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=Page[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
) -> Page[ProjectOut]:
    total = db.scalar(select(func.count(Project.id))) or 0
    rows = db.scalars(select(Project).order_by(Project.name).limit(limit).offset(offset)).all()
    return Page[ProjectOut](items=[ProjectOut.model_validate(r) for r in rows], total=total,
                            limit=limit, offset=offset)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(_reader)) -> Project:
    return _project(db, project_id)


def _canonical_sql(column: Any) -> Any:
    """SQL form of PEP 503 name normalisation for the separators PyPI names may use."""
    return func.lower(func.replace(func.replace(column, "_", "-"), ".", "-"))


def _stored_verdicts(db: Session, inventory: Any, environment: str) -> dict[str, Scan]:
    wanted = {(c.normalized_name, c.version): c.bom_ref for c in inventory.components
              if c.version and c.ecosystem == "pypi"}
    if not wanted:
        return {}
    names = sorted({name for name, _ in wanted})
    out: dict[str, Scan] = {}
    for scan in db.scalars(
        select(Scan).where(_canonical_sql(Scan.package_name).in_(names), Scan.environment == environment)
        .order_by(Scan.created_at.asc())
    ):
        ref = wanted.get((scan.package_name.lower().replace("_", "-").replace(".", "-"), scan.version))
        if ref:
            out[ref] = scan  # ascending order: the newest verdict wins
    return out


@router.post("/{project_id}/scans", response_model=ProjectScanOut, status_code=201)
def scan_project(
    project_id: uuid.UUID,
    payload: ProjectScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(_writer),
) -> ProjectScan:
    project = _project(db, project_id)
    environment = payload.environment or DEFAULT_ENVIRONMENT
    container_files = {path for path in payload.files if is_dockerfile(path) or is_compose_file(path)}
    # Container files are linted, not parsed as dependency manifests (the parser would report them as ignored).
    inventory = parse_project({k: v for k, v in payload.files.items() if k not in container_files}, project.name)
    container_findings = lint_container_files(payload.files)
    if not inventory.manifests and not container_findings:
        raise WardenError("No supported manifest found in the submitted files", code="validation_error",
                          status_code=422)

    findings = [*hygiene_findings(inventory), *project_confusion_findings(inventory), *container_findings]
    verdicts = _stored_verdicts(db, inventory, environment)
    risk_by_ref = {ref: s.risk_score for ref, s in verdicts.items()}
    decision_by_ref = {ref: s.decision.value for ref, s in verdicts.items() if s.decision}
    graph = build_graph(inventory, risk_by_ref=risk_by_ref, decision_by_ref=decision_by_ref)
    sbom = build_cyclonedx(inventory, risk_by_ref=risk_by_ref, timestamp=datetime.now(timezone.utc),
                           tool_version=__version__)

    worst = max((f.severity.value for f in findings), key=_SEVERITY_FLOOR.__getitem__, default="info")
    decision = "block" if worst in ("high", "critical") else "warn" if worst == "medium" else "allow"
    for value in decision_by_ref.values():
        if _DECISION_RANK.get(value, 0) > _DECISION_RANK[decision]:
            decision = value
    risk = max([_SEVERITY_FLOOR[worst], *[r for r in risk_by_ref.values() if r is not None]])

    row = ProjectScan(
        id=uuid.uuid4(), project_id=project.id, requested_by=user.id, environment=environment,
        manifests=inventory.manifests, component_count=len(inventory.components),
        direct_count=len(inventory.direct_components()), decision=decision, risk_score=int(risk),
        summary={
            "findings": [f.to_dict() for f in findings],
            "graph_metrics": graph.metrics,
            "warnings": [*inventory.warnings, *graph.warnings][:50],
            "components_with_verdict": len(verdicts),
        },
        sbom_cyclonedx=sbom, graph=graph.to_dict(),
        policy_reasons=[{"code": f.code, "severity": f.severity.value, "message": f.message} for f in findings],
    )
    db.add(row)
    for c in inventory.components:
        verdict = verdicts.get(c.bom_ref)
        row.components.append(ProjectComponent(
            bom_ref=c.bom_ref[:300], name=c.name[:214], version=(c.version or None) and c.version[:64],
            purl=c.purl and c.purl[:400], direct=c.direct, depth=c.depth, scope=c.scope[:20],
            resolution=c.resolution[:30], hashes=c.hashes or None, licenses=c.licenses or None,
            declared_at=c.declared_at or None, introduced_by=c.introduced_by or None,
            scan_id=verdict.id if verdict else None, risk_score=verdict.risk_score if verdict else None,
            decision=verdict.decision.value if verdict and verdict.decision else None,
        ))
    for e in inventory.edges:
        row.edges.append(DependencyEdge(parent_ref=e.parent[:300], child_ref=e.child[:300],
                                        specifier=e.specifier and e.specifier[:200]))
    db.flush()

    audit.record(db, actor_id=user.id, action="project.scan", target_type="project", target_id=str(project.id),
                 metadata={"project_scan_id": str(row.id), "decision": decision, "components": row.component_count,
                           "environment": environment})
    event_bus.publish(db, EventType.PROJECT_SCANNED, worst, f"Project {project.name} scanned: {decision}",
                      project_id=project.id,
                      details={"project_scan_id": str(row.id), "decision": decision,
                               "components": row.component_count, "findings": len(findings)})
    project.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return row


@router.get("/{project_id}/scans", response_model=Page[ProjectScanSummary])
def list_project_scans(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
) -> Page[ProjectScanSummary]:
    _project(db, project_id)
    filters = [ProjectScan.project_id == project_id]
    total = db.scalar(select(func.count(ProjectScan.id)).where(*filters)) or 0
    rows = db.scalars(select(ProjectScan).where(*filters).order_by(ProjectScan.created_at.desc())
                      .limit(limit).offset(offset)).all()
    return Page[ProjectScanSummary](items=[ProjectScanSummary.model_validate(r) for r in rows], total=total,
                                    limit=limit, offset=offset)


@router.get("/{project_id}/scans/{scan_id}", response_model=ProjectScanOut)
def get_project_scan(project_id: uuid.UUID, scan_id: uuid.UUID, db: Session = Depends(get_db),
                     _: User = Depends(_reader)) -> ProjectScan:
    return _project_scan(db, project_id, scan_id)


@router.get("/{project_id}/scans/{scan_id}/components", response_model=Page[ComponentOut])
def list_components(
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(_reader),
    limit: int = Query(100, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    direct: bool | None = None,
) -> Page[ComponentOut]:
    _project_scan(db, project_id, scan_id)
    filters = [ProjectComponent.project_scan_id == scan_id]
    if direct is not None:
        filters.append(ProjectComponent.direct.is_(direct))
    total = db.scalar(select(func.count(ProjectComponent.id)).where(*filters)) or 0
    rows = db.scalars(select(ProjectComponent).where(*filters).order_by(ProjectComponent.name)
                      .limit(limit).offset(offset)).all()
    return Page[ComponentOut](items=[ComponentOut.model_validate(r) for r in rows], total=total,
                              limit=limit, offset=offset)


@router.get("/{project_id}/scans/{scan_id}/graph")
def get_graph(project_id: uuid.UUID, scan_id: uuid.UUID, db: Session = Depends(get_db),
              _: User = Depends(_reader)) -> dict:
    return _project_scan(db, project_id, scan_id).graph or {"nodes": [], "edges": [], "metrics": {}}


@router.get("/{project_id}/scans/{scan_id}/sbom")
def get_sbom(
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(_reader),
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),  # noqa: A002 - query parameter name
) -> dict:
    row = _project_scan(db, project_id, scan_id)
    if format == "cyclonedx":
        document = row.sbom_cyclonedx or {}
    else:
        # SPDX is rebuilt from the stored components, which carry everything the builder reads.
        document = build_spdx(_inventory_from_row(row), timestamp=row.created_at, tool_version=__version__)
    event_bus.publish(db, EventType.SBOM_GENERATED, "info", f"SBOM exported ({format})",
                      project_id=project_id, details={"project_scan_id": str(scan_id), "format": format,
                                                      "requested_by": str(user.id)})
    db.commit()
    return document


def _inventory_from_row(row: ProjectScan) -> Any:
    from app.sbom.models import Component, ProjectInventory
    from app.sbom.models import DependencyEdge as Edge
    from app.sbom.parsers import project_root_ref

    name = row.project.name
    inventory = ProjectInventory(project_name=name, root_ref=project_root_ref(name),
                                 manifests=list(row.manifests or []))
    for c in row.components:
        inventory.components.append(Component(
            bom_ref=c.bom_ref, name=c.name, normalized_name=c.name.lower(), version=c.version, purl=c.purl,
            ecosystem="npm" if (c.purl or c.bom_ref).startswith("pkg:npm/") else "pypi",
            direct=c.direct, scope=c.scope or "required", hashes=dict(c.hashes or {}),
            licenses=list(c.licenses or []), declared_at=list(c.declared_at or []),
            resolution=c.resolution or "unresolved", depth=c.depth, introduced_by=list(c.introduced_by or []),
        ))
    inventory.edges = [Edge(parent=e.parent_ref, child=e.child_ref, specifier=e.specifier) for e in row.edges]
    return inventory
