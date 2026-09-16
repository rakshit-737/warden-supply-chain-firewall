"""Policy management and the policy-exception workflow.

Policies (``policy:read`` / ``policy:write``) are scoped to an environment and exactly one
policy is active per environment (enforced by the activation route *and* a partial unique
index in the database).

Policy-as-code: ``POST /policies/validate`` (``policy:read``) validates a document given as an
object or as YAML/JSON text and returns ``{valid, errors[{loc, msg, line}], warnings, normalized,
policy_hash}`` without storing anything. Create and update (``policy:write``) accept an optional
``document`` that is validated strictly, stored normalised and mirrored into the v1 columns (see
:mod:`app.schemas.policy`). Updating a document-defined policy without a ``document`` key is a
conflict, so a v1-style PUT can never leave the stored document and the v1 columns disagreeing;
``"document": null`` converts the policy back to v1 columns explicitly. Every policy response
carries ``policy_hash``.

Policy exceptions implement a two-person rule:

* ``exception:request`` — any engineering role may request a time-boxed exception;
* ``exception:approve`` — approvers decide pending requests, but **never their own**: the
  requester of an exception cannot approve or reject it, whatever their role (admins
  included). The check is repeated inside the conditional UPDATE, so it also holds under
  concurrent requests;
* ``revoke`` — an approver may revoke any pending/approved exception; a requester may
  withdraw their own;
* an exception whose ``expires_at`` has passed is reported as ``expired`` and can no longer
  be approved or revoked — expiry needs no background job.

Every transition is written to the audit trail and published as a security event. Approved,
unexpired exceptions are applied during scan evaluation by the policy engine
(:mod:`app.policy.exceptions`, :mod:`app.policy.engine`).

Policies are mutable rows without a history table, so the hash-chained audit trail is the only
tamper-evident record of what a policy said. ``policy.create`` records the policy's settings,
its lists (first ``AUDIT_LIST_ITEMS`` entries plus counts), ``policy_sha256`` (the SHA-256 of the
canonical JSON of every decision-relevant field: name, environment, thresholds, minimum age,
blocked capabilities, allowlist, denylist, document) and ``policy_hash`` (the hash scan
evaluations record). ``policy.update`` records both digests before and after, ``changed_fields``
and a field-level diff (added/removed list entries, old/new scalar values, changed document
paths), and ``policy.activate`` records the digests and the ids of the policies it deactivated.
The digests always cover the full content, so an auditor can verify a stored policy against the
chain even when a list was too long to log in full.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import require_any_permission, require_permission
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, WardenError
from app.core.permissions import Permission, permissions_for
from app.db.base import as_utc, utcnow
from app.db.models import DEFAULT_ENVIRONMENT, ExceptionStatus, Policy, PolicyException, User
from app.db.session import get_db
from app.events import bus as event_bus
from app.events.types import EventType
from app.policy.document import policy_hash_for, validate_policy_data, validate_policy_text
from app.sbom.models import normalize_name
from app.schemas.common import MAX_PAGE_LIMIT, Page
from app.schemas.exception import ExceptionCreate, ExceptionOut, ExceptionStatusOut, ExceptionTransition
from app.schemas.policy import PolicyCreate, PolicyOut, PolicyUpdate, PolicyValidateRequest, PolicyValidateResponse
from app.schemas.scan import PYPI_NAME_RE, validate_environment
from app.services import audit

router = APIRouter(prefix="/policies", tags=["policies"])

_policy_reader = require_permission(Permission.POLICY_READ)
_policy_writer = require_permission(Permission.POLICY_WRITE)

_OPEN_STATES = (ExceptionStatus.pending.value, ExceptionStatus.approved.value)


def _validation_error(message: str) -> WardenError:
    return WardenError(message, code="validation_error", status_code=422)


def _environment_param(value: str | None) -> str | None:
    try:
        return validate_environment(value)
    except ValueError as exc:
        raise _validation_error(str(exc)) from exc


# =========================================================================== exceptions
def effective_status(exc: PolicyException, now: datetime | None = None) -> str:
    """Stored status, except that an open (pending/approved) exception past expiry is ``expired``."""
    now = now or utcnow()
    if exc.status in _OPEN_STATES and as_utc(exc.expires_at) <= now:
        return "expired"
    return exc.status


def _exception_out(exc: PolicyException, now: datetime) -> ExceptionOut:
    status = effective_status(exc, now)
    return ExceptionOut(
        id=exc.id, policy_id=exc.policy_id, package=exc.package, version_spec=exc.version_spec,
        codes=list(exc.codes or []), categories=list(exc.categories or []), environment=exc.environment,
        justification=exc.justification, requested_by=exc.requested_by, approved_by=exc.approved_by,
        revoked_by=exc.revoked_by, status=status, active=status == ExceptionStatus.approved.value,
        expires_at=as_utc(exc.expires_at), created_at=as_utc(exc.created_at), decided_at=as_utc(exc.decided_at),
        revoked_at=as_utc(exc.revoked_at),
    )


def _event_details(exc: PolicyException, **extra: object) -> dict:
    return {
        "exception_id": str(exc.id),
        "policy_id": str(exc.policy_id) if exc.policy_id else None,
        "version_spec": exc.version_spec,
        "codes": list(exc.codes or []),
        "categories": list(exc.categories or []),
        "environment": exc.environment,
        "expires_at": as_utc(exc.expires_at).isoformat(),
        "requested_by": str(exc.requested_by),
        **extra,
    }


def _load_exception(db: Session, exception_id: uuid.UUID) -> PolicyException:
    exc = db.get(PolicyException, exception_id)
    if exc is None:
        raise NotFoundError("Policy exception not found")
    return exc


@router.get("/exceptions", response_model=Page[ExceptionOut])
def list_exceptions(
    db: Session = Depends(get_db),
    _: User = Depends(_policy_reader),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    status: ExceptionStatusOut | None = None,
    package: str | None = Query(None, max_length=214),
    policy_id: uuid.UUID | None = None,
    environment: str | None = Query(None, max_length=20),
) -> Page[ExceptionOut]:
    now = utcnow()
    filters = []
    if status == "expired":
        filters += [PolicyException.status.in_(_OPEN_STATES), PolicyException.expires_at <= now]
    elif status in _OPEN_STATES:
        filters += [PolicyException.status == status, PolicyException.expires_at > now]
    elif status is not None:
        filters.append(PolicyException.status == status)
    if package:
        if not PYPI_NAME_RE.match(package.strip()):
            raise _validation_error("Invalid PyPI package name")
        filters.append(PolicyException.package == normalize_name(package))
    if policy_id is not None:
        filters.append(PolicyException.policy_id == policy_id)
    if environment:
        filters.append(PolicyException.environment == _environment_param(environment))

    total = db.scalar(select(func.count(PolicyException.id)).where(*filters)) or 0
    rows = db.scalars(
        select(PolicyException).where(*filters)
        .order_by(PolicyException.created_at.desc(), PolicyException.id).limit(limit).offset(offset)
    ).all()
    return Page[ExceptionOut](items=[_exception_out(r, now) for r in rows], total=total, limit=limit, offset=offset)


@router.post("/exceptions", response_model=ExceptionOut, status_code=201)
def request_exception(
    payload: ExceptionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EXCEPTION_REQUEST)),
) -> ExceptionOut:
    if payload.policy_id is not None:
        policy = db.get(Policy, payload.policy_id)
        if policy is None:
            raise NotFoundError("Policy not found")
        if payload.environment and payload.environment != policy.environment:
            raise _validation_error("environment does not match the policy's environment")

    now = utcnow()
    exc = PolicyException(
        id=uuid.uuid4(),
        policy_id=payload.policy_id,
        package=payload.package,
        version_spec=payload.version_spec,
        codes=payload.codes,
        categories=payload.categories,
        environment=payload.environment,
        justification=payload.justification,
        requested_by=user.id,
        status=ExceptionStatus.pending.value,
        expires_at=payload.expires_at,
        created_at=now,
    )
    db.add(exc)
    audit.record(db, actor_id=user.id, action="exception.request", target_type="policy_exception",
                 target_id=str(exc.id), metadata={"package": exc.package, **_event_details(exc)})
    event_bus.publish(db, EventType.EXCEPTION_CREATED, "low", f"Policy exception requested for {exc.package}",
                      package=exc.package, details=_event_details(exc, status=exc.status))
    db.commit()
    db.refresh(exc)
    return _exception_out(exc, now)


def _decide(
    db: Session, exception_id: uuid.UUID, user: User, target: ExceptionStatus, body: ExceptionTransition | None,
) -> ExceptionOut:
    exc = _load_exception(db, exception_id)
    now = utcnow()
    if exc.requested_by == user.id:
        raise ForbiddenError(
            "Separation of duties: the requester of an exception cannot approve or reject it",
            code="separation_of_duties",
        )
    if exc.status != ExceptionStatus.pending.value:
        raise ConflictError(f"Only pending exceptions can be decided (current status: {exc.status})")
    if as_utc(exc.expires_at) <= now:
        raise ConflictError("The exception has expired and can no longer be decided")

    # Conditional update re-asserts every invariant atomically (concurrent deciders).
    result = db.execute(
        update(PolicyException)
        .where(
            PolicyException.id == exc.id,
            PolicyException.status == ExceptionStatus.pending.value,
            PolicyException.requested_by != user.id,
            PolicyException.expires_at > now,
        )
        .values(status=target.value, approved_by=user.id, decided_at=now)
        .execution_options(synchronize_session=False)
    )
    if (result.rowcount or 0) != 1:
        db.rollback()
        raise ConflictError("The exception was changed concurrently; reload and retry")
    db.expire(exc)

    verb = "approve" if target == ExceptionStatus.approved else "reject"
    comment = body.comment if body else None
    audit.record(db, actor_id=user.id, action=f"exception.{verb}", target_type="policy_exception",
                 target_id=str(exc.id), metadata={"package": exc.package, "comment": comment,
                                                  "requested_by": str(exc.requested_by)})
    event_type = EventType.EXCEPTION_APPROVED if target == ExceptionStatus.approved else EventType.EXCEPTION_REJECTED
    event_bus.publish(
        db, event_type, "medium" if target == ExceptionStatus.approved else "info",
        f"Policy exception {target.value} for {exc.package}", package=exc.package,
        details=_event_details(exc, status=target.value, decided_by=str(user.id), comment=comment),
    )
    db.commit()
    db.refresh(exc)
    return _exception_out(exc, now)


@router.post("/exceptions/{exception_id}/approve", response_model=ExceptionOut)
def approve_exception(
    exception_id: uuid.UUID,
    body: ExceptionTransition | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EXCEPTION_APPROVE)),
) -> ExceptionOut:
    return _decide(db, exception_id, user, ExceptionStatus.approved, body)


@router.post("/exceptions/{exception_id}/reject", response_model=ExceptionOut)
def reject_exception(
    exception_id: uuid.UUID,
    body: ExceptionTransition | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EXCEPTION_APPROVE)),
) -> ExceptionOut:
    return _decide(db, exception_id, user, ExceptionStatus.rejected, body)


@router.post("/exceptions/{exception_id}/revoke", response_model=ExceptionOut)
def revoke_exception(
    exception_id: uuid.UUID,
    body: ExceptionTransition | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_permission(Permission.EXCEPTION_APPROVE, Permission.EXCEPTION_REQUEST)),
) -> ExceptionOut:
    exc = _load_exception(db, exception_id)
    is_approver = Permission.EXCEPTION_APPROVE in permissions_for(user.role)
    if not is_approver and exc.requested_by != user.id:
        raise ForbiddenError("Only an approver or the original requester may revoke an exception")
    now = utcnow()
    if exc.status not in _OPEN_STATES:
        raise ConflictError(f"Only pending or approved exceptions can be revoked (current status: {exc.status})")
    if as_utc(exc.expires_at) <= now:
        raise ConflictError("The exception has already expired")

    result = db.execute(
        update(PolicyException)
        .where(
            PolicyException.id == exc.id,
            PolicyException.status.in_(_OPEN_STATES),
            PolicyException.expires_at > now,
        )
        .values(status=ExceptionStatus.revoked.value, revoked_by=user.id, revoked_at=now)
        .execution_options(synchronize_session=False)
    )
    if (result.rowcount or 0) != 1:
        db.rollback()
        raise ConflictError("The exception was changed concurrently; reload and retry")
    db.expire(exc)

    comment = body.comment if body else None
    audit.record(db, actor_id=user.id, action="exception.revoke", target_type="policy_exception",
                 target_id=str(exc.id), metadata={"package": exc.package, "comment": comment})
    event_bus.publish(
        db, EventType.EXCEPTION_REVOKED, "low", f"Policy exception revoked for {exc.package}", package=exc.package,
        details=_event_details(exc, status=ExceptionStatus.revoked.value, revoked_by=str(user.id), comment=comment),
    )
    db.commit()
    db.refresh(exc)
    return _exception_out(exc, now)


# =========================================================================== policy audit content
AUDIT_LIST_ITEMS = 40  # below the audit sanitiser's 50-item bound; the digest covers every entry
_SCALAR_FIELDS = ("name", "environment", "warn_threshold", "block_threshold", "min_package_age_days")
_LIST_FIELDS = ("blocked_capabilities", "allowlist", "denylist")
_DOCUMENT_DIFF_DEPTH = 3


def policy_snapshot(policy: Policy) -> dict[str, Any]:
    """Every decision-relevant field of ``policy`` in a JSON-serialisable form (list order as stored)."""
    snapshot: dict[str, Any] = {name: getattr(policy, name) for name in _SCALAR_FIELDS}
    for name in _LIST_FIELDS:
        snapshot[name] = [str(v) for v in (getattr(policy, name) or [])]
    snapshot["document"] = policy.document
    return snapshot


def _sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def policy_digest(snapshot: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON of a :func:`policy_snapshot`."""
    return _sha256(snapshot)


def _content_metadata(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_sha256": policy_digest(snapshot),
        "settings": {name: snapshot[name] for name in _SCALAR_FIELDS},
        "lists": {name: snapshot[name][:AUDIT_LIST_ITEMS] for name in _LIST_FIELDS},
        "list_counts": {name: len(snapshot[name]) for name in _LIST_FIELDS},
        "document_sha256": _sha256(snapshot["document"]) if snapshot["document"] is not None else None,
    }


def _document_paths(before: Any, after: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Dotted paths (at most three levels deep) whose values differ between two stored documents."""
    if isinstance(before, dict) and isinstance(after, dict) and depth < _DOCUMENT_DIFF_DEPTH:
        paths: list[str] = []
        for key in sorted(set(before) | set(after), key=str):
            if before.get(key) != after.get(key):
                paths.extend(_document_paths(before.get(key), after.get(key), f"{prefix}{key}.", depth + 1))
        return paths
    return [prefix.rstrip(".") or "document"]


def _policy_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for name in _SCALAR_FIELDS:
        if before[name] != after[name]:
            changes[name] = {"before": before[name], "after": after[name]}
    for name in _LIST_FIELDS:
        old, new = set(before[name]), set(after[name])
        added = [v for v in after[name] if v not in old]
        removed = [v for v in before[name] if v not in new]
        if added or removed or before[name] != after[name]:
            changes[name] = {"added": added[:AUDIT_LIST_ITEMS], "removed": removed[:AUDIT_LIST_ITEMS],
                             "added_count": len(added), "removed_count": len(removed)}
    if before["document"] != after["document"]:
        changes["document"] = {
            "before_sha256": _sha256(before["document"]) if before["document"] is not None else None,
            "after_sha256": _sha256(after["document"]) if after["document"] is not None else None,
            "changed_paths": _document_paths(before["document"], after["document"])[:AUDIT_LIST_ITEMS],
        }
    return changes


def _policy_source(policy: Policy) -> str:
    return "document" if policy.document is not None else "legacy"


# =========================================================================== policies
@router.get("", response_model=list[PolicyOut])
def list_policies(
    db: Session = Depends(get_db),
    _: User = Depends(_policy_reader),
    environment: str | None = Query(None, max_length=20),
) -> list[Policy]:
    stmt = select(Policy).order_by(Policy.created_at.desc())
    if environment:
        stmt = stmt.where(Policy.environment == _environment_param(environment))
    return list(db.scalars(stmt).all())


@router.get("/active", response_model=PolicyOut)
def active_policy(
    db: Session = Depends(get_db),
    _: User = Depends(_policy_reader),
    environment: str = Query(DEFAULT_ENVIRONMENT, max_length=20),
) -> Policy:
    env = _environment_param(environment)
    policy = db.scalar(select(Policy).where(Policy.is_active.is_(True), Policy.environment == env))
    if policy is None:
        raise NotFoundError(f"No active policy configured for environment '{env}'")
    return policy


@router.post("/validate", response_model=PolicyValidateResponse)
def validate_policy(
    payload: PolicyValidateRequest,
    _: User = Depends(_policy_reader),
) -> PolicyValidateResponse:
    """Validate a policy document (object, or YAML/JSON text) without storing it."""
    if payload.yaml is not None:
        outcome = validate_policy_text(payload.yaml, "auto")
    else:
        outcome = validate_policy_data(payload.document)
    return PolicyValidateResponse(
        valid=outcome.valid, errors=outcome.errors, warnings=outcome.warnings,
        normalized=outcome.normalized, policy_hash=outcome.policy_hash,
    )


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(_policy_writer),
) -> Policy:
    document = payload.document.to_dict() if payload.document is not None else None
    policy = Policy(id=uuid.uuid4(), **payload.model_dump(exclude={"document"}), document=document, version=1,
                    updated_at=datetime.now(timezone.utc))
    db.add(policy)
    audit.record(db, actor_id=admin.id, action="policy.create", target_type="policy", target_id=str(policy.id),
                 metadata={"name": policy.name, "environment": policy.environment, "version": 1,
                           "policy_hash": policy_hash_for(policy), "policy_source": _policy_source(policy),
                           **_content_metadata(policy_snapshot(policy))})
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: uuid.UUID,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(_policy_writer),
) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise NotFoundError("Policy not found")
    if policy.document is not None and not payload.document_supplied:
        raise ConflictError(
            "This policy is defined by a policy-as-code document: include the updated document, or send "
            '"document": null to manage it through the legacy fields'
        )
    data = payload.model_dump(exclude={"document"})
    new_environment = data.pop("environment") or policy.environment
    if policy.is_active and new_environment != policy.environment:
        raise ConflictError("An active policy cannot move to another environment; activate another policy first")
    before = policy_snapshot(policy)
    hash_before = policy_hash_for(policy)
    for k, v in data.items():
        setattr(policy, k, v)
    policy.environment = new_environment
    policy.document = (payload.document.with_environment(new_environment).to_dict()
                       if payload.document is not None else None)
    policy.version = (policy.version or 1) + 1
    policy.updated_at = datetime.now(timezone.utc)
    after = policy_snapshot(policy)
    content = _content_metadata(after)
    changes = _policy_changes(before, after)
    audit.record(db, actor_id=admin.id, action="policy.update", target_type="policy", target_id=str(policy_id),
                 metadata={"version": policy.version, "environment": new_environment, "is_active": policy.is_active,
                           "policy_sha256_before": policy_digest(before), "policy_sha256": content["policy_sha256"],
                           "policy_hash_before": hash_before, "policy_hash": policy_hash_for(policy),
                           "policy_source": _policy_source(policy), "changed_fields": sorted(changes),
                           "changes": changes, "settings": content["settings"],
                           "list_counts": content["list_counts"]})
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/{policy_id}/activate", response_model=PolicyOut)
def activate_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(_policy_writer),
) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise NotFoundError("Policy not found")
    # Exactly one active policy per environment: deactivate the others in this environment.
    deactivated = sorted(str(pid) for pid in db.scalars(
        select(Policy.id).where(Policy.environment == policy.environment, Policy.id != policy.id,
                                Policy.is_active.is_(True))
    ))
    db.execute(
        update(Policy)
        .where(Policy.environment == policy.environment, Policy.id != policy.id)
        .values(is_active=False)
        .execution_options(synchronize_session=False)
    )
    policy.is_active = True
    policy.updated_at = datetime.now(timezone.utc)
    audit.record(db, actor_id=admin.id, action="policy.activate", target_type="policy", target_id=str(policy_id),
                 metadata={"environment": policy.environment, "version": policy.version,
                           "policy_sha256": policy_digest(policy_snapshot(policy)),
                           "policy_hash": policy_hash_for(policy), "policy_source": _policy_source(policy),
                           "deactivated_policy_ids": deactivated})
    db.commit()
    db.refresh(policy)
    return policy
