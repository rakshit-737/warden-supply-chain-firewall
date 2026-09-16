"""Policy exceptions as the policy engine consumes them.

Two sources feed the engine:

* **database exceptions** — rows of ``policy_exceptions`` created through the two-person
  request/approve workflow (``app.api.routers.policies``);
* **document exceptions** — ``spec.exceptions`` entries of a policy-as-code document, reviewed
  through ``policy:write`` and the audit trail.

Both are converted into an immutable :class:`ExceptionGrant`. A grant applies to an evaluation
only when **all** of the following hold (anything else leaves the findings in place, i.e. the
engine fails towards enforcement):

* its stored status is ``approved`` (document exceptions are approved by construction);
* for a database exception, ``approved_by`` is set and differs from ``requested_by``. The API
  enforces separation of duties; the engine re-checks it so that a row written around the API
  (self-approved, or "approved" without an approver) never waives anything;
* ``now < expires_at`` — expiry is exclusive and compared as timezone-aware UTC instants (a naive
  stored timestamp is read as UTC, matching the data layer);
* the PEP 503-normalised package names are equal;
* ``version_spec`` is empty, or the evaluated version parses as PEP 440 and is contained in the
  specifier set (pre-releases inside the range are covered; an unparseable version or specifier
  never matches);
* its ``environment`` is empty or equals the evaluation environment;
* its ``policy_id`` is empty (global) or equals the id of the policy being evaluated.

:func:`load_active_exceptions` performs the status/approver/expiry/package/environment/policy
filtering in SQL, re-checks every condition in Python and bounds the result to
:data:`MAX_ACTIVE_EXCEPTIONS` rows (dropping rows can only make an evaluation stricter).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import or_, select

from app.core.redaction import sanitize_text
from app.db.base import as_utc, utcnow
from app.db.models import ExceptionStatus, PolicyException
from app.policy.document import ExceptionEntry
from app.sbom.models import normalize_name

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.orm import Session

MAX_ACTIVE_EXCEPTIONS = 500
SOURCE_DATABASE = "database"
SOURCE_DOCUMENT = "policy_document"
_APPROVED = ExceptionStatus.approved.value
_NEVER = datetime.min.replace(tzinfo=timezone.utc)


def aware_utc(value: datetime) -> datetime:
    """Normalise a datetime to aware UTC (naive values are interpreted as UTC)."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def version_matches(spec: str | None, version: str | None) -> bool:
    """True when ``version`` satisfies the PEP 440 specifier set ``spec`` (empty spec = any version)."""
    if spec is None or not str(spec).strip():
        return True
    if not isinstance(version, str) or not version.strip() or len(str(spec)) > 200:
        return False
    try:
        return SpecifierSet(str(spec)).contains(Version(version.strip()), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False


def _codes(values: Any) -> frozenset[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(str(v).strip().upper() for v in values if isinstance(v, str) and v.strip())


def _categories(values: Any) -> frozenset[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(str(v).strip().lower() for v in values if isinstance(v, str) and v.strip())


def _optional_str(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = sanitize_text(str(value), max_len=max_len)
    return text or None


def _identity(value: Any) -> str | None:
    """A user reference as text (UUIDs from rows, strings from mappings); blank means absent."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(frozen=True)
class ExceptionGrant:
    id: str
    source: str
    package: str
    expires_at: datetime
    version_spec: str | None = None
    codes: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    environment: str | None = None
    policy_id: str | None = None
    status: str = _APPROVED
    reason: str | None = None
    approved_by: str | None = None
    requested_by: str | None = None

    @property
    def whole_package(self) -> bool:
        """No code/category scope: every finding of the package except non-overridable ones."""
        return not self.codes and not self.categories

    def is_active(self, now: datetime) -> bool:
        if self.status != _APPROVED or aware_utc(now) >= self.expires_at:
            return False
        if self.source == SOURCE_DATABASE:
            # Two-person rule re-checked at evaluation time: an approved row written around the API (no
            # approver, or approved by its own requester) is treated as unreviewed.
            return self.approved_by is not None and self.approved_by != self.requested_by
        return True

    def applies_to(self, package: str, version: str | None, *, environment: str | None,
                   policy_id: str | None) -> bool:
        if normalize_name(package) != self.package:
            return False
        if self.environment is not None and self.environment != environment:
            return False
        if self.policy_id is not None and (policy_id is None or self.policy_id != str(policy_id)):
            return False
        return version_matches(self.version_spec, version)

    def covers(self, code: str, category: str | None) -> bool:
        """Scope check (a finding is covered when its code OR its category is listed)."""
        return self.whole_package or code in self.codes or (category is not None and category in self.categories)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "package": self.package,
            "version_spec": self.version_spec,
            "codes": sorted(self.codes),
            "categories": sorted(self.categories),
            "environment": self.environment,
            "policy_id": self.policy_id,
            "expires_at": self.expires_at.isoformat(),
            "reason": self.reason,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
        }


def _build_grant(get: Any, source: str) -> ExceptionGrant:
    expires = get("expires_at")
    if isinstance(expires, str):
        try:
            expires = datetime.fromisoformat(expires)
        except ValueError:
            expires = None
    policy_id, environment = get("policy_id"), get("environment")
    spec = get("version_spec")
    return ExceptionGrant(
        id=str(get("id") or ""),
        source=source,
        package=normalize_name(str(get("package") or "")),
        expires_at=as_utc(expires) if isinstance(expires, datetime) else _NEVER,
        version_spec=str(spec) if spec else None,
        codes=_codes(get("codes")),
        categories=_categories(get("categories")),
        environment=environment.strip().lower() if isinstance(environment, str) and environment.strip() else None,
        policy_id=str(policy_id) if policy_id is not None else None,
        status=str(get("status") or ""),
        reason=_optional_str(get("justification"), 200),
        approved_by=_identity(get("approved_by")),
        requested_by=_identity(get("requested_by")),
    )


def grant_from_row(row: Any) -> ExceptionGrant:
    """Build a grant from a ``PolicyException`` row (or any object with the same attributes)."""
    return _build_grant(lambda key: getattr(row, key, None), SOURCE_DATABASE)


def _entry_id(entry: ExceptionEntry) -> str:
    canonical = json.dumps(entry.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return "policy:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def grant_from_entry(entry: ExceptionEntry) -> ExceptionGrant:
    """Build a grant from a document ``spec.exceptions`` entry (id derived from its content)."""
    return ExceptionGrant(
        id=_entry_id(entry),
        source=SOURCE_DOCUMENT,
        package=entry.package,
        expires_at=entry.expires_at,
        version_spec=entry.version,
        codes=frozenset(entry.codes),
        categories=frozenset(entry.categories),
        reason=_optional_str(entry.reason, 200),
        approved_by=entry.approved_by,
    )


def coerce_grant(value: Any) -> ExceptionGrant:
    """Accept an ``ExceptionGrant``, a document ``ExceptionEntry``, a ``PolicyException``-like row or a mapping.

    A mapping uses the row's keys (``expires_at`` may be an ISO-8601 string); a missing ``status``
    means ``pending``, so an unreviewed mapping never applies. A mapping is a database exception
    unless ``source`` says ``policy_document``, so it also needs an ``approved_by`` that differs
    from its ``requested_by``.
    """
    if isinstance(value, ExceptionGrant):
        return value
    if isinstance(value, ExceptionEntry):
        return grant_from_entry(value)
    if isinstance(value, Mapping):
        source = value.get("source")
        source = source if source in (SOURCE_DATABASE, SOURCE_DOCUMENT) else SOURCE_DATABASE
        return _build_grant(lambda key: value.get(key, ExceptionStatus.pending.value if key == "status" else None),
                            source)
    if hasattr(value, "package") and hasattr(value, "expires_at"):
        return grant_from_row(value)
    raise TypeError(f"unsupported policy exception type: {type(value).__name__}")


def load_active_exceptions(
    db: Session,
    package: str,
    version: str | None,
    environment: str | None,
    policy_id: uuid.UUID | str | None,
    now: datetime | None = None,
) -> list[ExceptionGrant]:
    """Approved, unexpired database exceptions applicable to one package evaluation.

    Ordered by ``(expires_at, id)`` for deterministic evaluation. With ``environment=None`` only
    environment-agnostic exceptions apply; with ``policy_id=None`` only global exceptions apply.
    """
    current = aware_utc(now or utcnow())
    name = normalize_name(package)
    filters = [
        PolicyException.package == name,
        PolicyException.status == _APPROVED,
        PolicyException.approved_by.is_not(None),
        PolicyException.approved_by != PolicyException.requested_by,
        PolicyException.expires_at > current,
    ]
    if environment:
        filters.append(or_(PolicyException.environment.is_(None), PolicyException.environment == environment))
    else:
        filters.append(PolicyException.environment.is_(None))
    if policy_id is not None:
        pid = policy_id if isinstance(policy_id, uuid.UUID) else uuid.UUID(str(policy_id))
        filters.append(or_(PolicyException.policy_id.is_(None), PolicyException.policy_id == pid))
    else:
        filters.append(PolicyException.policy_id.is_(None))
    rows: Iterable[PolicyException] = db.scalars(
        select(PolicyException).where(*filters)
        .order_by(PolicyException.expires_at, PolicyException.id)
        .limit(MAX_ACTIVE_EXCEPTIONS)
    ).all()
    pid_text = str(policy_id) if policy_id is not None else None
    grants = [grant_from_row(row) for row in rows]
    return [g for g in grants
            if g.is_active(current) and g.applies_to(name, version, environment=environment, policy_id=pid_text)]


__all__ = [
    "MAX_ACTIVE_EXCEPTIONS",
    "SOURCE_DATABASE",
    "SOURCE_DOCUMENT",
    "ExceptionGrant",
    "aware_utc",
    "coerce_grant",
    "grant_from_entry",
    "grant_from_row",
    "load_active_exceptions",
    "version_matches",
]
