"""Security event vocabulary.

Event types are stored as lower-case snake-case strings (``package_scanned``); the enum
also accepts the upper-case member name (``PACKAGE_SCANNED``) on input so API filters and
callers can use either spelling.
"""

from __future__ import annotations

import enum

EVENT_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(EVENT_SEVERITIES)}


class EventType(str, enum.Enum):
    PACKAGE_SCANNED = "package_scanned"
    PACKAGE_BLOCKED = "package_blocked"
    RISK_INCREASED = "risk_increased"
    RISK_DECREASED = "risk_decreased"
    VULNERABILITY_DISCOVERED = "vulnerability_discovered"
    KEV_ADDED = "kev_added"
    BEHAVIOR_DRIFT_DETECTED = "behavior_drift_detected"
    MAINTAINER_CHANGED = "maintainer_changed"
    PROVENANCE_CHANGED = "provenance_changed"
    NEW_RELEASE_DETECTED = "new_release_detected"
    POLICY_VIOLATION = "policy_violation"
    EXCEPTION_CREATED = "exception_created"
    EXCEPTION_APPROVED = "exception_approved"
    EXCEPTION_REJECTED = "exception_rejected"
    EXCEPTION_REVOKED = "exception_revoked"
    EXCEPTION_EXPIRED = "exception_expired"
    SBOM_GENERATED = "sbom_generated"
    PROJECT_SCANNED = "project_scanned"
    CONTAINER_SCANNED = "container_scanned"
    DEPENDENCY_GRAPH_CHANGED = "dependency_graph_changed"
    MONITOR_ERROR = "monitor_error"

    @classmethod
    def _missing_(cls, value: object) -> EventType | None:
        if not isinstance(value, str):
            return None
        key = value.strip()
        for member in cls:
            if member.value == key.lower() or member.name == key.upper():
                return member
        return None


def coerce_severity(value: object) -> str:
    """Normalise a severity (str or str-enum) to one of :data:`EVENT_SEVERITIES`."""
    raw = getattr(value, "value", value)
    key = str(raw).strip().lower()
    if key not in _SEVERITY_RANK:
        raise ValueError(f"invalid event severity: {key[:20]!r}")
    return key


def max_severity(*values: object) -> str:
    """The most severe of ``values`` (each coerced with :func:`coerce_severity`)."""
    return max((coerce_severity(v) for v in values), key=_SEVERITY_RANK.__getitem__)
