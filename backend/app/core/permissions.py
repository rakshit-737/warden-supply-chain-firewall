"""Role-based access control: roles, permissions and the role → permission matrix.

Authorisation in Warden is expressed as *permissions* (``scan:create``, ``audit:read`` …)
rather than role names, so a route states what it needs and the mapping from roles to
capabilities lives in exactly one reviewed table (:data:`ROLE_PERMISSIONS`). Every check is
enforced server-side by :func:`app.api.deps.require_permission`; the frontend may hide
controls, but hiding is never the control.

Design notes
------------
* The matrix is **deny by default**: a role holds only the permissions listed for it, and
  an unknown role holds none.
* Roles are stored as plain strings (a non-native enum) so adding a role never requires a
  database enum-type migration. Legacy v1 role names are accepted on input and mapped to
  their current equivalents (``analyst`` → ``security_analyst``, ``viewer`` →
  ``read_only``); the mapping never grants more than the v1 role could do, except that
  v1 analysts can now also request policy exceptions and acknowledge events.
* ``admin`` is the only role with ``user:manage`` / ``policy:write`` / ``system:write``;
  ``auditor`` is read-only but may read the audit trail. Separation-of-duties rules that
  depend on the *data* (e.g. an exception approver must not be its requester) are enforced
  in the relevant route, for every role, in addition to these permissions.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable

# v1 role names still accepted on input (API payloads, stored rows that pre-date 0002).
LEGACY_ROLE_NAMES: dict[str, str] = {
    "analyst": "security_analyst",
    "viewer": "read_only",
}


class Role(str, enum.Enum):
    admin = "admin"
    security_analyst = "security_analyst"
    developer = "developer"
    auditor = "auditor"
    read_only = "read_only"

    @classmethod
    def _missing_(cls, value: object) -> Role | None:
        # Called by ``Role("viewer")`` (and by pydantic) when ``value`` is not a canonical
        # member value: accept case/whitespace variants and legacy v1 names.
        if not isinstance(value, str):
            return None
        key = value.strip().lower()
        key = LEGACY_ROLE_NAMES.get(key, key)
        for member in cls:
            if member.value == key:
                return member
        return None


class Permission(str, enum.Enum):
    # --- write actions available to engineering roles ---------------------------------
    SCAN_CREATE = "scan:create"
    PROJECT_WRITE = "project:write"
    CONTAINER_SCAN = "container:scan"
    DIFF_CREATE = "diff:create"
    # --- read access for every authenticated role ---------------------------------------
    SCAN_READ = "scan:read"
    PROJECT_READ = "project:read"
    EVENT_READ = "event:read"
    MONITOR_READ = "monitor:read"
    POLICY_READ = "policy:read"
    REPORT_READ = "report:read"
    ML_READ = "ml:read"
    VULN_READ = "vuln:read"
    # --- policy exceptions ---------------------------------------------------------------
    EXCEPTION_REQUEST = "exception:request"
    EXCEPTION_APPROVE = "exception:approve"
    # --- security operations -------------------------------------------------------------
    EVENT_ACK = "event:ack"
    MONITOR_WRITE = "monitor:write"
    # --- administration ------------------------------------------------------------------
    POLICY_WRITE = "policy:write"
    USER_MANAGE = "user:manage"
    SYSTEM_WRITE = "system:write"
    AUDIT_READ = "audit:read"
    SYSTEM_READ = "system:read"


P = Permission

_ENGINEERING_WRITE = frozenset({P.SCAN_CREATE, P.PROJECT_WRITE, P.CONTAINER_SCAN, P.DIFF_CREATE})
_READ = frozenset({
    P.SCAN_READ, P.PROJECT_READ, P.EVENT_READ, P.MONITOR_READ, P.POLICY_READ, P.REPORT_READ, P.ML_READ, P.VULN_READ,
})
_SECOPS = frozenset({P.EXCEPTION_APPROVE, P.EVENT_ACK, P.MONITOR_WRITE})
_ADMIN_ONLY = frozenset({P.POLICY_WRITE, P.USER_MANAGE, P.SYSTEM_WRITE})
_OVERSIGHT = frozenset({P.AUDIT_READ, P.SYSTEM_READ})

# The authoritative matrix (SPEC section 6). Changing it is a security decision.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.admin: frozenset(Permission),
    Role.security_analyst: _ENGINEERING_WRITE | _READ | {P.EXCEPTION_REQUEST} | _SECOPS,
    Role.developer: _ENGINEERING_WRITE | _READ | {P.EXCEPTION_REQUEST},
    Role.auditor: _READ | _OVERSIGHT,
    Role.read_only: _READ,
}

# Permissions no role other than admin may ever hold (checked by tests/test_rbac_matrix.py).
ADMIN_ONLY_PERMISSIONS: frozenset[Permission] = _ADMIN_ONLY


def coerce_role(value: Role | str | None) -> Role | None:
    """Return the :class:`Role` for ``value`` (legacy names accepted) or ``None`` if unknown."""
    if value is None:
        return None
    if isinstance(value, Role):
        return value
    try:
        return Role(value)
    except ValueError:
        return None


def permissions_for(role: Role | str | None) -> frozenset[Permission]:
    """Permissions granted to ``role``; an unknown role gets none (deny by default)."""
    resolved = coerce_role(role)
    return ROLE_PERMISSIONS.get(resolved, frozenset()) if resolved is not None else frozenset()


def has_permissions(role: Role | str | None, perms: Iterable[Permission | str]) -> bool:
    """True when ``role`` holds *every* permission in ``perms``."""
    granted = permissions_for(role)
    return all(Permission(p) in granted for p in perms)


def roles_with(permission: Permission | str) -> list[Role]:
    """Roles holding ``permission`` (for error messages and documentation)."""
    perm = Permission(permission)
    return [role for role in Role if perm in ROLE_PERMISSIONS[role]]
