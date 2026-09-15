"""Optional transitive dependency resolution from PyPI metadata (network; **off by default**).

Manifests without a lock file only say what a project asks for directly. When enabled
(``settings.SBOM_RESOLVE_TRANSITIVE`` or ``enabled=True``), this module fills in transitive
edges for *pinned* components that have no lock data:

1. fetch ``/pypi/<name>/<version>/json`` and read ``info.requires_dist``;
2. evaluate each requirement's environment markers against a configurable **target
   environment** (default: the interpreter Warden runs on) and the extras requested for the parent;
3. link to an existing component that satisfies the specifier, or pick the highest non-yanked
   release satisfying it from ``/pypi/<name>/json`` (``requires_python`` checked against the
   target; pre-releases follow ``packaging`` rules: only when the specifier names one or no final
   release satisfies it) and add it with ``resolution="resolved"``;
4. repeat breadth-first for pinned and resolved components.

Locked components are never re-resolved: a lock file is the better record of what is installed.
Work is bounded by ``max_nodes`` release-metadata fetches, ``max_requests`` HTTP requests in total
and ``MAX_PROJECT_COMPONENTS``; hitting a bound marks the report ``partial``.

This is an approximation of what an installer would choose at resolution time - it does not
backtrack on conflicts - and results are labelled ``resolved`` (not ``locked``) for that reason.
All HTTP goes through :class:`~app.core.http.SafeHttpClient` restricted to
``REGISTRY_HOST_ALLOWLIST``; responses are untrusted and every field is type-checked. Package
code is never downloaded. A release whose ``requires_dist`` is ``null`` keeps
``dependencies_known = False``: PyPI reports ``null`` both for "no dependencies" and for
"metadata not extracted", so Warden does not claim either. ``dependencies_known`` is set only
after every applicable requirement produced an edge: a malformed entry, a direct-URL dependency,
a failed or unsatisfiable release lookup, the component bound or the per-package requirement cap
leaves it ``False``, so SBOMs never report an incomplete dependency list as complete.
Requirements whose markers do not apply to the target environment count as handled.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from urllib.parse import quote

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app.core.config import settings
from app.core.http import OutboundHTTPError, SafeHttpClient
from app.sbom.models import Component, DependencyEdge, ProjectInventory, make_bom_ref, make_purl
from app.sbom.parsers import (
    MAX_NAME_LEN,
    bound_specifier,
    bounded_warnings,
    clean_version,
    compute_graph_metadata,
    credential_like,
    display,
    propagate_scope,
    version_sort_key,
    warn,
)

_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ABORT_KINDS = frozenset({"network", "host_not_allowed", "scheme", "redirect"})
_RESOLVABLE = frozenset({"pinned", "resolved"})
MAX_REQUIRES_PER_PACKAGE = 300
MAX_REQUIREMENT_CHARS = 2048
MAX_LICENSE_EXPRESSION = 200


class _Abort(Exception):
    """Stop resolution: the registry is unreachable, refused by policy, or a budget is spent."""


@dataclass
class ResolutionReport:
    status: str  # disabled | ok | partial
    fetched_nodes: int = 0  # release-metadata fetches (one per component)
    requests: int = 0  # HTTP requests of any kind
    added_components: int = 0
    added_edges: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_transitive(
    inventory: ProjectInventory,
    *,
    enabled: bool | None = None,
    client: SafeHttpClient | None = None,
    target_environment: Mapping[str, str] | None = None,
    max_nodes: int | None = None,
    max_requests: int | None = None,
    base_url: str | None = None,
) -> ResolutionReport:
    """Fill transitive edges in place when enabled; returns what was done (never raises for HTTP errors)."""
    if enabled is None:
        enabled = settings.SBOM_RESOLVE_TRANSITIVE
    if not enabled:
        return ResolutionReport(status="disabled")
    resolver = PyPIResolver(client=client, target_environment=target_environment, max_nodes=max_nodes,
                            max_requests=max_requests, base_url=base_url)
    return resolver.resolve(inventory)


def _resolvable(component: Component) -> bool:
    return bool(component.version and component.purl) and component.resolution in _RESOLVABLE


class PyPIResolver:
    def __init__(
        self,
        *,
        client: SafeHttpClient | None = None,
        base_url: str | None = None,
        target_environment: Mapping[str, str] | None = None,
        max_nodes: int | None = None,
        max_requests: int | None = None,
    ) -> None:
        self._owns_client = client is None
        self.client = client or SafeHttpClient(
            name="sbom-resolver",
            allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
            max_response_bytes=settings.MAX_METADATA_BYTES,
            timeout=float(settings.FETCH_TIMEOUT_SECONDS),
            rate_limit_per_second=10.0,
        )
        self.base_url = (base_url or settings.PYPI_JSON_BASE).rstrip("/")
        env = {k: str(v) for k, v in default_environment().items()}
        if target_environment:
            env.update({str(k): str(v) for k, v in target_environment.items()})
        self.env = env
        self.max_nodes = settings.MAX_PROJECT_COMPONENTS if max_nodes is None else max(0, int(max_nodes))
        self.max_requests = 2 * self.max_nodes + 50 if max_requests is None else max(0, int(max_requests))
        self._projects: dict[str, dict | None] = {}
        self._infos: dict[str, dict | None] = {}

    # ------------------------------------------------------------------ public
    def resolve(self, inventory: ProjectInventory) -> ResolutionReport:
        report = ResolutionReport(status="ok")
        try:
            self._resolve(inventory, report)
        except _Abort:
            report.status = "partial"
        finally:
            if self._owns_client:
                self.client.close()
        inventory.components.sort(key=lambda c: c.bom_ref)
        inventory.edges.sort(key=lambda e: (e.parent, e.child))
        order = compute_graph_metadata(inventory)
        # Resolved components inherit the widest scope of their parents; everything else keeps its own.
        explicit = {c.bom_ref: c.scope for c in inventory.components if c.resolution != "resolved"}
        propagate_scope(inventory, explicit, order)
        inventory.warnings = bounded_warnings(inventory.warnings + report.warnings)
        return report

    # ------------------------------------------------------------------ core
    def _resolve(self, inventory: ProjectInventory, report: ResolutionReport) -> None:
        by_name: dict[str, list[Component]] = {}
        for c in inventory.components:
            by_name.setdefault(c.normalized_name, []).append(c)
        edges = {(e.parent, e.child) for e in inventory.edges}
        extras: dict[str, set[str]] = {}
        for d in inventory.dependencies:
            if d.kind == "requirement" and d.extras:
                for c in by_name.get(d.normalized_name, []):
                    extras.setdefault(c.bom_ref, set()).update(d.extras)

        seeds = [c for c in inventory.components if _resolvable(c) and not c.dependencies_known]
        queue: deque[Component] = deque(sorted(seeds, key=lambda c: c.bom_ref))
        processed: dict[str, frozenset[str]] = {}
        while queue:
            comp = queue.popleft()
            wanted = frozenset(extras.get(comp.bom_ref, ()))
            done = processed.get(comp.bom_ref)
            if done is not None and wanted <= done:
                continue
            if comp.bom_ref not in self._infos and report.fetched_nodes >= self.max_nodes:
                warn(report.warnings, f"resolver node budget ({self.max_nodes}) reached; resolution is partial")
                report.status = "partial"
                return
            info = self._version_info(comp, report)
            processed[comp.bom_ref] = wanted | (done or frozenset())
            if info is None:
                continue
            license_expression = info.get("license_expression")
            if not comp.licenses and isinstance(license_expression, str) and \
                    0 < len(license_expression.strip()) <= MAX_LICENSE_EXPRESSION:
                comp.licenses = [license_expression.strip()]
            requires = info.get("requires_dist")
            if requires is None:
                continue
            if not isinstance(requires, list):
                warn(report.warnings, f"{comp.bom_ref}: malformed requires_dist ignored")
                report.status = "partial"
                continue
            complete = len(requires) <= MAX_REQUIRES_PER_PACKAGE
            if not complete:
                warn(report.warnings, f"{comp.bom_ref}: more than {MAX_REQUIRES_PER_PACKAGE} requirements; truncated")
                report.status = "partial"
            for text in requires[:MAX_REQUIRES_PER_PACKAGE]:
                child, req, handled = self._child_for(inventory, comp, text, wanted, by_name, report)
                complete = complete and handled
                if child is None or req is None or child.bom_ref == comp.bom_ref:
                    continue
                key = (comp.bom_ref, child.bom_ref)
                if key not in edges:
                    edges.add(key)
                    spec = bound_specifier(str(req.specifier), report.warnings, comp.bom_ref)
                    inventory.edges.append(DependencyEdge(comp.bom_ref, child.bom_ref, spec or None))
                    report.added_edges += 1
                new_extras = set(req.extras) - extras.get(child.bom_ref, set())
                if new_extras:
                    extras.setdefault(child.bom_ref, set()).update(new_extras)
                if _resolvable(child) and (child.bom_ref not in processed or new_extras):
                    queue.append(child)
            # A second pass (new extras) can only keep or lose completeness, never regain it.
            comp.dependencies_known = complete if done is None else (comp.dependencies_known and complete)

    def _child_for(self, inventory: ProjectInventory, parent: Component, text: object, extras: frozenset[str],
                   by_name: dict[str, list[Component]], report: ResolutionReport):
        """``(child, requirement, handled)``; ``handled`` is False when an applicable dependency got no edge."""
        if not isinstance(text, str) or len(text) > MAX_REQUIREMENT_CHARS:
            return None, None, False
        try:
            req = Requirement(text)
        except InvalidRequirement:
            warn(report.warnings, f"{parent.bom_ref}: invalid requires_dist entry ignored")
            return None, None, False
        if not self._applies(req, extras):
            return None, None, True
        if req.url:
            warn(report.warnings, f"{parent.bom_ref}: dependency '{display(req.name)}' uses a direct URL; not resolved")
            return None, None, False
        name = canonicalize_name(req.name)
        if len(name) > MAX_NAME_LEN or credential_like(req.name):
            return None, None, False
        existing = by_name.get(name, [])
        satisfying = [c for c in existing if c.version and _satisfies(req.specifier, c.version)]
        if satisfying:
            return max(satisfying, key=lambda c: version_sort_key(c.version)), req, True
        unversioned = [c for c in existing if c.version is None]
        if unversioned:
            return unversioned[0], req, True
        if existing:
            warn(report.warnings, f"{parent.bom_ref}: requires {display(name)}{display(str(req.specifier))} but the "
                 f"inventory only has {', '.join(sorted(display(c.version) for c in existing if c.version))}")
        if len(inventory.components) >= settings.MAX_PROJECT_COMPONENTS:
            warn(report.warnings, "MAX_PROJECT_COMPONENTS reached; resolution is partial")
            report.status = "partial"
            return None, None, False
        version = self._choose_version(name, req.specifier, report)
        if version is None:
            return None, None, False
        child = Component(
            bom_ref=make_bom_ref(name, version), name=req.name, normalized_name=name, version=version,
            purl=make_purl(name, version), direct=False, scope=parent.scope, resolution="resolved",
        )
        inventory.components.append(child)
        by_name.setdefault(name, []).append(child)
        report.added_components += 1
        return child, req, True

    def _applies(self, req: Requirement, extras: frozenset[str]) -> bool:
        if req.marker is None:
            return True
        try:
            if not extras:
                return bool(req.marker.evaluate({**self.env, "extra": ""}))
            return any(req.marker.evaluate({**self.env, "extra": extra}) for extra in sorted(extras))
        except Exception:  # undefined marker variables in hostile metadata: treat as not applicable
            return False

    # ------------------------------------------------------------------ registry access
    def _get(self, url: str, report: ResolutionReport) -> object | None:
        if report.requests >= self.max_requests:
            warn(report.warnings, f"resolver request budget ({self.max_requests}) reached; resolution is partial")
            raise _Abort
        report.requests += 1
        try:
            return self.client.get_json(url, allow_404=True, max_bytes=settings.MAX_METADATA_BYTES)
        except OutboundHTTPError as exc:
            warn(report.warnings, f"registry request failed ({exc.kind}{f' {exc.status}' if exc.status else ''})")
            report.status = "partial"
            if exc.kind in _ABORT_KINDS:
                raise _Abort from exc
            return None

    def _version_info(self, comp: Component, report: ResolutionReport) -> dict | None:
        if comp.bom_ref in self._infos:
            return self._infos[comp.bom_ref]
        info = None
        if _NAME_RE.match(comp.normalized_name) and comp.version:
            report.fetched_nodes += 1
            url = f"{self.base_url}/{quote(comp.normalized_name, safe='')}/{quote(comp.version, safe='')}/json"
            data = self._get(url, report)
            candidate = data.get("info") if isinstance(data, dict) else None
            info = candidate if isinstance(candidate, dict) else None
        if info is None:
            warn(report.warnings, f"{comp.bom_ref}: release metadata not available")
            report.status = "partial"
        self._infos[comp.bom_ref] = info
        return info

    def _project(self, name: str, report: ResolutionReport) -> dict | None:
        if name not in self._projects:
            data = self._get(f"{self.base_url}/{quote(name, safe='')}/json", report) if _NAME_RE.match(name) else None
            self._projects[name] = data if isinstance(data, dict) else None
        return self._projects[name]

    def _choose_version(self, name: str, specifier: SpecifierSet, report: ResolutionReport) -> str | None:
        data = self._project(name, report)
        releases = data.get("releases") if data else None
        if not isinstance(releases, dict):
            warn(report.warnings, f"pkg:pypi/{name}: release list not available; dependency not resolved")
            report.status = "partial"
            return None
        candidates: dict[Version, str] = {}
        for raw, files in releases.items():
            if not isinstance(raw, str) or not isinstance(files, list) or not files:
                continue
            try:
                parsed = Version(raw)
            except InvalidVersion:
                continue
            if all(isinstance(f, dict) and f.get("yanked") is True for f in files):
                continue
            if not self._python_ok(files):
                continue
            candidates.setdefault(parsed, raw)
        allowed = list(specifier.filter(candidates))
        if not allowed:
            warn(report.warnings, f"pkg:pypi/{name}: no release satisfies {display(str(specifier)) or '*'}")
            report.status = "partial"
            return None
        return clean_version(candidates[max(allowed)], report.warnings, f"pkg:pypi/{name}")

    def _python_ok(self, files: list) -> bool:
        """True when at least one non-yanked file of a release supports the target interpreter."""
        target = self.env.get("python_full_version", "")
        try:
            python = Version(target)
        except InvalidVersion:
            return True
        for f in files:
            if not isinstance(f, dict) or f.get("yanked") is True:
                continue
            value = f.get("requires_python")
            if not isinstance(value, str) or not value.strip():
                return True
            try:
                if SpecifierSet(value).contains(python, prereleases=True):
                    return True
            except InvalidSpecifier:
                return True
        return False


def _satisfies(specifier: SpecifierSet, version: str) -> bool:
    try:
        return specifier.contains(Version(version), prereleases=True)
    except InvalidVersion:
        return False
