"""Project-level dependency-confusion findings over a :class:`~app.sbom.models.ProjectInventory`.

For every inventory component whose canonical name matches a private-namespace pattern, this
module combines three questions:

1. **Is the name taken on the public index?** Answered from the local public-index snapshot. A live
   lookup against ``PYPI_SIMPLE_BASE`` is made *only* when ``settings.DEPCONF_ALLOW_PUBLIC_LOOKUP`` is
   true *and* the snapshot is missing or incomplete, because the lookup discloses the private name; it
   is limited to ``MAX_PUBLIC_LOOKUPS`` names per call. Without either source, presence is ``unknown``
   (never assumed absent) and one info ``TOOL_UNAVAILABLE`` finding says so.
2. **Can resolution reach a public index?** Inventory-wide *exposure reasons* from the recorded index
   configuration, evaluated per manifest file (``--no-index`` switches a file's reasons off):
   ``extra-index-url`` - an ``--extra-index-url`` merges indexes and at least one index in play (the
   ``--index-url``s, or pip's default PyPI when none is set, plus the extras) is not a configured
   private index; ``public-index-configured`` - an index / find-links / Poetry / Pipenv source on a
   public registry host. Per component: ``declared-public-index`` - a declaration or lock entry names a
   public index for it (e.g. Pipfile.lock ``"index": "pypi"``); ``locked-without-source`` - a
   ``poetry.lock`` entry without a ``[package.source]`` table, which Poetry writes for packages it
   resolved from PyPI.
3. **Is the component protected anyway?** ``direct-url`` (every declaration installs from a
   URL/VCS/path, not an index) and ``source-pinned`` (every declaration is routed to a non-public index
   by name, e.g. Poetry ``source = "corp"`` or a Pipfile ``index``) clear the inventory-wide reasons;
   ``hash-pinned`` (every declaration carries hashes) makes a substituted artifact fail hash checking,
   so it clears them too - but not the per-component reasons, where the lock already records the
   public index as the source of the hashed artifact.

Findings (severity / weight / confidence):

* ``NAMESPACE_COLLISION`` (high / 6.0 / 0.8) - the private name exists on the public index.
* ``DEPENDENCY_CONFUSION`` (critical / 12.0) - the name exists publicly *and* the component is exposed:
  0.9, or 0.85 when the only evidence is exact pinning without hashes (a substitute must publish that
  exact version) or a ``locked-without-source`` entry (inferred from Poetry's lock format).
* ``DEPENDENCY_CONFUSION`` (high / 6.0 / 0.6) - exposed, but the name is absent from the snapshot or
  its presence is unknown: anyone can still register it (the classic attack), so the risk is latent.

``INDEX_SOURCE_AMBIGUITY`` (one finding per ``--extra-index-url`` line) is emitted by
:mod:`app.sbom.hygiene`; it is referenced, never duplicated: exposure evidence names the code, and
when the caller passes those findings as ``related_findings`` their ids are linked in ``related``.

Limitations, stated plainly: index configuration outside the manifests (``pip.conf``,
``PIP_INDEX_URL``/``PIP_EXTRA_INDEX_URL``, CI settings) is invisible, so a project with no recorded
index options produces no exposure reason; pip options are evaluated per file rather than per
install invocation; Poetry source priorities (``supplemental`` / ``explicit``) are not modelled beyond
per-dependency ``source =`` routing. An inventory without ``index_sources`` (e.g. rebuilt from stored data)
falls back to its flat ``index_urls`` / ``extra_index_urls`` lists, treated as one manifest; those exposure
reasons carry no file or line. Locations are the components' recorded declaration lines only.

Findings record ``evidence["context"] = "resolution-time"``: the risk materialises when an installer
resolves names against its indexes, not in code a package runs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from app.analysis.depconf import (
    OTHER,
    PRIVATE,
    PUBLIC,
    IndexClassifier,
    NamespaceMatch,
    PrivateNamespaces,
    canonical_name,
    resolve_private_namespaces,
)
from app.analysis.depconf.index_snapshot import (
    ABSENT,
    PRESENT,
    SIMPLE_JSON_ACCEPT,
    UNKNOWN,
    PublicIndexSnapshot,
    SnapshotStatus,
    load_configured_snapshot,
)
from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.core.config import settings
from app.core.http import OutboundHTTPError, SafeHttpClient
from app.core.logging import get_logger
from app.sbom.models import Component, ManifestDependency, ProjectInventory
from app.sbom.parsers import redact_url

log = get_logger("warden.depconf.project")

ANALYZER_NAME = "dependency_confusion"
ANALYZER_VERSION = "1.0.0"
MAX_PUBLIC_LOOKUPS = 100
LOOKUP_MAX_BYTES = 4 * 1024 * 1024
# Resolution, not install-time: see app.analysis.analyzers.dependency_confusion for why the label matters.
CONTEXT = "resolution-time"
PIPELINE_PROVENANCE = "analysis-pipeline"
SNAPSHOT_PROVENANCE = Provenance.intel("public-index-snapshot")
PIP_DEFAULT_INDEX = "https://pypi.org/simple (pip default)"
POETRY_LOCK_TYPE = "poetry-lock"
_MAX_EVIDENCE_ITEMS = 10
_MAX_FALLBACK_SOURCES = 64
_INDEX_KINDS = frozenset({"index-url", "extra-index-url", "find-links", "poetry-source", "pipenv-source",
                          "poetry-lock-source"})
_LOCK_REASONS = frozenset({"declared-public-index", "locked-without-source"})


class _UseConfigured:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "USE_CONFIGURED_SNAPSHOT"


USE_CONFIGURED_SNAPSHOT: Any = _UseConfigured()


# --------------------------------------------------------------------------- public lookup (opt-in)
class PublicIndexLookup:
    """Live presence check against the public simple index (PEP 691). **Discloses queried names.**

    :func:`project_confusion_findings` uses it only when ``settings.DEPCONF_ALLOW_PUBLIC_LOOKUP`` is
    true. Answers ``present`` (HTTP 200), ``absent`` (404) or ``unknown`` (any other outcome, invalid
    name, or once ``max_lookups`` requests have been made). Results are memoised per instance.
    """

    def __init__(self, *, http: SafeHttpClient | None = None, simple_base: str | None = None,
                 max_lookups: int = MAX_PUBLIC_LOOKUPS) -> None:
        self._owned = http is None
        self._http = http or SafeHttpClient(
            name="depconf-public-lookup", allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
            max_response_bytes=LOOKUP_MAX_BYTES, timeout=float(settings.FETCH_TIMEOUT_SECONDS), retries=1,
            rate_limit_per_second=5.0, total_timeout=float(settings.FETCH_TIMEOUT_SECONDS) * 2,
        )
        self._base = (simple_base or settings.PYPI_SIMPLE_BASE).rstrip("/")
        self._max = max(0, int(max_lookups))
        self._results: dict[str, str] = {}
        self.lookups = 0
        self.limit_reached = False

    @property
    def max_lookups(self) -> int:
        return self._max

    def presence(self, name: object) -> str:
        canonical = canonical_name(name)
        if canonical is None:
            return UNKNOWN
        if canonical in self._results:
            return self._results[canonical]
        if self.lookups >= self._max:
            self.limit_reached = True
            return UNKNOWN
        self.lookups += 1
        status: int | None
        try:
            result = self._http.request("GET", f"{self._base}/{quote(canonical, safe='')}/",
                                        headers={"Accept": SIMPLE_JSON_ACCEPT}, max_bytes=LOOKUP_MAX_BYTES)
            status = result.status
        except OutboundHTTPError as exc:
            # A project page larger than the cap still answered 200: the name exists.
            status = exc.status if exc.kind == "too_large" else None
            if status is None:
                log.warning("depconf_public_lookup_failed", kind=exc.kind)  # the name itself is not logged
        answer = PRESENT if status == 200 else ABSENT if status == 404 else UNKNOWN
        self._results[canonical] = answer
        return answer

    def close(self) -> None:
        if self._owned:
            self._http.close()


# --------------------------------------------------------------------------- exposure model
def _reason(reason: str, *, url: object, file: object, line: object, classification: str | None,
            **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "reason": reason,
        "url": redact_url(url) if isinstance(url, str) and url else None,
        "file": file if isinstance(file, str) else None,
        "line": line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None,
        "index_classification": classification,
    }
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def _index_sources(inventory: ProjectInventory) -> list[Mapping[str, Any]]:
    """Recorded index sources, or - for an inventory built without them (e.g. restored from stored data) - the flat
    ``index_urls`` / ``extra_index_urls`` lists as sources without a file or line (bounded)."""
    recorded = [s for s in (inventory.index_sources or ()) if isinstance(s, Mapping)]
    if recorded:
        return recorded
    fallback: list[Mapping[str, Any]] = []
    for kind, urls in (("index-url", inventory.index_urls), ("extra-index-url", inventory.extra_index_urls)):
        for url in list(urls or ())[:_MAX_FALLBACK_SOURCES]:
            if isinstance(url, str) and url.strip():
                fallback.append({"kind": kind, "url": url, "file": None, "line": None})
    return fallback


def exposure_reasons(inventory: ProjectInventory, classifier: IndexClassifier) -> list[dict[str, Any]]:
    """Inventory-wide reasons a registry-resolved component can come from a public index."""
    by_file: dict[str, list[Mapping[str, Any]]] = {}
    for source in _index_sources(inventory):
        by_file.setdefault(str(source.get("file") or ""), []).append(source)
    reasons: list[dict[str, Any]] = []
    for file in sorted(by_file):
        entries = sorted(by_file[file], key=lambda s: (s.get("line") or 0, str(s.get("kind")), str(s.get("url"))))
        if any(s.get("kind") == "no-index" for s in entries):
            continue
        primaries = [s for s in entries if s.get("kind") == "index-url"]
        extras = [s for s in entries if s.get("kind") == "extra-index-url"]
        flagged: set[int] = set()
        if extras:
            classes = [classifier.classify(s.get("url")) for s in primaries] or [PUBLIC]
            classes += [classifier.classify(s.get("url")) for s in extras]
            if any(c != PRIVATE for c in classes):
                for s in extras:
                    flagged.add(id(s))
                    reasons.append(_reason(
                        "extra-index-url", url=s.get("url"), file=s.get("file"), line=s.get("line"),
                        classification=classifier.classify(s.get("url")),
                        primary_index=None if primaries else PIP_DEFAULT_INDEX,
                        see_also=Code.INDEX_SOURCE_AMBIGUITY,
                    ))
        for s in entries:
            if id(s) in flagged or s.get("kind") not in _INDEX_KINDS:
                continue
            if classifier.classify(s.get("url")) == PUBLIC:
                reasons.append(_reason("public-index-configured", url=s.get("url"), file=s.get("file"),
                                       line=s.get("line"), classification=PUBLIC, kind=s.get("kind")))
    return reasons


@dataclass
class _Facts:
    considered: list[ManifestDependency] = field(default_factory=list)
    direct_url: bool = False
    source_pinned: bool = False
    hash_pinned: bool = False
    exact_pin: bool = False
    lock_reasons: list[dict[str, Any]] = field(default_factory=list)

    @property
    def mitigations(self) -> list[str]:
        out = []
        if self.direct_url:
            out.append("direct-url")
        if self.source_pinned:
            out.append("source-pinned")
        if self.hash_pinned:
            out.append("hash-pinned")
        return out


def _component_facts(component: Component, decls: Sequence[ManifestDependency], classifier: IndexClassifier,
                     manifest_types: Mapping[str, Any]) -> _Facts:
    locks = [d for d in decls if d.kind == "lock"]
    considered = locks or [d for d in decls if d.kind == "requirement"]
    facts = _Facts(considered=considered)
    if not considered:
        facts.exact_pin = component.resolution in ("pinned", "locked")
        return facts
    facts.direct_url = all(d.url for d in considered)
    facts.source_pinned = all(d.index_url and classifier.classify(d.index_url) in (PRIVATE, OTHER) for d in considered)
    facts.hash_pinned = all(d.hashes for d in considered)
    facts.exact_pin = component.resolution in ("pinned", "locked") or all(d.pinned_version for d in considered)
    if facts.direct_url or facts.source_pinned:
        return facts
    for d in sorted(considered, key=lambda d: (d.source_file, d.line or 0)):
        if d.url:
            continue
        if d.index_url and classifier.classify(d.index_url) == PUBLIC:
            facts.lock_reasons.append(_reason("declared-public-index", url=d.index_url, file=d.source_file,
                                              line=d.line, classification=PUBLIC))
        elif d.kind == "lock" and not d.index_url and manifest_types.get(d.source_file) == POETRY_LOCK_TYPE:
            facts.lock_reasons.append(_reason("locked-without-source", url=None, file=d.source_file, line=d.line,
                                              classification=None))
    return facts


# --------------------------------------------------------------------------- findings
def _location(component: Component) -> Location | None:
    declared = [d for d in component.declared_at if isinstance(d, Mapping) and d.get("file")]
    declared.sort(key=lambda d: (str(d.get("file")), d.get("line") or 0))
    with_line = [d for d in declared if isinstance(d.get("line"), int) and d.get("line") >= 1]
    chosen = (with_line or declared or [None])[0]
    if not chosen:
        return None
    return Location(file=str(chosen["file"]), line=chosen.get("line") if chosen in with_line else None)


def _declarations(component: Component) -> list[str]:
    out = []
    for d in component.declared_at[:_MAX_EVIDENCE_ITEMS]:
        if isinstance(d, Mapping) and d.get("file"):
            out.append(f"{d['file']}:{d['line']}" if d.get("line") else str(d["file"]))
    return out


def _unique_reasons(reasons: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out = []
    for r in reasons:
        key = (r.get("reason"), r.get("url"), r.get("file"), r.get("line"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _presence(canonical: str, snapshot: PublicIndexSnapshot | None, lookup: PublicIndexLookup | None,
              ) -> tuple[str, str | None]:
    if snapshot is not None:
        answer = snapshot.presence(canonical)
        if answer != UNKNOWN:
            return answer, "snapshot"
    if lookup is not None:
        answer = lookup.presence(canonical)
        if answer != UNKNOWN:
            return answer, "public-lookup"
    return UNKNOWN, None


def _base_evidence(component: Component, canonical: str, match: NamespaceMatch, presence: str,
                   presence_source: str | None, snapshot: PublicIndexSnapshot | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "package": component.name,
        "normalized_name": canonical,
        "version": component.version,
        "resolution": component.resolution,
        **match.to_evidence(),
        "public_presence": presence,
        "presence_source": presence_source,
        "declarations": _declarations(component),
        "context": CONTEXT,
    }
    if presence_source == "snapshot" and snapshot is not None:
        evidence["snapshot"] = {"source": snapshot.header.source, "generated_at": snapshot.header.generated_at}
    return evidence


def _related_ids(reasons: Sequence[dict[str, Any]], related: Sequence[Finding]) -> tuple[str, ...]:
    # Only reasons with a real manifest position can be tied to a hygiene finding at that position.
    spots = {(r.get("file"), r.get("line")) for r in reasons
             if r.get("reason") == "extra-index-url" and r.get("file")}
    if not spots:
        return ()
    ids = []
    for f in related:
        if f.code != Code.INDEX_SOURCE_AMBIGUITY:
            continue
        where = (f.location.file, f.location.line) if f.location else (None, None)
        if where in spots:
            ids.append(f.finding_id)
    return tuple(sorted(set(ids)))


def _resolve_snapshot(snapshot: Any) -> tuple[PublicIndexSnapshot | None, str | None]:
    if snapshot is USE_CONFIGURED_SNAPSHOT:
        snapshot = load_configured_snapshot()
    if isinstance(snapshot, SnapshotStatus):
        return snapshot.snapshot, snapshot.detail
    if isinstance(snapshot, PublicIndexSnapshot):
        return snapshot, None if snapshot.complete else "snapshot incomplete"
    return None, "no public index snapshot supplied"


def project_confusion_findings(
    inventory: ProjectInventory,
    *,
    patterns: PrivateNamespaces | Iterable[str] | None = None,
    snapshot: PublicIndexSnapshot | SnapshotStatus | None = USE_CONFIGURED_SNAPSHOT,
    private_index_urls: Iterable[str] | None = None,
    lookup: PublicIndexLookup | None = None,
    related_findings: Iterable[Finding] = (),
) -> list[Finding]:
    """Dependency-confusion findings for a project inventory, deterministically ordered.

    ``patterns`` default to ``settings.PRIVATE_PACKAGE_PATTERNS``; ``private_index_urls`` to
    ``settings.PRIVATE_INDEX_URLS``; ``snapshot`` to the configured public-index snapshot (pass ``None``
    for none). ``lookup`` injects a :class:`PublicIndexLookup` (e.g. with a test HTTP client); it - or a
    default one - is consulted only when ``settings.DEPCONF_ALLOW_PUBLIC_LOOKUP`` is true.
    """
    if isinstance(patterns, PrivateNamespaces):
        namespaces = patterns
    elif patterns is None:
        namespaces = resolve_private_namespaces()
    else:
        namespaces = PrivateNamespaces.from_sources({"settings": list(patterns)})
    if not namespaces.configured:
        return []

    matched: list[tuple[Component, str, NamespaceMatch]] = []
    for component in sorted(inventory.components, key=lambda c: c.bom_ref):
        if component.ecosystem != "pypi":
            continue  # private namespaces and index classification are PyPI concepts
        canonical = canonical_name(component.normalized_name) or canonical_name(component.name)
        match = namespaces.match(canonical) if canonical else None
        if match is not None:
            matched.append((component, match.name, match))
    if not matched:
        return []

    classifier = IndexClassifier(private_index_urls)
    snap, snapshot_detail = _resolve_snapshot(snapshot)
    allow_lookup = bool(settings.DEPCONF_ALLOW_PUBLIC_LOOKUP)
    own_lookup = None
    if not allow_lookup:
        lookup = None  # privacy: never disclose private names unless explicitly allowed by configuration
    elif lookup is None and (snap is None or not snap.complete):
        lookup = own_lookup = PublicIndexLookup()

    decls: dict[str, list[ManifestDependency]] = {}
    for d in inventory.dependencies:
        key = canonical_name(d.normalized_name) or canonical_name(d.name)
        if key:
            decls.setdefault(key, []).append(d)
    manifest_types = {m.get("file"): m.get("type") for m in inventory.manifests if isinstance(m, Mapping)}
    related = [f for f in related_findings if isinstance(f, Finding)]
    inventory_reasons = exposure_reasons(inventory, classifier)

    findings: list[Finding] = []
    unknown = 0
    try:
        for component, canonical, match in matched:
            presence, presence_source = _presence(canonical, snap, lookup)
            unknown += presence == UNKNOWN
            facts = _component_facts(component, decls.get(canonical, []), classifier, manifest_types)
            routed = facts.direct_url or facts.source_pinned
            substitution_blocked = facts.hash_pinned and not facts.lock_reasons
            reasons = _unique_reasons([
                *facts.lock_reasons,
                *([] if routed or substitution_blocked else inventory_reasons),
            ])
            location = _location(component)
            base = _base_evidence(component, canonical, match, presence, presence_source, snap)
            base["mitigations"] = facts.mitigations

            if presence == PRESENT:
                findings.append(Finding(
                    Code.NAMESPACE_COLLISION, Severity.high, 6.0,
                    f"Internal package name '{component.name}' (private pattern '{match.pattern}') is registered "
                    "on the public index",
                    base, confidence=0.8, location=location,
                    provenance=SNAPSHOT_PROVENANCE if presence_source == "snapshot" else Provenance.REGISTRY,
                ))
            if not reasons:
                continue
            evidence = {**base, "exposure": reasons[:_MAX_EVIDENCE_ITEMS]}
            related_ids = _related_ids(reasons, related)
            if presence == PRESENT:
                # Weaker evidence: only Poetry's source-less lock entries, or an exact pin without hashes.
                inferred_lock_only = bool(facts.lock_reasons) and all(
                    r["reason"] == "locked-without-source" for r in facts.lock_reasons
                ) and all(r["reason"] in _LOCK_REASONS for r in reasons)
                weak = inferred_lock_only or (facts.exact_pin and not facts.lock_reasons)
                how = ("its lock entry resolves it from a public index" if facts.lock_reasons
                       else "the configured indexes let installers resolve it from a public index")
                findings.append(Finding(
                    Code.DEPENDENCY_CONFUSION, Severity.critical, 12.0,
                    f"Internal package '{component.name}' exists on the public index and {how}",
                    evidence, capability=Capability.DEPENDENCY_CONFUSION, confidence=0.85 if weak else 0.9,
                    location=location, provenance=Provenance.STATIC, related=related_ids,
                ))
            else:
                state = "is not in the public index snapshot" if presence == ABSENT else "has unknown public presence"
                findings.append(Finding(
                    Code.DEPENDENCY_CONFUSION, Severity.high, 6.0,
                    f"Internal package '{component.name}' {state}, but the configured indexes let installers "
                    "resolve it from a public index where anyone can register the name",
                    evidence, confidence=0.6, location=location, provenance=Provenance.STATIC, related=related_ids,
                ))
    finally:
        if own_lookup is not None:
            own_lookup.close()

    if unknown:
        detail = snapshot_detail or "snapshot incomplete"
        if lookup is not None and lookup.limit_reached:
            detail = f"{detail}; public lookup limit ({lookup.max_lookups}) reached"
        findings.append(Finding(
            Code.TOOL_UNAVAILABLE, Severity.info, 0.0,
            f"Public-index presence of {unknown} private-namespace component(s) is unknown",
            {"tool": "public-index-snapshot", "detail": detail,
             "public_lookup": "enabled" if allow_lookup else "disabled", "unknown_components": unknown},
            confidence=1.0, provenance=PIPELINE_PROVENANCE,
        ))

    stamped = [f.with_defaults(analyzer=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION) for f in findings]
    return sorted(stamped, key=lambda f: (f.code, (f.location.file or "") if f.location else "",
                                          (f.location.line or 0) if f.location else 0, f.finding_id))


__all__ = [
    "ANALYZER_NAME",
    "ANALYZER_VERSION",
    "MAX_PUBLIC_LOOKUPS",
    "USE_CONFIGURED_SNAPSHOT",
    "PublicIndexLookup",
    "exposure_reasons",
    "project_confusion_findings",
]
