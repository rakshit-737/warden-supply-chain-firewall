"""Project inventory data model shared by manifest parsers, SBOM builders and the graph engine.

A ``ProjectInventory`` is the ecosystem-neutral result of reading a project's dependency
manifests: the components it declares or locks, the dependency edges between them, and
the provenance of each declaration (file + line). Manifests are attacker-influenced input
(a pull request can edit them), so everything here is plain data with no behaviour that
touches the filesystem or network.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import quote

_PEP503_RE = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """PEP 503 normalised project name."""
    return _PEP503_RE.sub("-", name.strip()).lower()


def make_purl(name: str, version: str | None, ecosystem: str = "pypi") -> str | None:
    """Package URL (purl) for a component; ``None`` when the version is unknown.

    For PyPI the purl spec lower-cases the name and replaces underscores with dashes, which
    matches PEP 503 normalisation for all valid project names. The version is percent-encoded as
    the purl specification requires, so local versions and epochs get the canonical form that
    reference implementations produce (``2.0.1+cu118`` -> ``2.0.1%2Bcu118``, ``1!2.0`` ->
    ``1%212.0``); plain PEP 440 versions are unchanged.
    """
    if ecosystem != "pypi" or not version:
        return None
    return f"pkg:pypi/{normalize_name(name)}@{quote(version, safe='')}"


def make_bom_ref(name: str, version: str | None, ecosystem: str = "pypi") -> str:
    """Stable in-document reference: the purl when versioned, else ``pkg:pypi/<name>``."""
    purl = make_purl(name, version, ecosystem)
    return purl if purl else f"pkg:{ecosystem}/{normalize_name(name)}"


@dataclass
class ManifestDependency:
    name: str
    normalized_name: str
    specifier: str = ""  # PEP 440 specifier set as written ("" when unconstrained)
    pinned_version: str | None = None  # exact version when specifier is ==X (no wildcard) or locked
    extras: list[str] = field(default_factory=list)
    markers: str | None = None
    source_file: str = ""
    line: int | None = None  # 1-based line of the declaration, when the format has lines
    hashes: list[str] = field(default_factory=list)  # "sha256:<hex>"
    index_url: str | None = None
    direct: bool = True
    scope: str = "required"  # required | optional | dev
    group: str | None = None  # optional-dependency extra / poetry group name
    # --- additive (Warden 2 SBOM engine) ---------------------------------------------
    # Credential-redacted direct URL / VCS / path reference. Never fetched by Warden.
    url: str | None = None
    # requirement (declared) | constraint (pip -c, constrains but does not add) | lock (lock-file entry)
    kind: str = "requirement"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Component:
    bom_ref: str
    name: str
    normalized_name: str
    version: str | None
    purl: str | None
    ecosystem: str = "pypi"
    direct: bool = True
    scope: str = "required"
    hashes: dict[str, str] = field(default_factory=dict)  # {"sha256": "<hex>"}
    licenses: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    declared_at: list[dict] = field(default_factory=list)  # [{"file": ..., "line": ...}]
    resolution: str = "unresolved"  # pinned | locked | resolved | unresolved
    depth: int | None = None  # 1 = direct dependency of the project root
    introduced_by: list[str] = field(default_factory=list)  # bom_refs of direct deps pulling this in
    specifier: str = ""
    # --- additive (Warden 2 SBOM engine) ---------------------------------------------
    # Every distribution-file digest recorded by the manifests ("sha256:<hex>"). A release has
    # one file per wheel/sdist, so ``hashes`` (one value per algorithm) is only filled when a
    # single digest is known; SBOM builders emit ``file_hashes``.
    file_hashes: list[str] = field(default_factory=list)
    # True when this component's own dependencies were recorded (lock file or resolver), so
    # an empty child list means "no dependencies" rather than "unknown".
    dependencies_known: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DependencyEdge:
    parent: str  # bom_ref (or the inventory root_ref)
    child: str  # bom_ref
    specifier: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProjectInventory:
    project_name: str
    root_ref: str
    components: list[Component] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)  # [{"file", "type", "sha256"}]
    warnings: list[str] = field(default_factory=list)
    index_urls: list[str] = field(default_factory=list)
    extra_index_urls: list[str] = field(default_factory=list)
    dependencies: list[ManifestDependency] = field(default_factory=list)  # raw declarations
    # --- additive (Warden 2 SBOM engine) ---------------------------------------------
    # Where package indexes were configured: [{"kind", "url" (credential-redacted), "file", "line"}].
    index_sources: list[dict] = field(default_factory=list)
    # Redacted index URLs whose host is not the public PyPI registry.
    private_index_hints: list[str] = field(default_factory=list)
    # Static version of the project itself, when the root pyproject.toml declares one.
    project_version: str | None = None

    def component(self, bom_ref: str) -> Component | None:
        for c in self.components:
            if c.bom_ref == bom_ref:
                return c
        return None

    def direct_components(self) -> list[Component]:
        return [c for c in self.components if c.direct]

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "root_ref": self.root_ref,
            "components": [c.to_dict() for c in self.components],
            "edges": [e.to_dict() for e in self.edges],
            "manifests": list(self.manifests),
            "warnings": list(self.warnings),
            "index_urls": list(self.index_urls),
            "extra_index_urls": list(self.extra_index_urls),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "index_sources": [dict(s) for s in self.index_sources],
            "private_index_hints": list(self.private_index_hints),
            "project_version": self.project_version,
        }
