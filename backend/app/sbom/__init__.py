"""Warden SBOM engine: manifest parsing, dependency inventory, CycloneDX / SPDX generation.

Public entry points are exported lazily so that importing :mod:`app.sbom.models` (a plain data
module shared with the graph engine) does not pull in parsers, HTTP or analysis code.

* :func:`parse_project` - in-memory manifests -> :class:`ProjectInventory`
* :func:`discover_manifests` - read known manifests from a local checkout (no link following)
* :func:`resolve_transitive` - optional PyPI-backed transitive edges (off by default)
* :func:`build_cyclonedx` / :func:`build_spdx` - CycloneDX 1.6 / SPDX 2.3 JSON documents
* :func:`hygiene_findings` - pinning / hash / index-configuration findings
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "parse_project": ("app.sbom.parsers", "parse_project"),
    "discover_manifests": ("app.sbom.discover", "discover_manifests"),
    "resolve_transitive": ("app.sbom.resolver", "resolve_transitive"),
    "build_cyclonedx": ("app.sbom.cyclonedx", "build"),
    "build_spdx": ("app.sbom.spdx", "build"),
    "hygiene_findings": ("app.sbom.hygiene", "hygiene_findings"),
    "Component": ("app.sbom.models", "Component"),
    "DependencyEdge": ("app.sbom.models", "DependencyEdge"),
    "ManifestDependency": ("app.sbom.models", "ManifestDependency"),
    "ProjectInventory": ("app.sbom.models", "ProjectInventory"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'app.sbom' has no attribute {name!r}")
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value
