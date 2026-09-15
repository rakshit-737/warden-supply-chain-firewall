"""Dependency-hygiene findings for a project inventory.

These are configuration observations about how a project pins and sources its dependencies -
not evidence that any package is malicious or vulnerable - and are reported at low/medium
severity to match:

* ``UNPINNED_DEPENDENCY`` (low) - a direct dependency whose version is neither pinned (``==``)
  nor locked. What gets installed can change between builds, so the artifact Warden analysed may
  not be the one deployed. One finding per component, located at its first declaration.
* ``MISSING_HASHES`` (low) - one aggregated finding per requirements file (or lock file) in
  which no entry carries a hash, so pip's hash-checking mode cannot protect the install.
* ``INDEX_SOURCE_AMBIGUITY`` (medium) - each ``--extra-index-url``: pip treats all indexes as
  equals and installs the best version from any of them, the root cause of dependency confusion.

Locations are only the file/line positions the parsers recorded; unknown lines stay unknown.
"""

from __future__ import annotations

from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Code
from app.sbom.models import Component, ProjectInventory
from app.sbom.parsers import LOCK_TYPES, REQUIREMENTS

ANALYZER_NAME = "sbom-hygiene"
ANALYZER_VERSION = "1.0.0"
_MAX_EVIDENCE_ITEMS = 10


def hygiene_findings(inventory: ProjectInventory) -> list[Finding]:
    """Return dependency-hygiene findings, deterministically ordered."""
    findings = [*_unpinned(inventory), *_missing_hashes(inventory), *_index_ambiguity(inventory)]
    stamped = [f.with_defaults(analyzer=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION) for f in findings]
    return sorted(stamped, key=lambda f: (f.code, (f.location.file or "") if f.location else "",
                                          (f.location.line or 0) if f.location else 0, f.finding_id))


def _first_location(component: Component) -> Location | None:
    declared = sorted(component.declared_at, key=lambda d: (str(d.get("file") or ""), d.get("line") or 0))
    with_line = [d for d in declared if d.get("line")]
    chosen = (with_line or declared or [None])[0]
    if not chosen or not chosen.get("file"):
        return None
    return Location(file=chosen["file"], line=chosen.get("line"))


def _unpinned(inventory: ProjectInventory) -> list[Finding]:
    url_declared = {d.normalized_name for d in inventory.dependencies if d.kind == "requirement" and d.url}
    out = []
    for c in sorted(inventory.components, key=lambda c: c.bom_ref):
        if not c.direct or c.resolution in ("pinned", "locked"):
            continue
        declarations = [f"{d['file']}:{d['line']}" if d.get("line") else str(d.get("file"))
                        for d in c.declared_at[:_MAX_EVIDENCE_ITEMS]]
        from_url = c.normalized_name in url_declared
        if from_url:
            message = (f"Direct dependency '{c.name}' is installed from a direct URL/VCS/path reference rather "
                       "than a pinned registry version")
        else:
            message = f"Direct dependency '{c.name}' is not pinned to an exact version ({c.specifier or 'any version'})"
        out.append(Finding(
            Code.UNPINNED_DEPENDENCY, Severity.low, 1.0, message,
            {"package": c.name, "specifier": c.specifier or "*", "declarations": declarations,
             "source": "url" if from_url else "registry", "scope": c.scope},
            confidence=0.8 if from_url else 0.95,
            location=_first_location(c),
            provenance=Provenance.STATIC,
        ))
    return out


def _missing_hashes(inventory: ProjectInventory) -> list[Finding]:
    types = {m.get("file"): m.get("type") for m in inventory.manifests}
    by_file: dict[str, list] = {}
    for d in inventory.dependencies:
        by_file.setdefault(d.source_file, []).append(d)
    out = []
    for file in sorted(by_file):
        mtype = types.get(file)
        if mtype == REQUIREMENTS:
            entries = [d for d in by_file[file] if d.kind == "requirement"]
            label = "requirement"
        elif mtype in LOCK_TYPES:
            entries = [d for d in by_file[file] if d.kind == "lock"]
            label = "locked package"
        else:
            continue
        if not entries or any(d.hashes for d in entries):
            continue
        names = sorted({d.name for d in entries})
        out.append(Finding(
            Code.MISSING_HASHES, Severity.low, 1.0,
            f"None of the {len(entries)} {label} entr{'y' if len(entries) == 1 else 'ies'} in {file} carry a hash",
            {"file": file, "manifest_type": mtype, "entry_count": len(entries),
             "examples": names[:_MAX_EVIDENCE_ITEMS]},
            confidence=0.95,
            location=Location(file=file),
            provenance=Provenance.STATIC,
        ))
    return out


def _index_ambiguity(inventory: ProjectInventory) -> list[Finding]:
    out = []
    sources = sorted(inventory.index_sources, key=lambda s: (str(s.get("file") or ""), s.get("line") or 0))
    for source in sources:
        if source.get("kind") != "extra-index-url":
            continue
        file = source.get("file")
        primary = next((s.get("url") for s in sources if s.get("kind") == "index-url" and s.get("file") == file), None)
        out.append(Finding(
            Code.INDEX_SOURCE_AMBIGUITY, Severity.medium, 3.0,
            f"--extra-index-url adds a second package index ({source.get('url')}); pip may install a package "
            "from whichever index offers the highest version",
            {"extra_index_url": source.get("url"), "index_url": primary or "https://pypi.org/simple (pip default)",
             "file": file, "line": source.get("line")},
            confidence=0.8,
            location=Location(file=file, line=source.get("line")) if file else None,
            provenance=Provenance.STATIC,
        ))
    return out
