"""Analyzer protocol and the shared package context (Warden X contract).

An ``Analyzer`` is a pure function object: given a ``PackageContext`` (already-fetched
metadata, a bounded inventory of archive members, and decoded source files), it returns a
list of :class:`~app.analysis.findings.Finding`. Analyzers never execute package code.
Analyzers backed by network intelligence declare ``requires_network = True`` and are
skipped in offline scans; analyzers backed by an external tool report ``availability()``
so a missing tool degrades gracefully instead of silently producing "no findings".

Everything inside a ``PackageContext`` except ``options`` is derived from attacker-controlled
input (archive contents *and* registry metadata) and must be treated as hostile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.analysis.findings import Finding


@dataclass
class SourceFile:
    relpath: str
    text: str  # decoded (best-effort) file contents, truncated to the analyzer cap
    size: int
    truncated: bool = False
    sha256: str | None = None  # of the full member bytes when known


@dataclass
class InventoryEntry:
    """One archive member as seen by safe extraction (whether or not its bytes were kept)."""

    relpath: str
    size: int  # declared size from the archive header
    kind: str = "file"  # file | dir | symlink | hardlink | device | other
    sha256: str | None = None  # None when the member was not read (skipped/too large)
    magic: str | None = None  # elf | pe | macho | zip | gzip | bzip2 | xz | tar | wheel | None
    is_text: bool = False
    is_executable_binary: bool = False  # ELF / PE / Mach-O header detected
    mode: int | None = None  # permission bits from the archive header, if any
    retained: bool = False  # True when text is in ``files`` or bytes are in ``binaries``
    skipped_reason: str | None = None  # e.g. "too_large", "unsafe_path", "symlink"


@dataclass
class ArtifactInfo:
    """A distribution file published for the release (from registry metadata)."""

    filename: str
    url: str
    packagetype: str  # "sdist" | "bdist_wheel" | other registry value
    size: int | None = None
    digests: dict[str, str] = field(default_factory=dict)  # e.g. {"sha256": "..."}
    upload_time: str | None = None  # ISO-8601
    yanked: bool = False
    yanked_reason: str | None = None
    requires_python: str | None = None
    downloaded_sha256: str | None = None  # sha256 of the bytes Warden actually analysed
    hash_verified: bool | None = None  # None: not downloaded / no registry digest to compare


@dataclass
class ReleaseInfo:
    version: str
    upload_time: str | None  # earliest upload time among the release's files, ISO-8601
    yanked: bool = False
    file_count: int = 0


@dataclass
class ScanOptions:
    """Caller-controlled scan switches (the only non-hostile part of a context)."""

    offline: bool = False  # never contact intelligence / provenance services
    intel: bool = True  # vulnerability intelligence enrichment
    provenance: bool = True  # attestation / integrity API lookups
    analyze_wheels: bool = True  # also inventory a wheel for sdist/wheel divergence
    private_namespaces: tuple[str, ...] = ()  # glob patterns of internal package names
    environment: str | None = None  # policy environment (development|staging|production)
    project_context: dict | None = None  # e.g. blast radius from a project dependency graph


@dataclass
class PackageContext:
    ecosystem: str
    name: str
    version: str
    # Slim registry metadata (see acquisition.pypi for keys). Underscore-prefixed keys are
    # values Warden derived (e.g. ``_age_days``); all others are copied from the registry.
    metadata: dict = field(default_factory=dict)
    # Extracted, size-capped *text* files of interest (Python, build scripts, config).
    files: list[SourceFile] = field(default_factory=list)
    # Non-fatal issues encountered while building the context (fetch/extract problems).
    context_signals: list[Finding] = field(default_factory=list)
    # Every archive member seen by safe extraction, bounded by MAX_EXTRACTED_FILES.
    inventory: list[InventoryEntry] = field(default_factory=list)
    # Raw bytes of retained non-text members (bounded budget) for YARA / secret scanning.
    binaries: dict[str, bytes] = field(default_factory=dict)
    # All distribution files the registry lists for this release.
    artifacts: list[ArtifactInfo] = field(default_factory=list)
    # The artifact whose contents populated ``files`` / ``inventory`` (usually the sdist).
    analyzed_artifact: ArtifactInfo | None = None
    # Inventory of a wheel for the same release (for sdist/wheel divergence), if fetched.
    wheel_inventory: list[InventoryEntry] = field(default_factory=list)
    wheel_files: list[SourceFile] = field(default_factory=list)
    # Full release history, sorted oldest → newest by upload time.
    releases: list[ReleaseInfo] = field(default_factory=list)
    options: ScanOptions = field(default_factory=ScanOptions)

    def python_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.relpath.endswith(".py")]

    def find(self, *names: str) -> list[SourceFile]:
        wanted = {n.lower() for n in names}
        return [f for f in self.files if f.relpath.split("/")[-1].lower() in wanted]

    def get_file(self, relpath: str) -> SourceFile | None:
        for f in self.files:
            if f.relpath == relpath:
                return f
        return None

    def files_with_suffix(self, *suffixes: str) -> list[SourceFile]:
        lowered = tuple(s.lower() for s in suffixes)
        return [f for f in self.files if f.relpath.lower().endswith(lowered)]


@dataclass
class ToolStatus:
    """Availability of an analyzer's backing tool or data source."""

    name: str
    available: bool
    version: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "available": self.available, "version": self.version, "detail": self.detail}


@runtime_checkable
class Analyzer(Protocol):
    name: str

    def analyze(self, ctx: PackageContext) -> list[Finding]:  # pragma: no cover - protocol
        ...


class BaseAnalyzer:
    """Convenience base: declares the optional Warden X analyzer attributes with defaults.

    Subclasses set ``name`` and ``version`` and implement ``analyze``. The orchestrator stamps
    ``analyzer``/``analyzer_version`` and taxonomy defaults onto every returned finding.
    """

    name: str = "base"
    version: str = "1.0.0"
    requires_network: bool = False

    def availability(self) -> ToolStatus:
        return ToolStatus(name=self.name, available=True, version=self.version)

    def analyze(self, ctx: PackageContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError
