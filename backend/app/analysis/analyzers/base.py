"""Analyzer protocol and the shared package context.

An ``Analyzer`` is a pure function object: given a ``PackageContext`` (already-fetched
metadata plus a list of extracted source files), it returns a list of ``Signal``. Analyzers
never perform network I/O and never execute package code — those responsibilities live in
the fetcher and are deliberately kept out of the analysis layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.analysis.signals import Signal


@dataclass
class SourceFile:
    relpath: str
    text: str  # decoded (best-effort) file contents, truncated to the analyzer cap
    size: int
    truncated: bool = False


@dataclass
class PackageContext:
    ecosystem: str
    name: str
    version: str
    # Raw metadata as returned by the registry (PyPI JSON ``info`` block, etc.).
    metadata: dict = field(default_factory=dict)
    # Extracted, size-capped source files (Python files and build scripts of interest).
    files: list[SourceFile] = field(default_factory=list)
    # Non-fatal issues encountered while building the context (fetch/extract problems).
    context_signals: list[Signal] = field(default_factory=list)

    def python_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.relpath.endswith(".py")]

    def find(self, *names: str) -> list[SourceFile]:
        wanted = {n.lower() for n in names}
        return [f for f in self.files if f.relpath.split("/")[-1].lower() in wanted]


@runtime_checkable
class Analyzer(Protocol):
    name: str

    def analyze(self, ctx: PackageContext) -> list[Signal]:  # pragma: no cover - protocol
        ...
