"""Inventory analyzer: suspicious artifacts in the distribution files Warden inventoried.

Works only on the archive inventory built by safe extraction (names, declared sizes, magic
bytes, hashes) and on registry facts — never on executed code. It provides signals for:

* ``BINARY_EXECUTABLE`` — ELF / PE / Mach-O files in an sdist, or in a wheel tagged
  ``none-any`` (which declares that it contains no compiled code). Binaries disguised with a
  text extension get higher confidence; well-known launcher stubs (``cli-64.exe``,
  ``t64.exe``…, shipped by setuptools and distlib) get low confidence.
* ``NESTED_ARCHIVE`` — archives inside the package; they are not extracted recursively, so their
  contents were not analysed.
* ``SUSPICIOUS_FILE`` — Windows payload/script file types in pure-Python packages (heuristic,
  low-to-moderate confidence), members Warden had to skip (unsafe names, over-deep paths),
  device/FIFO members, duplicate member names (different tools may see different content),
  zip entries whose mode bits claim a symlink/directory/device while installers write their
  bytes as a regular file, and members left unanalysed because the retained-text budget was
  exhausted (one aggregated finding per artifact; high when code files were skipped).
* ``YANKED_RELEASE`` — the registry marks the analysed release as yanked.
* ``SDIST_WHEEL_MISMATCH`` — ``.py`` / ``.pth`` files present in the wheel but absent from the
  sdist, i.e. code that was not built from the reviewable source. Paths are compared as full
  relative paths after a bounded set of layout rewrites only: ``*.dist-info/`` members and
  common generated version files are ignored, wheel ``.data/purelib|platlib/`` prefixes are
  removed, and one leading sdist source root (``src/``, ``lib/``, ``python/``) is removed. A
  file with the same basename elsewhere in the sdist does not count. Only file *presence* is
  compared, not content; packages using other ``package_dir`` roots can produce false positives.

These are indicators with documented false-positive sources, not proof of malice.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

# Module imports (attributes read at call time), not ``from … import name``: pypi and
# safe_archive import ``app.analysis.analyzers.base``, which initialises this package's
# registry, which imports this module. Importing either of them first would otherwise hit a
# partially initialised module and fail with ImportError.
from app.analysis.acquisition import pypi as _pypi
from app.analysis.analyzers.base import ArtifactInfo, BaseAnalyzer, InventoryEntry, PackageContext
from app.analysis.extraction import safe_archive as _safe_archive
from app.analysis.findings import Finding, Location, Provenance
from app.analysis.signals import Capability, Code, Severity

ANALYZER_VERSION = "1.0.0"
MAX_FINDINGS_PER_CODE = 25

NATIVE_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".pyx", ".pxd", ".rs", ".f", ".f90", ".go")
# Extensions under which a native executable is clearly disguised as something else.
DISGUISE_SUFFIXES = (".py", ".pyi", ".pth", ".txt", ".json", ".cfg", ".toml", ".ini", ".yml", ".yaml", ".md",
                     ".rst", ".js", ".html", ".css", ".csv", ".png", ".jpg", ".gif", ".svg")
GENERATED_BASENAMES = frozenset({"_version.py", "version.py"})
# setuptools (cli/gui[-32|-64|-arm64].exe) and distlib (t32/t64/w32/w64[-arm].exe) launcher stubs.
_LAUNCHER_RE = re.compile(r"^(?:(?:cli|gui)(?:-(?:32|64|arm64))?|[tw](?:32|64)(?:-arm)?)\.exe$", re.IGNORECASE)
_SECURITY_YANK_RE = re.compile(r"(?i)malware|malicious|compromis|security|vulnerab|backdoor|exploit|cve-\d")
_WHEEL_DATA_RE = re.compile(r"^[^/]+\.data/(?:purelib|platlib)/(.+)$")
_UNSAFE_NAME_REASONS = frozenset({"control_character", "invalid_encoding", "path_too_deep", "path_too_long"})
# The only sdist directories treated as an import root when comparing against wheel paths.
SDIST_SOURCE_ROOTS = frozenset({"src", "lib", "python"})
CODE_SUFFIXES = (".py", ".pyi", ".pth", ".sh", ".bat", ".cmd", ".ps1", ".js")

# extension -> (severity, weight, confidence, why)
_PAYLOAD_EXTENSIONS: dict[str, tuple[Severity, float, float, str]] = {
    ".scr": (Severity.medium, 2.5, 0.6, "Windows screensaver executable"),
    ".lnk": (Severity.medium, 2.5, 0.6, "Windows shortcut (common malware launcher)"),
    ".vbs": (Severity.medium, 2.5, 0.6, "VBScript file"),
    ".ps1": (Severity.low, 1.0, 0.3, "PowerShell script"),
    ".bat": (Severity.low, 1.0, 0.3, "Windows batch script"),
}


class _Emitter:
    """Collects findings, capping each code so a hostile archive cannot flood the report."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.counts: Counter[str] = Counter()
        self.omitted: Counter[str] = Counter()

    def add(self, code: str, severity: Severity, weight: float, message: str, evidence: dict, *,
            confidence: float, relpath: str | None = None, capability: str | None = None,
            provenance: str = Provenance.STATIC) -> None:
        if self.counts[code] >= MAX_FINDINGS_PER_CODE:
            self.omitted[code] += 1
            return
        self.counts[code] += 1
        self.findings.append(Finding(
            code, severity, weight, message, evidence, capability, confidence=confidence,
            location=Location(file=relpath) if relpath else None, provenance=provenance,
        ))

    def finish(self) -> list[Finding]:
        for code, count in sorted(self.omitted.items()):
            self.findings.append(Finding(
                code, Severity.info, 0.0, f"{count} further {code} findings omitted (per-code cap)",
                {"omitted": count, "cap": MAX_FINDINGS_PER_CODE}, confidence=1.0,
            ))
        return self.findings


def _suffix(relpath: str) -> str:
    base = relpath.rsplit("/", 1)[-1].lower()
    return base[base.rfind("."):] if "." in base else ""


def _basename(relpath: str) -> str:
    return relpath.rsplit("/", 1)[-1]


def _is_wheel(artifact: ArtifactInfo) -> bool:
    return artifact.packagetype == "bdist_wheel" or artifact.filename.lower().endswith(".whl")


def _inventoried_wheel(ctx: PackageContext) -> ArtifactInfo | None:
    """The wheel whose inventory is in ``ctx.wheel_inventory`` (downloaded, not the main artifact)."""
    for artifact in ctx.artifacts:
        if _is_wheel(artifact) and artifact.downloaded_sha256 and artifact is not ctx.analyzed_artifact:
            return artifact
    return None


def _sdist_looks_pure(ctx: PackageContext) -> bool:
    if any(_is_wheel(a) and not _pypi.is_pure_python_wheel(a.filename) for a in ctx.artifacts):
        return False
    return not any(e.relpath.lower().endswith(NATIVE_SOURCE_SUFFIXES) for e in ctx.inventory)


class InventoryAnalyzer(BaseAnalyzer):
    name = "inventory"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Finding]:
        out = _Emitter()
        main = ctx.analyzed_artifact
        main_label = main.filename if main else None
        main_is_sdist = main is not None and main.packagetype == "sdist"
        if main is not None:
            pure = _sdist_looks_pure(ctx) if main_is_sdist else _pypi.is_pure_python_wheel(main.filename)
            kind = "sdist" if main_is_sdist else ("pure-python wheel" if pure else "wheel")
            self._inventory(out, ctx.inventory, main_label, kind, check_binaries=main_is_sdist or pure, pure=pure)
        wheel = _inventoried_wheel(ctx)
        if ctx.wheel_inventory:
            wheel_pure = bool(wheel and _pypi.is_pure_python_wheel(wheel.filename))
            label = wheel.filename if wheel else None
            self._inventory(out, ctx.wheel_inventory, label, "pure-python wheel" if wheel_pure else "wheel",
                            check_binaries=wheel_pure, pure=wheel_pure)
            if main_is_sdist:
                self._sdist_wheel_mismatch(out, ctx, main_label, label)
        self._yanked(out, ctx)
        return out.finish()

    # ------------------------------------------------------------------ per-inventory checks
    def _inventory(self, out: _Emitter, inventory: Iterable[InventoryEntry], artifact: str | None, kind: str, *,
                   check_binaries: bool, pure: bool) -> None:
        entries = list(inventory)
        duplicates = {p for p, n in Counter(e.relpath for e in entries if e.kind == "file").items() if n > 1}
        for rel in sorted(duplicates):
            out.add(Code.SUSPICIOUS_FILE, Severity.medium, 2.5,
                    f"Archive contains more than one member named {rel}; tools may disagree on its content",
                    {"artifact": artifact, "reason": "duplicate_member_name"}, confidence=0.65, relpath=rel)
        self._budget_skipped(out, entries, artifact, kind)
        for entry in entries:
            evidence = {"artifact": artifact, "artifact_kind": kind, "size": entry.size}
            if entry.skipped_reason in _UNSAFE_NAME_REASONS:
                out.add(Code.SUSPICIOUS_FILE, Severity.medium, 2.5,
                        f"Member with an unsafe name was not analysed ({entry.skipped_reason})",
                        {**evidence, "reason": entry.skipped_reason, "member": entry.relpath}, confidence=0.6)
                continue
            if entry.kind == "device" or entry.skipped_reason == "fifo":
                out.add(Code.SUSPICIOUS_FILE, Severity.medium, 2.5,
                        f"Package archive contains a {entry.skipped_reason or entry.kind} member",
                        {**evidence, "reason": entry.skipped_reason or entry.kind}, confidence=0.7,
                        relpath=entry.relpath)
                continue
            if entry.kind != "file":
                continue
            if entry.declared_kind:
                code = entry.relpath.lower().endswith(CODE_SUFFIXES)
                out.add(Code.SUSPICIOUS_FILE, Severity.high if code else Severity.medium, 5.0 if code else 2.5,
                        f"Archive member claims to be a {entry.declared_kind} but installers write its content as a "
                        "regular file",
                        {**evidence, "reason": "member_type_mismatch", "declared_kind": entry.declared_kind,
                         "sha256": entry.sha256}, confidence=0.75 if code else 0.6, relpath=entry.relpath)
            if check_binaries and entry.is_executable_binary:
                self._binary(out, entry, evidence, kind)
            if entry.magic in _safe_archive.ARCHIVE_MAGIC:
                out.add(Code.NESTED_ARCHIVE, Severity.low, 1.0,
                        f"Nested {entry.magic} archive {entry.relpath} was not analysed",
                        {**evidence, "magic": entry.magic, "sha256": entry.sha256}, confidence=0.5,
                        relpath=entry.relpath)
            if pure:
                self._suspicious_extension(out, entry, evidence, kind)

    @staticmethod
    def _budget_skipped(out: _Emitter, entries: list[InventoryEntry], artifact: str | None, kind: str) -> None:
        skipped = [e for e in entries if e.skipped_reason == _safe_archive.TEXT_BUDGET_SKIP_REASON]
        if not skipped:
            return
        code = sorted(e.relpath for e in skipped if e.relpath.lower().endswith(CODE_SUFFIXES))
        examples = code or sorted(e.relpath for e in skipped)
        out.add(Code.SUSPICIOUS_FILE, Severity.high if code else Severity.medium, 6.0 if code else 3.0,
                f"{len(skipped)} member(s) of the {kind} were not analysed because the retained-text budget was "
                f"exhausted ({len(code)} code file(s))",
                {"artifact": artifact, "artifact_kind": kind, "reason": _safe_archive.TEXT_BUDGET_SKIP_REASON,
                 "skipped_members": len(skipped), "skipped_code_members": len(code), "examples": examples[:10]},
                confidence=0.7 if code else 0.5, relpath=examples[0])

    @staticmethod
    def _binary(out: _Emitter, entry: InventoryEntry, evidence: dict, kind: str) -> None:
        details = {**evidence, "magic": entry.magic, "sha256": entry.sha256, "mode": entry.mode}
        if entry.relpath.lower().endswith(DISGUISE_SUFFIXES):
            out.add(Code.BINARY_EXECUTABLE, Severity.high, 6.0,
                    f"Native {entry.magic} executable disguised as {_suffix(entry.relpath)} file in {kind}",
                    {**details, "disguised": True}, confidence=0.85, relpath=entry.relpath,
                    capability=Capability.NATIVE_CODE)
        elif entry.magic == "pe" and _LAUNCHER_RE.match(_basename(entry.relpath)):
            out.add(Code.BINARY_EXECUTABLE, Severity.low, 1.0,
                    f"Prebuilt Windows launcher stub in {kind}", {**details, "launcher_stub_name": True},
                    confidence=0.35, relpath=entry.relpath, capability=Capability.NATIVE_CODE)
        else:
            wheel = kind == "pure-python wheel"
            out.add(Code.BINARY_EXECUTABLE, Severity.medium, 3.5 if wheel else 3.0,
                    f"Prebuilt {entry.magic} executable in {kind}", details, confidence=0.7 if wheel else 0.6,
                    relpath=entry.relpath, capability=Capability.NATIVE_CODE)

    @staticmethod
    def _suspicious_extension(out: _Emitter, entry: InventoryEntry, evidence: dict, kind: str) -> None:
        suffix = _suffix(entry.relpath)
        if suffix in _PAYLOAD_EXTENSIONS:
            severity, weight, confidence, why = _PAYLOAD_EXTENSIONS[suffix]
            out.add(Code.SUSPICIOUS_FILE, severity, weight, f"{why} shipped in {kind}",
                    {**evidence, "reason": "suspicious_extension", "extension": suffix}, confidence=confidence,
                    relpath=entry.relpath)
        elif suffix in (".exe", ".dll") and entry.magic != "pe":
            out.add(Code.SUSPICIOUS_FILE, Severity.low, 1.0,
                    f"{suffix} file in {kind} is not a valid PE executable",
                    {**evidence, "reason": "extension_content_mismatch", "extension": suffix, "magic": entry.magic},
                    confidence=0.4, relpath=entry.relpath)

    # ------------------------------------------------------------------ registry / divergence
    @staticmethod
    def _yanked(out: _Emitter, ctx: PackageContext) -> None:
        md = ctx.metadata or {}
        art = ctx.analyzed_artifact
        release_yanked = any(r.version == ctx.version and r.yanked for r in ctx.releases)
        if not (md.get("yanked") is True or (art is not None and art.yanked) or release_yanked):
            return
        reason = md.get("yanked_reason") or (art.yanked_reason if art is not None else None)
        security = bool(isinstance(reason, str) and _SECURITY_YANK_RE.search(reason))
        out.add(Code.YANKED_RELEASE, Severity.medium if security else Severity.low, 3.0 if security else 1.5,
                "Release is yanked on the registry" + (" for a security-related reason" if security else ""),
                {"version": ctx.version, "yanked_reason": reason if isinstance(reason, str) else None,
                 "security_related_reason": security},
                confidence=0.95, provenance=Provenance.REGISTRY)

    @staticmethod
    def _sdist_wheel_mismatch(out: _Emitter, ctx: PackageContext, sdist: str | None, wheel: str | None) -> None:
        sdist_aborted = any(
            s.code == Code.EXTRACTION_ABORTED and (not isinstance(s.evidence, dict) or s.evidence.get("artifact") in
                                                   (None, sdist))
            for s in ctx.context_signals
        )
        if sdist_aborted:
            return  # a partial sdist inventory would produce false divergence
        known: set[str] = set()
        for entry in ctx.inventory:
            if entry.kind == "dir":
                continue
            known.add(entry.relpath)
            root, sep, rest = entry.relpath.partition("/")
            if sep and root in SDIST_SOURCE_ROOTS:
                known.add(rest)
        for entry in ctx.wheel_inventory:
            rel = entry.relpath
            if entry.kind != "file" or not rel.lower().endswith((".py", ".pth")):
                continue
            if rel.split("/", 1)[0].endswith(".dist-info") or _basename(rel) in GENERATED_BASENAMES:
                continue
            match = _WHEEL_DATA_RE.match(rel)
            target = match.group(1) if match else rel
            if target in known:
                continue
            pth = rel.lower().endswith(".pth")
            out.add(Code.SDIST_WHEEL_MISMATCH, Severity.high if pth else Severity.medium, 6.0 if pth else 3.5,
                    f"{rel} is present in the wheel but not in the source distribution",
                    {"wheel": wheel, "sdist": sdist, "wheel_path": rel, "sha256": entry.sha256},
                    confidence=0.8 if pth else 0.65, relpath=rel)
