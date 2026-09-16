"""YARA analysis layer: packaged Warden X signatures plus optional organisational rules.

What is scanned
===============
The analyzer compiles the packaged rules (``app/analysis/rules/yara``) once per process and, when
``settings.YARA_RULES_DIR`` is set, the organisational rules in that directory. It scans every
retained member of the package:

* ``ctx.files`` — decoded text files, scanned as their UTF-8 encoding (offsets are byte offsets
  into that encoding, which preserves line terminators);
* ``ctx.binaries`` — raw bytes of retained non-text members: executables, but also documents and
  extension-less scripts that safe extraction did not select as text.

Each member gets a *file kind* (python, shell, powershell, batch, javascript, config, metadata,
document, dockerfile, other_text, binary) from its name, shebang and content. A rule only reports
matches in the kinds listed in its ``scope`` metadata, so a curl-pipe-shell rule meant for shell
scripts stays quiet on a README that documents an installer.

Findings
========
One ``YARA_MATCH`` finding per matching rule, not per file, so one idiom repeated across many
files cannot inflate the score:

* severity and confidence come from the rule metadata; weight is set by severity (critical 10,
  high 7, medium 3, low 1);
* ``location`` is the first matching member outside test files (``ctx.files`` order, then binaries
  by path), falling back to the first test file. ``line`` is the 1-based line of the first matched
  byte that is not a line terminator, for text members only; it is ``None`` for binary members
  and for rules whose condition matched without any string match;
* ``evidence`` holds the rule id, name, version, namespace, ruleset and description, the
  execution context, the file kind, matched string identifiers with byte offsets, and up to ten
  occurrences ``{file, line, context, file_kind, first_offset, identifiers}`` (primary first, then
  file order). **Matched data is never read or stored**, only identifiers and offsets;
* category, capability, ATT&CK, CWE and reference come from the rule; provenance is
  ``external-tool:yara``.

Execution context (``evidence["context"]``) describes where the primary match sits:
``install_time`` (``setup.py``), ``interpreter_startup`` (``.pth``, ``sitecustomize.py``,
``usercustomize.py``), ``import_time`` (module-level Python, including class bodies), ``runtime``
(inside a function or lambda body, an ``if __name__ == "__main__":`` block, or ``__main__.py``),
``test`` (a ``test``/``tests`` directory, ``test_*.py``, ``*_test.py``, ``conftest.py``), ``script``
(shell, PowerShell, batch, JavaScript, Dockerfile), ``binary``, ``data`` (other text) or ``unknown``
(Python that does not parse). Python contexts come from ``ast.parse`` (nothing is executed) at line
granularity. If a rule matches only in test files, its finding is kept with confidence × 0.6 and
weight × 0.5: security tooling legitimately ships malicious-looking fixtures in its tests, but a
payload hidden under ``tests/`` is still reported.

Bounds and failure handling
===========================
* Scans run in YARA fast mode (only the first occurrence of each string is recorded), so a hostile
  member cannot make YARA allocate millions of match records.
* Each member is capped (``MAX_ANALYZED_FILE_BYTES`` for text, ``MAX_RETAINED_BINARY_FILE_BYTES`` for
  binaries; a capped scan is flagged ``truncated``), each scan has a YARA timeout, and the whole
  analyzer has a time budget (80% of ``ANALYZER_TIMEOUT_SECONDS``, capped by ``TOOL_TIMEOUT_SECONDS``).
* Each of the following produces an ``ANALYZER_ERROR`` finding (medium, weight 2.0, confidence
  1.0), because analysis is incomplete and the verdict must fail closed: a member that times out
  or errors, an exhausted budget, or organisational rules that are missing, invalid or do not
  compile. Matches from the rules that did run are still reported.
* yara-python is optional and imported lazily. When it is missing or ``YARA_ENABLED`` is false,
  :meth:`YaraScanAnalyzer.availability` reports unavailable, so the orchestrator records
  ``TOOL_UNAVAILABLE``; :meth:`YaraScanAnalyzer.analyze` raises instead of returning an empty,
  clean-looking result.

Compiled rules are cached per process behind a lock. Organisational rules are reloaded when a rule
file's name, size or modification time changes. The verdict cache key contains this analyzer's
version but not the organisational rule contents, so a cached verdict can predate a rule change by
up to ``VERDICT_CACHE_TTL_SECONDS``.

The signatures are designed to detect specific high-signal patterns. They do not detect all
malware, and a scan with no YARA matches is not evidence that a package is safe.
"""

from __future__ import annotations

import ast
import bisect
import importlib
import math
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis import rules as rule_catalog
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ToolStatus
from app.analysis.findings import Finding, Location, Provenance, Severity, sort_key
from app.analysis.signals import Code
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.analyzers.yara")

ANALYZER_NAME = "yara_scan"
ANALYZER_VERSION = "1.0.0"
TOOL_NAME = "yara"
PROVENANCE = Provenance.tool(TOOL_NAME)

SEVERITY_WEIGHTS: dict[str, float] = {"critical": 10.0, "high": 7.0, "medium": 3.0, "low": 1.0}
TEST_CONTEXT_CONFIDENCE_FACTOR = 0.6
TEST_CONTEXT_WEIGHT_FACTOR = 0.5
FILE_TIMEOUT_SECONDS = 10
BUDGET_FRACTION = 0.8
MAX_FINDINGS = 200
MAX_OCCURRENCES = 10
MAX_STRING_IDENTIFIERS = 10
MAX_OFFSETS_PER_STRING = 5
MAX_ERROR_EXAMPLES = 5
MAX_AST_PARSE_BYTES = 2 * 1024 * 1024
SNIFF_BYTES = 8192

CONTEXT_INSTALL_TIME = "install_time"
CONTEXT_STARTUP = "interpreter_startup"
CONTEXT_IMPORT_TIME = "import_time"
CONTEXT_RUNTIME = "runtime"
CONTEXT_TEST = "test"
CONTEXT_SCRIPT = "script"
CONTEXT_BINARY = "binary"
CONTEXT_DATA = "data"
CONTEXT_UNKNOWN = "unknown"

ORIGIN_TEXT = "utf8_text"  # ctx.files: offsets into the UTF-8 encoding of the decoded text
ORIGIN_RAW = "raw_bytes"  # ctx.binaries: offsets into the retained bytes

_NEWLINE_RE = re.compile(rb"\r\n|\r|\n")
_EXTENSION_KINDS: dict[str, str] = {
    ".py": "python", ".pyw": "python", ".pyi": "python", ".pth": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".dash": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "javascript",
    ".cfg": "config", ".toml": "config", ".ini": "config", ".yml": "config", ".yaml": "config",
    ".json": "config", ".conf": "config", ".xml": "config",
    ".txt": "document", ".md": "document", ".rst": "document", ".html": "document", ".htm": "document",
}
_NAME_KINDS: dict[str, str] = {
    "PKG-INFO": "metadata", "METADATA": "metadata", "RECORD": "metadata", "WHEEL": "metadata",
    "entry_points.txt": "metadata", "Dockerfile": "dockerfile",
}
_INTERPRETER_KINDS: tuple[tuple[str, str], ...] = (
    ("python", "python"), ("pypy", "python"), ("bash", "shell"), ("dash", "shell"), ("zsh", "shell"),
    ("ksh", "shell"), ("ash", "shell"), ("sh", "shell"), ("nodejs", "javascript"), ("node", "javascript"),
    ("pwsh", "powershell"), ("powershell", "powershell"),
)
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "unittests", "unit_tests"})
_TEST_FILE_RE = re.compile(r"(?:test_.+|.+_tests?|conftest|tests?)\.py")
_STARTUP_NAMES = frozenset({"sitecustomize.py", "usercustomize.py"})
_SCRIPT_KINDS = frozenset({"shell", "powershell", "batch", "javascript", "dockerfile"})

# Indirection so tests can drive the clock (time budget) deterministically.
_clock = time.monotonic


class YaraUnavailableError(RuntimeError):
    """``analyze`` was called while YARA scanning is disabled or yara-python is missing."""


# --------------------------------------------------------------------------- yara-python loading
def _import_yara() -> Any:
    return importlib.import_module("yara")


def load_yara() -> tuple[Any | None, str | None]:
    """``(module, None)`` when a usable yara-python is importable, else ``(None, reason)``."""
    try:
        module = _import_yara()
    except (ImportError, OSError) as exc:  # OSError: the bundled libyara failed to load
        return None, type(exc).__name__
    if not callable(getattr(module, "compile", None)) or not isinstance(getattr(module, "Error", None), type):
        return None, "IncompatibleYaraModule"  # e.g. an unrelated package also named "yara"
    return module, None


# --------------------------------------------------------------------------- compiled rules cache
@dataclass(frozen=True)
class CompiledRuleset:
    loaded: rule_catalog.LoadedRuleset
    rules: Any  # yara.Rules


@dataclass(frozen=True)
class RulesetFailure:
    error_type: str
    detail: str


_CACHE_LOCK = threading.Lock()
_PACKAGED_CACHE: dict[int, CompiledRuleset] = {}
_ORGANISATIONAL_CACHE: dict[tuple, CompiledRuleset | RulesetFailure] = {}


def reset_caches() -> None:
    """Forget compiled rules (tests; or after replacing rule files in place)."""
    with _CACHE_LOCK:
        _PACKAGED_CACHE.clear()
        _ORGANISATIONAL_CACHE.clear()


def verify_compiled_metadata(compiled: Any, loaded: rule_catalog.LoadedRuleset) -> None:
    """Cross-check yara-python's view of every public rule against the validated metadata."""
    expected: dict[str, list[dict]] = {}
    for (_namespace, name), meta in loaded.rules.items():
        expected.setdefault(name, []).append(dict(meta.raw_meta))
    try:
        compiled_rules = list(compiled)
    except TypeError:  # yara-python < 4.3 cannot enumerate compiled rules
        log.warning("yara_rules_not_enumerable")
        return
    problems = [
        f"rule {sanitize_text(rule.identifier, max_len=80)}: compiled metadata differs from validated metadata"
        for rule in compiled_rules
        if not getattr(rule, "is_private", False) and dict(rule.meta) not in expected.get(rule.identifier, [])
    ]
    if problems:
        raise rule_catalog.RuleValidationError(problems)


def compile_ruleset(yara: Any, loaded: rule_catalog.LoadedRuleset) -> Any:
    # includes=False: an include directive could read arbitrary files at compile time.
    compiled = yara.compile(sources=loaded.source_map(), includes=False)
    verify_compiled_metadata(compiled, loaded)
    return compiled


def packaged_rules(yara: Any) -> CompiledRuleset:
    """The packaged rules compiled for ``yara`` (compiled once; errors propagate: fail loudly)."""
    key = id(yara)
    with _CACHE_LOCK:
        cached = _PACKAGED_CACHE.get(key)
        if cached is None:
            loaded = rule_catalog.PACKAGED_YARA_RULES
            cached = CompiledRuleset(loaded, compile_ruleset(yara, loaded))
            _PACKAGED_CACHE.clear()
            _PACKAGED_CACHE[key] = cached
    return cached


def _directory_fingerprint(directory: Path) -> tuple:
    try:
        entries = []
        for entry in sorted(directory.iterdir(), key=lambda p: p.name):
            if entry.suffix.lower() in rule_catalog.YARA_RULE_SUFFIXES:
                stat = entry.stat()
                entries.append((entry.name, stat.st_size, stat.st_mtime_ns))
                if len(entries) > rule_catalog.MAX_RULE_FILES:
                    break
        return ("ok", str(directory.resolve()), tuple(entries))
    except OSError as exc:
        return ("error", str(directory), type(exc).__name__)


def _load_organisational(yara: Any, directory: Path) -> CompiledRuleset | RulesetFailure:
    compile_error = getattr(yara, "Error", Exception)
    try:
        loaded = rule_catalog.load_ruleset(directory, ruleset=rule_catalog.ORGANISATIONAL_RULESET)
        compiled = compile_ruleset(yara, loaded)
    except rule_catalog.RuleValidationError as exc:
        failure = RulesetFailure("YaraRuleValidationError", "; ".join(exc.problems))
    except compile_error as exc:  # yara.SyntaxError / yara.WarningError / yara.Error
        failure = RulesetFailure("YaraRuleCompileError", str(exc))
    else:
        log.info("yara_organisational_rules_loaded", rules=len(loaded.rules), digest=loaded.digest[:16])
        return CompiledRuleset(loaded, compiled)
    log.error("yara_organisational_rules_failed", error_type=failure.error_type)
    return failure


def organisational_rules(yara: Any, raw_directory: str | None) -> CompiledRuleset | RulesetFailure | None:
    """Rules from ``YARA_RULES_DIR`` (``None`` when unset); reloaded when the directory changes."""
    if raw_directory is None or not str(raw_directory).strip():
        return None
    directory = Path(str(raw_directory).strip())
    key = (id(yara), _directory_fingerprint(directory))
    with _CACHE_LOCK:
        cached = _ORGANISATIONAL_CACHE.get(key)
        if cached is None:
            cached = _load_organisational(yara, directory)
            _ORGANISATIONAL_CACHE.clear()
            _ORGANISATIONAL_CACHE[key] = cached
    return cached


# --------------------------------------------------------------------------- scan targets
def looks_binary(data: bytes) -> bool:
    """NUL bytes or invalid UTF-8 in the first ``SNIFF_BYTES`` bytes."""
    head = data[:SNIFF_BYTES]
    if b"\x00" in head:
        return True
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character cut by the sniff window is still text.
        return not (len(data) > SNIFF_BYTES and exc.start >= len(head) - 3)
    return False


def _shebang_kind(head: bytes) -> str | None:
    if not head.startswith(b"#!"):
        return None
    words = head[2:256].split(b"\n", 1)[0].decode("ascii", "replace").split()
    if not words:
        return None
    program = words[0].rsplit("/", 1)[-1]
    if program == "env":
        rest = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
        if not rest:
            return None
        program = rest[0].rsplit("/", 1)[-1]
    program = program.lower()
    for prefix, kind in _INTERPRETER_KINDS:
        suffix = program[len(prefix):] if program.startswith(prefix) else None
        if suffix is not None and (suffix == "" or suffix.replace(".", "").isdigit()):
            return kind
    return None


def file_kind(relpath: str, head: bytes, *, binary: bool) -> str:
    if binary:
        return "binary"
    base = relpath.rsplit("/", 1)[-1]
    if base in _NAME_KINDS:
        return _NAME_KINDS[base]
    lowered = base.lower()
    dot = lowered.rfind(".")
    if dot >= 0 and lowered[dot:] in _EXTENSION_KINDS:
        return _EXTENSION_KINDS[lowered[dot:]]
    return _shebang_kind(head) or "other_text"


def is_test_path(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").lower().split("/")
    return any(part in _TEST_DIRS for part in parts[:-1]) or bool(_TEST_FILE_RE.fullmatch(parts[-1]))


def _is_main_guard(test: ast.AST) -> bool:
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1):
        return False
    sides = (test.left, test.comparators[0])
    names = [s for s in sides if isinstance(s, ast.Name) and s.id == "__name__"]
    constants = [s for s in sides if isinstance(s, ast.Constant) and s.value == "__main__"]
    return len(names) == 1 and len(constants) == 1


def python_runtime_ranges(source: str) -> list[tuple[int, int]] | None:
    """Line ranges whose code runs only when called (function/lambda bodies, ``__main__`` guards).

    ``None`` when the source does not parse. The tree is walked with an explicit stack, so deeply
    nested but valid source cannot exhaust the interpreter recursion limit.
    """
    if len(source) > MAX_AST_PARSE_BYTES:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return None
    ranges: list[tuple[int, int]] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body:
                ranges.append((node.body[0].lineno, node.end_lineno or node.body[-1].lineno))
            # Decorators, defaults and annotations are evaluated when the def statement runs.
            stack.extend(node.decorator_list)
            stack.append(node.args)
            if node.returns is not None:
                stack.append(node.returns)
            continue
        if isinstance(node, ast.Lambda):
            ranges.append((node.body.lineno, node.body.end_lineno or node.body.lineno))
            stack.append(node.args)
            continue
        if isinstance(node, ast.If) and _is_main_guard(node.test):
            if node.body:
                ranges.append((node.body[0].lineno, node.body[-1].end_lineno or node.body[-1].lineno))
            stack.extend(node.orelse)
            continue
        stack.extend(ast.iter_child_nodes(node))
    ranges.sort()
    return ranges


@dataclass
class ScanTarget:
    index: int
    relpath: str
    data: bytes
    kind: str
    origin: str
    truncated: bool
    _line_starts: list[int] | None = field(default=None, repr=False)
    _runtime_ranges: list[tuple[int, int]] | None = field(default=None, repr=False)
    _ranges_ready: bool = field(default=False, repr=False)

    def line_for(self, offset: int, length: int = 0) -> int | None:
        """1-based line of the first non-line-terminator byte of a match (text members only)."""
        if self.kind == "binary" or not 0 <= offset <= len(self.data):
            return None
        end = min(len(self.data), offset + max(0, length))
        while offset < end and self.data[offset] in (0x0A, 0x0D):
            offset += 1
        if self._line_starts is None:
            self._line_starts = [m.end() for m in _NEWLINE_RE.finditer(self.data)]
        return bisect.bisect_right(self._line_starts, offset) + 1

    def runtime_ranges(self) -> list[tuple[int, int]] | None:
        if not self._ranges_ready:
            self._runtime_ranges = python_runtime_ranges(self.data.decode("utf-8", errors="replace"))
            self._ranges_ready = True
        return self._runtime_ranges


def execution_context(target: ScanTarget, line: int | None) -> str:
    base = target.relpath.rsplit("/", 1)[-1].lower()
    if is_test_path(target.relpath):
        return CONTEXT_TEST
    if target.kind == "binary":
        return CONTEXT_BINARY
    if base == "setup.py":
        return CONTEXT_INSTALL_TIME
    if base.endswith(".pth") or base in _STARTUP_NAMES:
        return CONTEXT_STARTUP
    if target.kind == "python":
        if base == "__main__.py":
            return CONTEXT_RUNTIME
        ranges = target.runtime_ranges()
        if ranges is None or line is None:
            return CONTEXT_UNKNOWN
        return CONTEXT_RUNTIME if any(start <= line <= end for start, end in ranges) else CONTEXT_IMPORT_TIME
    if target.kind in _SCRIPT_KINDS:
        return CONTEXT_SCRIPT
    return CONTEXT_DATA


def scan_targets(ctx: PackageContext) -> list[ScanTarget]:
    """Members to scan in deterministic order: ``ctx.files`` order, then binaries sorted by path."""
    text_cap = max(1, int(settings.MAX_ANALYZED_FILE_BYTES))
    binary_cap = max(1, int(settings.MAX_RETAINED_BINARY_FILE_BYTES))
    targets: list[ScanTarget] = []
    seen: set[str] = set()
    for source in ctx.files:
        if source.relpath in seen:
            continue
        seen.add(source.relpath)
        encoded = source.text.encode("utf-8", errors="replace")
        data = encoded[:text_cap]
        if data:
            targets.append(ScanTarget(len(targets), source.relpath, data,
                                      file_kind(source.relpath, data[:SNIFF_BYTES], binary=False), ORIGIN_TEXT,
                                      bool(source.truncated) or len(encoded) > text_cap))
    binaries = ctx.binaries or {}
    for relpath in sorted(binaries, key=str):
        raw = binaries[relpath]
        if relpath in seen or not isinstance(raw, (bytes, bytearray, memoryview)):
            continue
        seen.add(relpath)
        data = bytes(raw[:binary_cap])
        if data:
            kind = file_kind(relpath, data[:SNIFF_BYTES], binary=looks_binary(data))
            targets.append(ScanTarget(len(targets), relpath, data, kind, ORIGIN_RAW, len(raw) > binary_cap))
    return targets


def scan_budget_seconds() -> float:
    analyzer_budget = float(settings.ANALYZER_TIMEOUT_SECONDS) * BUDGET_FRACTION
    return max(1.0, min(analyzer_budget, float(settings.TOOL_TIMEOUT_SECONDS)))


# --------------------------------------------------------------------------- aggregation
@dataclass(frozen=True)
class _Occurrence:
    relpath: str
    kind: str
    origin: str
    context: str
    line: int | None
    first_offset: int | None
    strings: tuple[tuple[str, tuple[int, ...]], ...]
    truncated: bool


@dataclass
class _RuleHits:
    meta: rule_catalog.YaraRuleMeta
    tags: tuple[str, ...]
    occurrences: list[_Occurrence] = field(default_factory=list)
    primary: _Occurrence | None = None  # first occurrence outside test files
    file_count: int = 0

    def add(self, occurrence: _Occurrence) -> None:
        self.file_count += 1
        if self.primary is None and occurrence.context != CONTEXT_TEST:
            self.primary = occurrence
        if len(self.occurrences) < MAX_OCCURRENCES:
            self.occurrences.append(occurrence)


def _occurrence(match: Any, target: ScanTarget) -> _Occurrence:
    strings: list[tuple[str, tuple[int, ...]]] = []
    first_offset: int | None = None
    first_length = 0
    for string_match in list(getattr(match, "strings", None) or ()):
        # Only offsets and lengths are read; StringMatchInstance.matched_data is never touched.
        positions = sorted((int(i.offset), int(i.matched_length)) for i in getattr(string_match, "instances", ()))
        if not positions:
            continue
        if first_offset is None or positions[0] < (first_offset, first_length):
            first_offset, first_length = positions[0]
        offsets = tuple(offset for offset, _ in positions[:MAX_OFFSETS_PER_STRING])
        strings.append((str(string_match.identifier), offsets))
    strings.sort(key=lambda item: (item[1][0], item[0]))
    line = target.line_for(first_offset, first_length) if first_offset is not None else None
    return _Occurrence(target.relpath, target.kind, target.origin, execution_context(target, line), line,
                       first_offset, tuple(strings[:MAX_STRING_IDENTIFIERS]), target.truncated)


def _rule_finding(hits: _RuleHits) -> Finding:
    meta = hits.meta
    test_only = hits.primary is None
    primary = hits.primary or hits.occurrences[0]
    shown = [primary, *[o for o in hits.occurrences if o is not primary]][:MAX_OCCURRENCES]
    confidence = meta.confidence * (TEST_CONTEXT_CONFIDENCE_FACTOR if test_only else 1.0)
    weight = SEVERITY_WEIGHTS[meta.severity] * (TEST_CONTEXT_WEIGHT_FACTOR if test_only else 1.0)
    others = hits.file_count - 1
    where = primary.relpath + (f" and {others} other file(s)" if others > 0 else "")
    suffix = " (test files only)" if test_only else ""
    evidence = {
        "rule_id": meta.rule_id,
        "rule": meta.name,
        "rule_version": meta.version,
        "namespace": meta.namespace,
        "ruleset": meta.ruleset,
        "description": meta.description,
        "context": primary.context,
        "file_kind": primary.kind,
        "offset_basis": primary.origin,
        "strings": [{"identifier": ident, "offsets": list(offsets)} for ident, offsets in primary.strings],
        "truncated": primary.truncated,
        "test_files_only": test_only,
        "match_file_count": hits.file_count,
        "occurrences": [
            {"file": o.relpath, "line": o.line, "context": o.context, "file_kind": o.kind,
             "first_offset": o.first_offset, "identifiers": [ident for ident, _ in o.strings]}
            for o in shown
        ],
        "locations": [{"file": o.relpath, "line": o.line} for o in shown],
        "tags": list(hits.tags[:10]),
    }
    return Finding(
        Code.YARA_MATCH, Severity.coerce(meta.severity), round(weight, 2),
        f"YARA rule {meta.rule_id} ({meta.name}) matched in {where}{suffix}: {meta.description}",
        evidence, meta.capability,
        confidence=round(confidence, 4), category=meta.category, title=f"YARA {meta.rule_id}: {meta.description}",
        location=Location(file=primary.relpath, line=primary.line), cwe=meta.cwe, attack=meta.attack,
        references=(meta.reference,), provenance=PROVENANCE,
    )


def _incomplete(status: str, error_type: str, message: str, **details: Any) -> Finding:
    return Finding(
        Code.ANALYZER_ERROR, Severity.medium, 2.0, message,
        {"analyzer": ANALYZER_NAME, "status": status, "error_type": error_type, **details},
        confidence=1.0, provenance=PROVENANCE,
    )


# --------------------------------------------------------------------------- analyzer
class YaraScanAnalyzer(BaseAnalyzer):
    """Signature scanning of package members with packaged and organisational YARA rules."""

    name = ANALYZER_NAME
    version = ANALYZER_VERSION

    def availability(self) -> ToolStatus:
        if not settings.YARA_ENABLED:
            return ToolStatus(name=TOOL_NAME, available=False, detail="disabled by configuration (YARA_ENABLED=false)")
        module, reason = load_yara()
        if module is None:
            return ToolStatus(name=TOOL_NAME, available=False,
                              detail=f"yara-python is not installed or unusable ({reason}); optional dependency, "
                                     "see requirements-optional.txt")
        version = getattr(module, "__version__", None) or getattr(module, "YARA_VERSION", None)
        return ToolStatus(name=TOOL_NAME, available=True, version=str(version) if version else None)

    def analyze(self, ctx: PackageContext) -> list[Finding]:
        if not settings.YARA_ENABLED:
            raise YaraUnavailableError("YARA scanning is disabled (YARA_ENABLED=false)")
        yara, reason = load_yara()
        if yara is None:
            raise YaraUnavailableError(f"yara-python is not available ({reason})")

        started = _clock()
        budget = scan_budget_seconds()
        pipeline: list[Finding] = []
        rulesets = [packaged_rules(yara)]
        organisational = organisational_rules(yara, settings.YARA_RULES_DIR)
        if isinstance(organisational, RulesetFailure):
            pipeline.append(_incomplete(
                "error", organisational.error_type,
                "Organisational YARA rules (YARA_RULES_DIR) could not be loaded; only packaged rules ran",
                ruleset=rule_catalog.ORGANISATIONAL_RULESET, detail=sanitize_text(organisational.detail, max_len=300),
            ))
        elif organisational is not None:
            rulesets.append(organisational)

        timeout_error = getattr(yara, "TimeoutError", None)
        yara_error = getattr(yara, "Error", None)
        hits: dict[tuple[str, str], _RuleHits] = {}
        timeouts: list[str] = []
        errors: list[tuple[str, str]] = []
        targets = scan_targets(ctx)
        unscanned: list[ScanTarget] = []
        for position, target in enumerate(targets):
            remaining = budget - (_clock() - started)
            if remaining <= 0:
                unscanned = targets[position:]
                break
            timeout = int(max(1, min(FILE_TIMEOUT_SECONDS, math.ceil(remaining))))
            for compiled in rulesets:
                try:
                    matches = compiled.rules.match(data=target.data, fast=True, timeout=timeout)
                except Exception as exc:
                    if isinstance(timeout_error, type) and isinstance(exc, timeout_error):
                        timeouts.append(target.relpath)
                    elif isinstance(yara_error, type) and isinstance(exc, yara_error):
                        errors.append((target.relpath, type(exc).__name__))
                    else:
                        raise
                    continue
                for match in matches:
                    self._record(hits, compiled, match, target)

        findings = self._findings(hits)
        findings.extend(pipeline)
        if timeouts:
            findings.append(_incomplete(
                "timeout", "YaraScanTimeout",
                f"YARA scan timed out on {len(set(timeouts))} member(s); analysis is incomplete",
                files=len(set(timeouts)), examples=sorted(set(timeouts))[:MAX_ERROR_EXAMPLES],
            ))
        if errors:
            failed = sorted({path for path, _ in errors})
            findings.append(_incomplete(
                "error", "YaraScanError", f"YARA scan failed on {len(failed)} member(s); analysis is incomplete",
                files=len(failed), examples=failed[:MAX_ERROR_EXAMPLES],
                error_types=sorted({kind for _, kind in errors}),
            ))
        if unscanned:
            findings.append(_incomplete(
                "timeout", "YaraScanBudgetExceeded",
                f"YARA time budget exhausted; {len(unscanned)} member(s) were not scanned",
                budget_seconds=round(budget, 3), scanned_files=len(targets) - len(unscanned),
                unscanned_files=len(unscanned), examples=[t.relpath for t in unscanned[:MAX_ERROR_EXAMPLES]],
            ))
        log.info("yara_scan_complete", members=len(targets), rules_matched=len(hits), timeouts=len(timeouts),
                 errors=len(errors), unscanned=len(unscanned))
        return findings

    @staticmethod
    def _record(hits: dict[tuple[str, str], _RuleHits], compiled: CompiledRuleset, match: Any,
                target: ScanTarget) -> None:
        key = (str(getattr(match, "namespace", "")), str(getattr(match, "rule", "")))
        meta = compiled.loaded.rules.get(key)
        if meta is None:  # only private rules lack metadata, and they never match; never guess
            log.warning("yara_match_without_metadata", namespace=sanitize_text(key[0], max_len=80),
                        rule=sanitize_text(key[1], max_len=80))
            return
        if not meta.applies_to(target.kind):
            return
        bucket = hits.get(key)
        if bucket is None:
            bucket = hits[key] = _RuleHits(meta, tuple(str(t) for t in (getattr(match, "tags", None) or ())))
        bucket.add(_occurrence(match, target))

    @staticmethod
    def _findings(hits: dict[tuple[str, str], _RuleHits]) -> list[Finding]:
        ordered = [hits[key] for key in sorted(hits, key=lambda k: (hits[k].meta.rule_id, k))]
        findings = [_rule_finding(h) for h in ordered]
        if len(findings) <= MAX_FINDINGS:
            return findings
        kept = sorted(findings, key=lambda f: (sort_key(f), f.evidence.get("rule_id", "")))[:MAX_FINDINGS]
        kept_ids = {id(f) for f in kept}
        result = [f for f in findings if id(f) in kept_ids]
        omitted = len(findings) - len(result)
        result.append(Finding(
            Code.YARA_MATCH, Severity.info, 0.0, f"{omitted} further YARA rule match(es) omitted (cap {MAX_FINDINGS})",
            {"omitted": omitted, "cap": MAX_FINDINGS}, confidence=1.0, provenance=PROVENANCE,
        ))
        return result


__all__ = [
    "ANALYZER_NAME",
    "ANALYZER_VERSION",
    "SEVERITY_WEIGHTS",
    "CompiledRuleset",
    "RulesetFailure",
    "ScanTarget",
    "YaraScanAnalyzer",
    "YaraUnavailableError",
    "compile_ruleset",
    "execution_context",
    "file_kind",
    "is_test_path",
    "load_yara",
    "looks_binary",
    "organisational_rules",
    "packaged_rules",
    "python_runtime_ranges",
    "reset_caches",
    "scan_budget_seconds",
    "scan_targets",
    "verify_compiled_metadata",
]
