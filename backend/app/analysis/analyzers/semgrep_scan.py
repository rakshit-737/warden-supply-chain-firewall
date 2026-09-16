"""Semgrep adapter: Warden's packaged rules plus organisational rule sets.

The analyzer materialises a package's retained text files into a private temporary
workspace (:func:`app.analysis.tools.package_workspace`), runs ``semgrep scan`` over it with
the hardened runner (:func:`app.analysis.tools.run_tool`: no shell, scrubbed environment,
bounded output, process-tree kill on timeout) and normalises the JSON results into
``SEMGREP_FINDING`` findings. Semgrep parses the package source; nothing is executed.

Rules
    ``rules/semgrep/warden-python.yml`` ships with Warden and is designed to detect code
    structures common in malicious Python packages (see the README next to it). Operators may
    add organisational rule sets with ``SEMGREP_EXTRA_CONFIGS``.

Organisational configs (security)
    Semgrep treats ``--config`` values such as ``p/python``, ``r/...``, ``auto`` or
    ``https://...`` as instructions to download and run remote rule content. Every extra
    config must therefore be an existing local YAML/JSON file or directory that resolves
    (symlinks and junctions included) inside one of the allowlisted base directories
    (``SEMGREP_CONFIG_ROOTS``; no roots configured means every extra config is refused). The
    resolved absolute path is what reaches semgrep, so a value can never be reinterpreted as
    a registry name. Refused configs are skipped, logged, and reported in a
    ``SEMGREP_SCAN_INCOMPLETE`` status finding; the packaged rules still run.

Evasion controls
    * A package can ship ``.semgrepignore`` (with ``*.py`` in it semgrep 1.177.0 scanned zero
      files in our validation), ``.gitignore``, ``.git`` or ``.semgrep`` configuration. Such
      control files are never materialised. Warden writes its own empty ``.semgrepignore`` at
      the workspace root and pins ``--project-root`` to it, because without one semgrep
      applies a default ignore list that skips e.g. ``tests/`` and ``build/`` directories.
    * ``--disable-nosem``: ``# nosemgrep`` comments in package code cannot suppress results.
    * Lone CR line endings are rewritten to LF before materialisation. CPython executes such
      files, but semgrep 1.177.0 does not treat a lone CR as a line break and failed to parse
      them in our validation (see :func:`normalise_line_endings`).
    * ``--no-git-ignore``, ``--metrics=off``, ``--disable-version-check``, ``--oss-only``;
      ``--no-rewrite-rule-ids`` keeps rule ids stable (otherwise semgrep prefixes them with the
      config file's directory path).

Normalisation
    Rule id, category (only a known Warden category is accepted), CWE ids, references,
    confidence and a ``warden_code`` hint come from rule metadata. Severity maps ERROR/HIGH/
    CRITICAL → high (weight 5), WARNING/MEDIUM → medium (2), INFO/LOW → low (0.5) and
    INVENTORY/EXPERIMENT → info (0); unknown values → low. Result paths must resolve inside
    the workspace; anything else is dropped and counted. Line numbers are semgrep's (1-based);
    a result without one keeps ``line=None``. ``evidence["context"]`` records where a match
    sits: ``test-file``, ``install-time`` (``setup.py``), ``import-time`` (module or class body,
    decorators, default values) or ``runtime`` (function or lambda body), derived from the
    path and the file's AST (parsed, never executed); ``unknown`` when that cannot be
    determined.

Confidence
    ``warden_confidence_by_context[context]`` → ``warden_confidence`` → ``confidence``
    (a number in [0, 1], or HIGH 0.8 / MEDIUM 0.6 / LOW 0.4) → 0.5. Matches in test files are
    multiplied by 0.7 unless the rule gives an explicit test-file value. Numbers may be
    written as quoted strings: semgrep's rule loader rejects YAML floats in metadata.

Failure handling
    semgrep missing or disabled → unavailable (``TOOL_UNAVAILABLE``). Timeout, truncated
    output, an exit status other than 0/1, or malformed JSON → an exception, which the
    orchestrator records as ``ANALYZER_ERROR`` (fail closed): a non-zero exit means a
    configuration or engine failure in which an unknown subset of rules did not run.
    ``errors[]`` entries alongside a successful exit (per-file problems; a rule timeout makes
    semgrep skip that file), result paths outside the workspace, Python files semgrep did not
    scan (for example over ``--max-target-bytes``), workspace members that could not be
    materialised and refused configs are partial-result conditions: the findings that were
    produced are kept and the counts are reported in one info-level, zero-weight
    ``SEMGREP_SCAN_INCOMPLETE`` finding.

Limits
    Semgrep OSS taint tracking is intraprocedural, so flows split across functions or modules
    are not followed; reflective calls (``getattr(os, "system")``) and runtime-built strings
    are not resolved. These rules provide signals for review; they are not a complete
    malware detector.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from app.analysis import taxonomy
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, SourceFile, ToolStatus
from app.analysis.findings import Category, Finding, Location, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.analysis.tools import (
    DEFAULT_MAX_OUTPUT_BYTES,
    UnsafePathError,
    find_tool,
    normalize_relpath,
    package_workspace,
    run_tool,
)
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.analyzers.semgrep")

ANALYZER_NAME = "semgrep_scan"
ANALYZER_VERSION = "1.0.0"
TOOL_NAME = "semgrep"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
PACKAGED_RULES = RULES_DIR / "warden-python.yml"
WARDEN_RULE_PREFIX = "warden."

# Scan-status code (registered below unless another module already registered it).
SEMGREP_SCAN_INCOMPLETE = "SEMGREP_SCAN_INCOMPLETE"

# --- semgrep invocation bounds --------------------------------------------------------------
RULE_TIMEOUT_SECONDS = 10  # per rule, per file (semgrep --timeout; integers only)
RULE_TIMEOUT_THRESHOLD = 3  # rule timeouts on one file before semgrep skips that file
MAX_MEMORY_MB = 2048
JOBS = 2
# Workspace text is UTF-8 re-encoded with replacement characters (up to 3 bytes each), so the
# per-file byte cap leaves room for that expansion of a file retained at the analyzer cap.
TARGET_BYTES_FACTOR = 4
MAX_RESULTS = 1000
MAX_ERROR_SAMPLES = 5
MAX_PATH_SAMPLES = 5
MAX_CONFIG_DIR_ENTRIES = 5000
MAX_CONTEXT_PARSE_CHARS = 4 * 1024 * 1024
# Default time budget: min(TOOL_TIMEOUT_SECONDS, ANALYZER_TIMEOUT_SECONDS - margin), where the
# margin is the larger of these, so semgrep is killed before the orchestrator's own timeout fires.
TIMEOUT_MARGIN_SECONDS = 3.0
TIMEOUT_MARGIN_FRACTION = 0.1
# CPython treats a lone CR as a line break; semgrep 1.177.0 does not (see normalise_line_endings).
_LONE_CR_RE = re.compile(r"\r(?!\n)")

# --- normalisation tables ----------------------------------------------------------------------
SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.high,  # capped: a rule match alone never produces a critical finding
    "ERROR": Severity.high,
    "HIGH": Severity.high,
    "WARNING": Severity.medium,
    "MEDIUM": Severity.medium,
    "INFO": Severity.low,
    "LOW": Severity.low,
    "INVENTORY": Severity.info,
    "EXPERIMENT": Severity.info,
}
UNKNOWN_SEVERITY = Severity.low
WEIGHTS: dict[Severity, float] = {Severity.high: 5.0, Severity.medium: 2.0, Severity.low: 0.5, Severity.info: 0.0}
CONFIDENCE_LABELS = {"HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}
DEFAULT_CONFIDENCE = 0.5
TEST_FILE_CONFIDENCE_FACTOR = 0.7

CONTEXT_TEST = "test-file"
CONTEXT_INSTALL = "install-time"
CONTEXT_IMPORT = "import-time"
CONTEXT_RUNTIME = "runtime"
CONTEXT_UNKNOWN = "unknown"
CONTEXTS = (CONTEXT_TEST, CONTEXT_INSTALL, CONTEXT_IMPORT, CONTEXT_RUNTIME)
_TEST_DIRS = frozenset({"test", "tests", "testing"})

# Categories a rule may claim. Pipeline status and correlation-derived attack chains are
# produced by Warden itself, never by a rule match.
ALLOWED_CATEGORIES = frozenset(c.value for c in Category) - {Category.PIPELINE.value, Category.ATTACK_CHAIN.value}
_NON_HINT_CODES = frozenset({
    Code.ANALYZER_ERROR, Code.TOOL_UNAVAILABLE, Code.INTEL_UNAVAILABLE, Code.FETCH_FAILED, Code.ATTACK_CHAIN,
    Code.SEMGREP_FINDING, SEMGREP_SCAN_INCOMPLETE,
})
CAPABILITY_BY_CODE: dict[str, str] = {
    Code.SHELL_INVOCATION: Capability.SHELL,
    Code.SUBPROCESS_EXEC: Capability.SUBPROCESS,
    Code.NETWORK_EGRESS: Capability.NETWORK,
    Code.DYNAMIC_EXEC: Capability.DYNAMIC_EXEC,
    Code.ENCODED_EXEC: Capability.OBFUSCATION,
    Code.OBFUSCATION: Capability.OBFUSCATION,
    Code.ENV_HARVEST: Capability.ENV_HARVEST,
    Code.FS_SENSITIVE: Capability.CREDENTIAL_ACCESS,
    Code.PERSISTENCE: Capability.PERSISTENCE,
    Code.NATIVE_CODE_LOADING: Capability.NATIVE_CODE,
    Code.INSTALL_HOOK_EXEC: Capability.INSTALL_EXEC,
}
_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)

# --- package files that steer semgrep's own target selection ----------------------------------
_CONTROL_NAMES = frozenset({
    ".semgrepignore", ".gitignore", ".semgrep.yml", ".semgrep.yaml", ".semgrepconfig", ".semgrepconfig.yml",
    ".git", ".semgrep",
})
IGNORE_FILE_CONTENT = (
    "# Written by Warden: an explicit, empty ignore list so semgrep scans every materialised file\n"
    "# (without this file semgrep applies default ignores such as tests/ and build/).\n"
)

# --- organisational config validation -------------------------------------------------------------
_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_REGISTRY_RE = re.compile(r"^(?:p|r|s|c|tr|ruleset|rules|policy|supply-chain)/", re.IGNORECASE)
_REGISTRY_WORDS = frozenset({"auto", "policy", "supply-chain", "secrets"})
_CONFIG_SUFFIXES = frozenset({".yml", ".yaml", ".json"})
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_DECIMAL_RE = re.compile(r"(?:\d{1,3}(?:\.\d{1,6})?|\.\d{1,6})")


class SemgrepError(RuntimeError):
    """semgrep could not produce a trustworthy result. Messages never contain tool output."""


class SemgrepTimeoutError(SemgrepError, TimeoutError):
    pass


class SemgrepOutputError(SemgrepError):
    pass


class SemgrepExecutionError(SemgrepError):
    pass


if taxonomy.get(SEMGREP_SCAN_INCOMPLETE) is None:
    taxonomy.register(taxonomy.CodeInfo(
        code=SEMGREP_SCAN_INCOMPLETE,
        category=Category.PIPELINE.value,
        dimension=taxonomy.Dimension.PIPELINE,
        title="Semgrep scan incomplete",
        remediation="Review the reported semgrep errors, unscanned files or refused rule sets; findings from the "
                    "files and rules that did run are still reported.",
    ))


# ============================================================================ config validation
@dataclass(frozen=True)
class ConfigDecision:
    """Outcome of validating one ``SEMGREP_EXTRA_CONFIGS`` entry."""

    config: str  # display-safe form of the configured value
    path: str | None = None  # resolved absolute path passed to semgrep when accepted
    reason: str | None = None  # machine-readable refusal reason

    @property
    def accepted(self) -> bool:
        return self.path is not None

    def to_dict(self) -> dict[str, Any]:
        return {"config": self.config, "reason": self.reason}


def _is_unc(text: str) -> bool:
    return text.startswith(("\\\\", "//"))


def _within(path: Path, root: Path) -> bool:
    try:
        return path == root or path.is_relative_to(root)
    except (TypeError, ValueError):
        return False


def _resolve_roots(roots: Iterable[Any] | None) -> list[Path]:
    """Existing absolute directories, fully resolved. Anything else is ignored (never trusted)."""
    resolved: list[Path] = []
    for raw in roots or ():
        fs_text = os.fspath(raw) if isinstance(raw, (str, os.PathLike)) else None
        if not isinstance(fs_text, str):
            continue
        text = fs_text.strip()
        if not text or _CONTROL_CHARS_RE.search(text) or _is_unc(text) or not Path(text).is_absolute():
            continue
        try:
            real = Path(os.path.realpath(text))
        except (OSError, ValueError):
            continue
        if real.is_dir() and not _is_unc(str(real)) and real not in resolved:
            resolved.append(real)
    return resolved


def _directory_escapes(directory: Path, root: Path) -> str | None:
    """Refusal reason if anything under ``directory`` resolves outside ``root`` (bounded walk)."""
    seen = 0
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        for name in [*dirnames, *filenames]:
            seen += 1
            if seen > MAX_CONFIG_DIR_ENTRIES:
                return "too_many_entries"
            try:
                real = Path(os.path.realpath(os.path.join(current, name)))
            except (OSError, ValueError):
                return "unresolvable_entry"
            if not _within(real, root):
                return "symlink_escape"
    return None


def validate_extra_config(value: Any, allowed_roots: Sequence[Path]) -> ConfigDecision:
    """Accept ``value`` only as a local rules file/directory inside an allowlisted root.

    ``allowed_roots`` must already be resolved (see :func:`resolve_extra_configs`).
    """
    text = os.fspath(value) if isinstance(value, (str, os.PathLike)) else None
    if not isinstance(text, str):  # also a PathLike whose __fspath__ returns bytes
        return ConfigDecision(config=sanitize_text(repr(value), max_len=120), reason="invalid_type")
    display = sanitize_text(text, max_len=200)
    stripped = text.strip()
    if not stripped:
        return ConfigDecision(config=display, reason="empty")
    if _CONTROL_CHARS_RE.search(stripped):
        return ConfigDecision(config=display, reason="invalid_characters")
    if stripped == "-":
        return ConfigDecision(config=display, reason="stdin")
    if _URL_RE.match(stripped) or stripped.lower().startswith("git@"):
        return ConfigDecision(config=display, reason="remote_url")
    if _REGISTRY_RE.match(stripped) or stripped.lower() in _REGISTRY_WORDS:
        return ConfigDecision(config=display, reason="registry_reference")
    if _is_unc(stripped):
        return ConfigDecision(config=display, reason="remote_path")
    if not allowed_roots:
        return ConfigDecision(config=display, reason="no_allowed_roots")
    try:
        resolved = Path(os.path.realpath(stripped))
    except (OSError, ValueError):
        return ConfigDecision(config=display, reason="not_found")
    if _is_unc(str(resolved)):
        return ConfigDecision(config=display, reason="remote_path")
    if not resolved.exists():
        return ConfigDecision(config=display, reason="not_found")
    root = next((r for r in allowed_roots if _within(resolved, r)), None)
    if root is None:
        return ConfigDecision(config=display, reason="outside_allowed_roots")
    if resolved.is_file():
        if resolved.suffix.lower() not in _CONFIG_SUFFIXES:
            return ConfigDecision(config=display, reason="unsupported_file_type")
    elif resolved.is_dir():
        escape = _directory_escapes(resolved, root)
        if escape:
            return ConfigDecision(config=display, reason=escape)
    else:
        return ConfigDecision(config=display, reason="not_a_file_or_directory")
    return ConfigDecision(config=display, path=str(resolved))


def _names_file(value: Any, target: str | os.PathLike[str]) -> bool:
    """True when ``value`` is a local path that resolves to ``target`` (never raises)."""
    text = os.fspath(value) if isinstance(value, (str, os.PathLike)) else None
    if not isinstance(text, str):
        return False
    text = text.strip()
    if not text or _CONTROL_CHARS_RE.search(text) or _URL_RE.match(text) or _is_unc(text):
        return False
    try:
        return os.path.normcase(os.path.realpath(text)) == os.path.normcase(os.path.realpath(target))
    except (OSError, ValueError):
        return False


def resolve_extra_configs(
    configs: Iterable[Any] | None,
    allowed_roots: Iterable[Any] | None,
    *,
    packaged_rules: str | os.PathLike[str] = PACKAGED_RULES,
) -> tuple[list[str], list[ConfigDecision]]:
    """(accepted absolute paths in configured order, refused decisions).

    An entry naming the packaged rules is skipped silently (they are always the first
    ``--config``), as are repeated entries: semgrep would report every result twice.
    """
    roots = _resolve_roots(allowed_roots)
    accepted: list[str] = []
    seen: set[str] = set()
    refused: list[ConfigDecision] = []
    for value in configs or ():
        if _names_file(value, packaged_rules):
            continue
        decision = validate_extra_config(value, roots)
        if not decision.accepted or decision.path is None:
            refused.append(decision)
            continue
        key = os.path.normcase(decision.path)
        if key not in seen:
            seen.add(key)
            accepted.append(decision.path)
    if refused:
        log.warning("semgrep_extra_configs_refused", configs=[d.to_dict() for d in refused[:10]])
    return accepted, refused


# ============================================================================ argv
def build_argv(
    binary: str,
    workspace: str | os.PathLike[str],
    *,
    rules: str | os.PathLike[str] = PACKAGED_RULES,
    extra_configs: Sequence[str] = (),
    rule_timeout: int = RULE_TIMEOUT_SECONDS,
    max_target_bytes: int | None = None,
    jobs: int = JOBS,
    max_memory_mb: int = MAX_MEMORY_MB,
) -> list[str]:
    """The ``semgrep scan`` argument vector (a list; never a shell string).

    ``extra_configs`` must already be validated absolute paths (:func:`resolve_extra_configs`).
    Flag names were checked against ``semgrep scan --help`` of semgrep 1.177.0; ``--timeout``
    is passed as an integer because that release rejects fractional values.
    """
    target = os.fspath(workspace)
    if max_target_bytes is None:
        max_target_bytes = max(1, int(settings.MAX_ANALYZED_FILE_BYTES) * TARGET_BYTES_FACTOR)
    argv = [str(binary), "scan", f"--config={os.fspath(rules)}"]
    argv.extend(f"--config={config}" for config in extra_configs)
    argv.extend([
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
        "--oss-only",
        f"--timeout={max(1, int(rule_timeout))}",
        f"--timeout-threshold={RULE_TIMEOUT_THRESHOLD}",
        f"--max-target-bytes={int(max_target_bytes)}",
        f"--max-memory={int(max_memory_mb)}",
        f"--jobs={int(jobs)}",
        f"--project-root={target}",
        target,
    ])
    return argv


def tool_env() -> dict[str, str]:
    """Extra environment for semgrep (belt and braces with the metrics/version flags)."""
    return {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "NO_COLOR": "1"}


# ============================================================================ helpers
def is_control_file(relpath: str) -> bool:
    """True for package members that would change which files semgrep scans (or how)."""
    return any(part.lower() in _CONTROL_NAMES for part in str(relpath).replace("\\", "/").split("/") if part)


def normalise_line_endings(source: SourceFile) -> SourceFile:
    """``source`` with every lone CR turned into LF (CRLF and LF are left untouched).

    CPython (and ``ast``) treat a lone ``\\r`` as a line break; semgrep 1.177.0 does not: in our
    validation it reported a call on the fourth Python line as line 1 and failed to parse the
    file. Without this step a package could use lone-CR line endings to hide code from the rules
    and to desynchronise semgrep's line numbers from the ``ast`` used for execution context. The
    text length is unchanged; reported line numbers follow Python's own counting.
    """
    if "\r" not in source.text:
        return source
    text = _LONE_CR_RE.sub("\n", source.text)
    return source if text == source.text else replace(source, text=text)


@dataclass
class _WorkspaceView:
    """What gets materialised: package text files minus semgrep control files, no binaries."""

    files: list[SourceFile]
    binaries: dict[str, bytes]


def parse_confidence(value: Any) -> float | None:
    """A confidence in [0, 1] from a number, a decimal string or HIGH/MEDIUM/LOW; else None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if text.upper() in CONFIDENCE_LABELS:
            return CONFIDENCE_LABELS[text.upper()]
        if not _DECIMAL_RE.fullmatch(text):
            return None
        number = float(text)
    elif isinstance(value, (int, float)):
        number = float(value)
    else:
        return None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return None
    return round(number, 4)


def resolve_confidence(metadata: Mapping[str, Any], context: str) -> tuple[float, str]:
    """(confidence, basis) following the precedence in the module docstring."""
    by_context = metadata.get("warden_confidence_by_context")
    if isinstance(by_context, Mapping):
        value = parse_confidence(by_context.get(context))
        if value is not None:
            return value, "rule_context"
    base, basis = DEFAULT_CONFIDENCE, "default"
    for key in ("warden_confidence", "confidence"):
        value = parse_confidence(metadata.get(key))
        if value is not None:
            base, basis = value, "rule"
            break
    if context == CONTEXT_TEST:
        return round(base * TEST_FILE_CONFIDENCE_FACTOR, 4), f"{basis}_test_file_discount"
    return base, basis


def map_severity(raw: Any) -> Severity:
    return SEVERITY_MAP.get(str(raw or "").strip().upper(), UNKNOWN_SEVERITY)


def _string_items(raw: Any) -> list[str]:
    values = [raw] if isinstance(raw, str) else list(raw)[:20] if isinstance(raw, (list, tuple)) else []
    return [v for v in values if isinstance(v, str)]


def extract_cwes(raw: Any) -> tuple[str, ...]:
    out: list[str] = []
    for value in _string_items(raw):
        for match in _CWE_RE.finditer(value[:500]):
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in out:
                out.append(cwe)
    return tuple(out[:5])


def extract_references(raw: Any) -> tuple[str, ...]:
    out: list[str] = []
    for value in _string_items(raw):
        if value.strip().lower().startswith(("https://", "http://")):
            ref = sanitize_text(value.strip(), max_len=200)
            if ref not in out:
                out.append(ref)
    return tuple(out[:5])


def _scrub_root(text: str, root: str | os.PathLike[str]) -> str:
    """Replace the (random, temporary) workspace path so evidence stays deterministic."""
    root_text = os.fspath(root)
    for variant in sorted({root_text, root_text.replace("\\", "/"), root_text.replace("/", "\\")}, key=len,
                          reverse=True):
        text = text.replace(variant, "<workspace>")
    return text


def normalize_result_path(raw: Any, root: str | os.PathLike[str]) -> str | None:
    """Workspace-relative ``/`` path for a semgrep result path, or None when outside the root."""
    if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\x00" in raw:
        return None
    root_path = Path(os.fspath(root))
    if PureWindowsPath(raw).drive or raw.startswith(("/", "\\")):
        candidate = Path(raw)
        if not candidate.is_absolute():  # rooted but driveless on Windows, or drive-relative "C:x"
            return None
    else:
        candidate = root_path / raw
    try:
        real_root = os.path.realpath(root_path)
        real = os.path.realpath(candidate)
        common = os.path.commonpath([real_root, real])
    except (OSError, ValueError):  # e.g. different drives
        return None
    if os.path.normcase(common) != os.path.normcase(real_root) or os.path.normcase(real) == os.path.normcase(real_root):
        return None
    try:
        return normalize_relpath(PurePosixPath(*Path(os.path.relpath(real, real_root)).parts).as_posix())
    except (UnsafePathError, ValueError):
        return None


def _function_body_spans(tree: ast.AST) -> list[tuple[int, int]]:
    """(first body line, last line) of every function and lambda body, walked without recursion."""
    spans: list[tuple[int, int]] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0].lineno if node.body else node.lineno
            spans.append((first, getattr(node, "end_lineno", None) or first))
            # Decorators and default values are evaluated when the def runs (import time).
            stack.extend(node.decorator_list)
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.Lambda):
            spans.append((node.body.lineno, getattr(node.body, "end_lineno", None) or node.body.lineno))
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return spans


def _is_test_path(relpath: str) -> bool:
    parts = [p for p in relpath.split("/") if p]
    if not parts:
        return False
    name = parts[-1].lower()
    return (any(p.lower() in _TEST_DIRS for p in parts[:-1]) or name == "conftest.py"
            or (name.startswith("test_") and name.endswith(".py")) or name.endswith("_test.py"))


class _ContextResolver:
    """Per-scan cache of function-body spans used to classify where a match executes."""

    def __init__(self, files_by_key: Mapping[str, SourceFile]) -> None:
        self._files = files_by_key
        self._spans: dict[str, list[tuple[int, int]] | None] = {}

    def _spans_for(self, relpath: str) -> list[tuple[int, int]] | None:
        key = relpath.casefold()
        if key not in self._spans:
            source = self._files.get(key)
            spans: list[tuple[int, int]] | None = None
            # A lone CR means ast and semgrep count lines differently: no context is better than a wrong one.
            if (source is not None and len(source.text) <= MAX_CONTEXT_PARSE_CHARS
                    and not _LONE_CR_RE.search(source.text)):
                try:
                    spans = _function_body_spans(ast.parse(source.text))
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    spans = None  # syntax errors and parser bombs: the context stays unknown
            self._spans[key] = spans
        return self._spans[key]

    def classify(self, relpath: str, line: int | None) -> str:
        if _is_test_path(relpath):
            return CONTEXT_TEST
        if relpath.split("/")[-1].lower() == "setup.py":
            return CONTEXT_INSTALL
        if not relpath.lower().endswith(".py") or line is None:
            return CONTEXT_UNKNOWN
        spans = self._spans_for(relpath)
        if spans is None:
            return CONTEXT_UNKNOWN
        return CONTEXT_RUNTIME if any(start <= line <= end for start, end in spans) else CONTEXT_IMPORT


def _positive_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _line_text(source: SourceFile | None, line: int | None) -> str | None:
    if source is None or line is None:
        return None
    lines = source.text.split("\n")
    if line > len(lines):
        return None
    return lines[line - 1].strip() or None


def parse_semgrep_json(stdout: str) -> dict[str, Any]:
    """The semgrep JSON document; :class:`SemgrepOutputError` for anything else."""
    try:
        document = json.loads(stdout)
    except (ValueError, RecursionError) as exc:
        raise SemgrepOutputError("semgrep produced malformed JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise SemgrepOutputError("semgrep JSON has no results list")
    if document.get("errors") is not None and not isinstance(document.get("errors"), list):
        raise SemgrepOutputError("semgrep JSON errors field is not a list")
    return document


# ============================================================================ normalisation
@dataclass
class NormalizedScan:
    findings: list[Finding]
    stats: dict[str, Any]


def _error_summary(errors: Sequence[Any], root: str | os.PathLike[str]) -> dict[str, Any]:
    by_level: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []
    for error in errors:
        if not isinstance(error, Mapping):
            by_level["unknown"] += 1
            by_type["malformed"] += 1
            continue
        level = sanitize_text(str(error.get("level") or "unknown"), max_len=20)
        raw_type = error.get("type")
        if isinstance(raw_type, list):  # e.g. ["PartialParsing", [locations]]
            raw_type = raw_type[0] if raw_type else None
        err_type = sanitize_text(str(raw_type or "unknown"), max_len=60)
        by_level[level] += 1
        by_type[err_type] += 1
        if len(samples) < MAX_ERROR_SAMPLES:
            rule_id = error.get("rule_id")
            samples.append({
                "level": level,
                "type": err_type,
                "rule_id": sanitize_text(rule_id, max_len=200) if isinstance(rule_id, str) else None,
                "path": normalize_result_path(error.get("path"), root),
                "message": sanitize_text(_scrub_root(str(error.get("message") or ""), root), max_len=160),
            })
    return {"count": len(errors), "by_level": dict(sorted(by_level.items())),
            "by_type": dict(sorted(by_type.items())), "samples": samples}


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return type(value).__name__


def _sort_key(result: Any) -> tuple[str, int, int, str, str]:
    """A total order: exact duplicates aside, input order never decides which result is kept."""
    if not isinstance(result, Mapping):
        return ("", 0, 0, "", _canonical(result))
    start = result.get("start") if isinstance(result.get("start"), Mapping) else {}
    return (str(result.get("path") or ""), _positive_int(start.get("line")) or 0,
            _positive_int(start.get("col")) or 0, str(result.get("check_id") or ""), _canonical(result))


def normalize_results(
    document: Mapping[str, Any],
    root: str | os.PathLike[str],
    files: Sequence[SourceFile] = (),
) -> NormalizedScan:
    """Turn a semgrep JSON document into ``SEMGREP_FINDING`` findings plus partial-result stats.

    ``root`` is the directory semgrep scanned; ``files`` are the package source files (used for
    the execution context and snippets). Deterministic for identical inputs.
    """
    files_by_key: dict[str, SourceFile] = {}
    for source in files:
        try:
            files_by_key.setdefault(normalize_relpath(source.relpath).casefold(), source)
        except UnsafePathError:
            continue
    resolver = _ContextResolver(files_by_key)
    raw_results = document.get("results")
    ordered = sorted(raw_results if isinstance(raw_results, list) else [], key=_sort_key)
    truncated = max(0, len(ordered) - MAX_RESULTS)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()
    rejected = 0
    rejected_samples: list[str] = []
    malformed = 0
    nosem_annotated = 0

    for result in ordered[:MAX_RESULTS]:
        if not isinstance(result, Mapping):
            malformed += 1
            continue
        rule_id = result.get("check_id")
        extra = result.get("extra")
        if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id) > 256 or not isinstance(extra, Mapping):
            malformed += 1
            continue
        relpath = normalize_result_path(result.get("path"), root)
        if relpath is None:
            rejected += 1
            if len(rejected_samples) < MAX_PATH_SAMPLES:
                rejected_samples.append(sanitize_text(_scrub_root(str(result.get("path")), root), max_len=120))
            continue
        start = result.get("start") if isinstance(result.get("start"), Mapping) else {}
        end = result.get("end") if isinstance(result.get("end"), Mapping) else {}
        line = _positive_int(start.get("line"))
        col = _positive_int(start.get("col"))
        end_line = _positive_int(end.get("line"))
        if end_line is not None and (line is None or end_line < line):
            end_line = None
        # finding_id covers rule, file and line, so one finding per (rule, file, line); the column
        # only distinguishes results that have no line.
        key = (rule_id, relpath.casefold(), line, col if line is None else None)
        if key in seen:
            continue
        seen.add(key)

        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), Mapping) else {}
        raw_severity = str(extra.get("severity") or "").strip().upper()
        severity = map_severity(raw_severity)
        context = resolver.classify(relpath, line)
        confidence, basis = resolve_confidence(metadata, context)
        source = files_by_key.get(relpath.casefold())
        rule_name = sanitize_text(rule_id.strip(), max_len=200)

        raw_category = metadata.get("category")
        category = raw_category if isinstance(raw_category, str) and raw_category in ALLOWED_CATEGORIES else None
        hint = metadata.get("warden_code")
        warden_code = hint if isinstance(hint, str) and taxonomy.get(hint) and hint not in _NON_HINT_CODES else None

        evidence: dict[str, Any] = {
            "rule_id": rule_name,
            "rule_source": "warden" if rule_name.startswith(WARDEN_RULE_PREFIX) else "organisation",
            "semgrep_severity": sanitize_text(raw_severity or "UNKNOWN", max_len=20),
            "context": context,
            "confidence_basis": basis,
        }
        if warden_code:
            evidence["warden_code"] = warden_code
        if isinstance(raw_category, str) and category is None:
            evidence["rule_category"] = sanitize_text(raw_category, max_len=60)
        for name in ("likelihood", "impact"):
            value = metadata.get(name)
            if isinstance(value, str) and value.strip():
                evidence[name] = sanitize_text(value.strip().upper(), max_len=20)
        if extra.get("is_ignored") is True:
            nosem_annotated += 1
            evidence["nosemgrep_annotated"] = True

        message = extra.get("message")
        text = " ".join(message.split()) if isinstance(message, str) and message.strip() else ""
        remediation = metadata.get("remediation")
        findings.append(Finding(
            Code.SEMGREP_FINDING,
            severity,
            WEIGHTS[severity],
            text or f"Semgrep rule {rule_name} matched",
            evidence,
            CAPABILITY_BY_CODE.get(warden_code) if warden_code else None,
            confidence=confidence,
            category=category,
            title=f"Semgrep rule {rule_name}",
            location=Location(
                file=source.relpath if source is not None else relpath,
                line=line,
                column=(col - 1) if col is not None else None,  # semgrep columns are 1-based
                end_line=end_line,
                snippet=_line_text(source, line),
            ),
            cwe=extract_cwes(metadata.get("cwe")),
            references=extract_references(metadata.get("references")),
            remediation=remediation if isinstance(remediation, str) and remediation.strip() else None,
            provenance=Provenance.tool(TOOL_NAME),
        ))

    errors = document.get("errors") or []
    skipped_rules = document.get("skipped_rules")
    stats = {
        "tool_version": sanitize_text(str(document["version"]), max_len=40) if document.get("version") else None,
        "results": len(findings),
        "errors": _error_summary(errors, root) if errors else {"count": 0},
        "rejected_result_paths": {"count": rejected, "samples": rejected_samples},
        "malformed_results": malformed,
        "results_truncated": truncated,
        "nosemgrep_annotated": nosem_annotated,
        "skipped_rules": len(skipped_rules) if isinstance(skipped_rules, list) else 0,
    }
    return NormalizedScan(findings=findings, stats=stats)


def unscanned_python_files(document: Mapping[str, Any], root: str | os.PathLike[str],
                           materialised: Iterable[str]) -> list[str]:
    """Materialised ``.py`` files absent from semgrep's ``paths.scanned`` (e.g. over the size cap)."""
    paths = document.get("paths")
    scanned_raw = paths.get("scanned") if isinstance(paths, Mapping) else None
    if not isinstance(scanned_raw, list):
        return []  # scanned paths not reported: nothing to compare against
    scanned = {p.casefold() for p in (normalize_result_path(s, root) for s in scanned_raw) if p}
    return sorted(rel for rel in materialised if rel.lower().endswith(".py") and rel.casefold() not in scanned)


def scan_status_finding(
    stats: Mapping[str, Any],
    *,
    refused: Sequence[ConfigDecision] = (),
    unscanned: Sequence[str] = (),
    skipped: Sequence[Mapping[str, Any]] = (),
    control_files_removed: int = 0,
) -> Finding | None:
    """One info-level, zero-weight ``SEMGREP_SCAN_INCOMPLETE`` finding, or None when complete."""
    reasons: list[str] = []
    error_count = int((stats.get("errors") or {}).get("count") or 0)
    rejected = int((stats.get("rejected_result_paths") or {}).get("count") or 0)
    if error_count:
        reasons.append(f"{error_count} semgrep error(s)")
    if refused:
        reasons.append(f"{len(refused)} organisational rule set(s) refused")
    if unscanned:
        reasons.append(f"{len(unscanned)} Python file(s) not scanned")
    if skipped:
        reasons.append(f"{len(skipped)} package file(s) not materialised")
    if rejected:
        reasons.append(f"{rejected} result(s) with paths outside the workspace dropped")
    if stats.get("malformed_results"):
        reasons.append(f"{stats['malformed_results']} malformed result(s) dropped")
    if stats.get("results_truncated"):
        reasons.append(f"{stats['results_truncated']} result(s) beyond the {MAX_RESULTS}-result cap dropped")
    if not reasons:
        return None
    evidence = {
        "tool": TOOL_NAME,
        **{k: v for k, v in stats.items() if k != "results"},
        "refused_configs": [d.to_dict() for d in refused[:10]],
        "unscanned_python_files": {"count": len(unscanned), "samples": list(unscanned[:MAX_PATH_SAMPLES])},
        "workspace_skipped": {"count": len(skipped), "samples": [dict(s) for s in skipped[:MAX_PATH_SAMPLES]]},
        "control_files_removed": int(control_files_removed),
    }
    return Finding(
        SEMGREP_SCAN_INCOMPLETE, Severity.info, 0.0, "Semgrep scan incomplete: " + "; ".join(reasons),
        evidence, confidence=1.0, provenance=Provenance.tool(TOOL_NAME),
    )


# ============================================================================ analyzer
class SemgrepAnalyzer(BaseAnalyzer):
    """Runs semgrep with Warden's packaged rules (and validated organisational rule sets).

    Constructor arguments override settings (used by tests); ``None`` means "read the setting
    at call time". Instances hold no per-scan state, so one instance serves concurrent scans.
    """

    name = ANALYZER_NAME
    version = ANALYZER_VERSION
    requires_network = False

    def __init__(
        self,
        *,
        binary: str | None = None,
        rules_path: str | os.PathLike[str] | None = None,
        extra_configs: Sequence[Any] | None = None,
        allowed_config_roots: Sequence[Any] | None = None,
        enabled: bool | None = None,
        timeout_seconds: float | None = None,
        workspace_base_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        self._binary = binary
        self._rules_path = Path(rules_path) if rules_path is not None else None
        self._extra_configs = tuple(extra_configs) if extra_configs is not None else None
        self._allowed_roots = tuple(allowed_config_roots) if allowed_config_roots is not None else None
        self._enabled = enabled
        self._timeout = timeout_seconds
        self._workspace_base_dir = workspace_base_dir

    # ------------------------------------------------------------------ configuration
    def binary(self) -> str:
        return self._binary if self._binary is not None else str(settings.SEMGREP_BINARY)

    def rules_path(self) -> Path:
        return self._rules_path if self._rules_path is not None else PACKAGED_RULES

    def enabled(self) -> bool:
        return bool(settings.SEMGREP_ENABLED if self._enabled is None else self._enabled)

    def extra_configs(self) -> tuple[Any, ...]:
        if self._extra_configs is not None:
            return self._extra_configs
        return tuple(settings.SEMGREP_EXTRA_CONFIGS or ())

    def allowed_config_roots(self) -> tuple[Any, ...]:
        if self._allowed_roots is not None:
            return self._allowed_roots
        # SEMGREP_CONFIG_ROOTS is a requested setting; while it is absent no root is allowlisted.
        return tuple(getattr(settings, "SEMGREP_CONFIG_ROOTS", None) or ())

    def timeout_seconds(self) -> float:
        """Wall-clock budget for one ``analyze`` call (tool probe, materialisation and scan)."""
        if self._timeout is not None:
            return max(1.0, float(self._timeout))
        analyzer_budget = float(settings.ANALYZER_TIMEOUT_SECONDS)
        # Headroom so this analyzer kills semgrep (and removes the workspace) before the
        # orchestrator gives up on it and reports a bare timeout.
        margin = max(TIMEOUT_MARGIN_SECONDS, analyzer_budget * TIMEOUT_MARGIN_FRACTION)
        return max(1.0, min(float(settings.TOOL_TIMEOUT_SECONDS), analyzer_budget - margin))

    # ------------------------------------------------------------------ protocol
    def availability(self) -> ToolStatus:
        if not self.enabled():
            return ToolStatus(name=TOOL_NAME, available=False, detail="disabled by configuration (SEMGREP_ENABLED)")
        status = find_tool(self.binary())
        return ToolStatus(name=TOOL_NAME, available=status.available, version=status.version, detail=status.detail)

    def analyze(self, ctx: PackageContext) -> list[Finding]:
        started = time.monotonic()
        budget = self.timeout_seconds()
        status = self.availability()
        if not status.available:
            return [Finding(
                Code.TOOL_UNAVAILABLE, Severity.info, 0.0, f"Analyzer '{self.name}' skipped: semgrep is unavailable",
                {"analyzer": self.name, "tool": TOOL_NAME, "version": status.version, "detail": status.detail},
                confidence=1.0, provenance=Provenance.tool(TOOL_NAME),
            )]
        rules = self.rules_path()
        if not rules.is_file():
            raise SemgrepError("packaged semgrep rules are missing")
        accepted, refused = resolve_extra_configs(self.extra_configs(), self.allowed_config_roots(),
                                                  packaged_rules=rules)

        source_files = list(getattr(ctx, "files", None) or [])
        kept = [normalise_line_endings(f) for f in source_files if not is_control_file(f.relpath)]
        removed = len(source_files) - len(kept)
        if not kept:
            status_finding = scan_status_finding({}, refused=refused, control_files_removed=removed)
            return [status_finding] if status_finding else []

        view = _WorkspaceView(files=kept, binaries={})
        with package_workspace(view, include_binaries=False, base_dir=self._workspace_base_dir) as workspace:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(workspace.root / ".semgrepignore", flags, 0o600), "wb") as fh:
                fh.write(IGNORE_FILE_CONTENT.encode("utf-8"))
            argv = build_argv(self.binary(), workspace.root, rules=rules, extra_configs=accepted)
            remaining = budget - (time.monotonic() - started)
            if remaining <= 0:
                raise SemgrepTimeoutError("semgrep time budget exhausted before the scan started")
            result = run_tool(argv, timeout=remaining, cwd=workspace.root, extra_env=tool_env(),
                              max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES)
            if result.timed_out:
                raise SemgrepTimeoutError("semgrep timed out")
            if result.truncated:
                raise SemgrepOutputError("semgrep output exceeded the capture limit")
            if result.returncode not in (0, 1):
                raise SemgrepExecutionError(f"semgrep exited with status {result.returncode}")
            document = parse_semgrep_json(result.stdout)
            normalized = normalize_results(document, workspace.root, kept)
            unscanned = unscanned_python_files(document, workspace.root, workspace.files)
            skipped = list(workspace.skipped)

        findings = list(normalized.findings)
        status_finding = scan_status_finding(normalized.stats, refused=refused, unscanned=unscanned, skipped=skipped,
                                             control_files_removed=removed)
        if status_finding is not None:
            findings.append(status_finding)
        return findings


__all__ = [
    "ANALYZER_NAME",
    "ANALYZER_VERSION",
    "PACKAGED_RULES",
    "SEMGREP_SCAN_INCOMPLETE",
    "ConfigDecision",
    "NormalizedScan",
    "SemgrepAnalyzer",
    "SemgrepError",
    "SemgrepExecutionError",
    "SemgrepOutputError",
    "SemgrepTimeoutError",
    "build_argv",
    "is_control_file",
    "map_severity",
    "normalise_line_endings",
    "normalize_result_path",
    "normalize_results",
    "parse_confidence",
    "parse_semgrep_json",
    "resolve_confidence",
    "resolve_extra_configs",
    "scan_status_finding",
    "unscanned_python_files",
    "validate_extra_config",
]
