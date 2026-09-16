"""Packaged analysis rules and the Warden X YARA rule loader.

``app/analysis/rules/yara/*.yar`` holds the YARA rules shipped with Warden X, one namespace per
file (the file stem). Every public rule carries a metadata schema (documented in
``rules/yara/README.md``):

* required: ``id``, ``version``, ``author``, ``date``, ``description``, ``severity``,
  ``confidence``, ``attack``, ``reference``, ``false_positives`` — all strings. YARA metadata has
  no float type, so ``confidence`` is a decimal string such as ``"0.85"``;
* optional: ``category`` (a finding category), ``capability`` (a policy capability tag),
  ``scope`` (comma-separated file kinds the rule applies to; default ``any``) and ``cwe``.

This module reads rule files with a small pure-Python reader (yara-python is not needed) and
validates that schema. The packaged rules are loaded and validated **at import time**: an
invalid packaged rule raises :class:`RuleValidationError` as soon as this package is imported,
so a broken rule fails every test run instead of silently switching detection off.

Organisational rules (``settings.YARA_RULES_DIR``) go through the same validation with
:func:`load_ruleset` when the YARA analyzer loads them; problems there are reported as analysis
failures, never ignored. Validation also rejects constructs Warden cannot honour: ``include``
directives (rules are compiled with includes disabled) and string count / offset / length
references (``#a``, ``@a[i]``, ``!a[i]``), which are unreliable because Warden scans in YARA
fast mode (only the first occurrence of each string is recorded, which bounds memory on
hostile input). Packaged rules are also held to house style: author ``Warden X``,
``WX-YARA-NNN`` ids, an explicit ``scope``, no unknown metadata keys, no modules, and no private
or global rules. Organisational rules may use modules, global/private rules and extra metadata,
but must not claim the ``WX-YARA-`` id prefix.

The reader understands the YARA grammar far enough to find imports, includes, rules, tags,
metadata and condition string references (comments and text/hex/regex strings are tokenised as
units). It is not a YARA compiler: everything else is left to yara-python, and the analyzer
cross-checks the compiled metadata against this reader.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from app.analysis.findings import Category
from app.analysis.signals import Capability

RULES_ROOT = Path(__file__).resolve().parent
YARA_RULES_PATH = RULES_ROOT / "yara"
YARA_RULE_SUFFIXES = (".yar", ".yara")

PACKAGED_RULESET = "packaged"
ORGANISATIONAL_RULESET = "organisational"
RULESETS = (PACKAGED_RULESET, ORGANISATIONAL_RULESET)
ORG_NAMESPACE_PREFIX = "org."
PACKAGED_AUTHOR = "Warden X"
PACKAGED_ID_PREFIX = "WX-YARA-"

REQUIRED_META = (
    "id", "version", "author", "date", "description", "severity", "confidence", "attack", "reference",
    "false_positives",
)
OPTIONAL_META = ("category", "capability", "scope", "cwe")
SEVERITIES = ("low", "medium", "high", "critical")

# File kinds the YARA analyzer assigns to scanned members (see analyzers/yara_scan.py).
FILE_KINDS = (
    "python", "shell", "powershell", "batch", "javascript", "config", "metadata", "document", "dockerfile",
    "other_text", "binary",
)
CODE_KINDS = ("python", "shell", "powershell", "batch", "javascript")
SCOPE_ALIASES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "any": FILE_KINDS,
    "text": tuple(k for k in FILE_KINDS if k != "binary"),
    "code": CODE_KINDS,
})
# Categories a YARA rule may assign. Pipeline, vulnerability, secret and derived categories are
# produced by other subsystems and would distort risk dimensions if a signature claimed them.
YARA_CATEGORIES = frozenset({
    Category.MALICIOUS_BEHAVIOR.value, Category.CAPABILITY.value, Category.INSTALL_TIME.value,
    Category.OBFUSCATION.value, Category.CREDENTIAL_ACCESS.value, Category.IOC.value,
    Category.SUSPICIOUS_ARTIFACT.value, Category.OTHER.value,
})
CAPABILITIES = frozenset(
    value for key, value in vars(Capability).items() if not key.startswith("_") and isinstance(value, str)
)

# Bounds for reading rule files (organisational rules are operator-supplied, but still bounded).
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_RULE_FILES = 256
MAX_DESCRIPTION_CHARS = 300
MAX_FALSE_POSITIVES_CHARS = 500
_MAX_PROBLEM_VALUE_CHARS = 80

_PACKAGED_ID_RE = re.compile(r"WX-YARA-\d{3}")
_ORG_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:\-]{1,63}")
_VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,6}")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CONFIDENCE_RE = re.compile(r"0(?:\.\d{1,4})?|1(?:\.0{1,4})?")
_ATTACK_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
_CWE_RE = re.compile(r"CWE-\d{1,5}")
_REFERENCE_RE = re.compile(r"https://[^\s\"'<>]{4,300}")
_SCOPE_TOKEN_RE = re.compile(r"[a-z_]{2,20}")

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"0x[0-9A-Fa-f]+|0o[0-7]+|\d+(?:\.\d+)?(?:KB|MB)?")
_STRING_REF_RE = re.compile(r"[$#@!][A-Za-z0-9_]*\*?")
_HEX2_RE = re.compile(r"[0-9A-Fa-f]{2}")
_TWO_CHAR_PUNCT = frozenset({"==", "!=", "<=", ">=", "<<", ">>", ".."})
_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
_SECTIONS = ("meta", "strings", "condition")


class RuleSyntaxError(ValueError):
    """A rule file could not be read by the metadata reader."""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


class RuleValidationError(ValueError):
    """One or more rules violate the metadata schema or Warden's rule constraints."""

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems) or ("invalid rules",)
        shown = "; ".join(self.problems[:10])
        more = f" (+{len(self.problems) - 10} more)" if len(self.problems) > 10 else ""
        super().__init__(shown + more)


@dataclass(frozen=True)
class ParsedRule:
    """One rule as seen by the metadata reader."""

    name: str
    line: int
    tags: tuple[str, ...]
    is_private: bool
    is_global: bool
    meta: Mapping[str, str | int | bool]
    duplicate_meta: tuple[str, ...]
    # Condition references that fast-mode scanning cannot honour: ``#a``, ``@a``, ``!a``.
    fast_mode_conflicts: tuple[str, ...]


@dataclass(frozen=True)
class ParsedRuleFile:
    namespace: str
    imports: tuple[str, ...]
    includes: tuple[str, ...]
    rules: tuple[ParsedRule, ...]


@dataclass(frozen=True)
class YaraRuleMeta:
    """Validated metadata of one public rule."""

    rule_id: str
    name: str
    namespace: str
    ruleset: str
    version: str
    author: str
    date: str
    description: str
    severity: str
    confidence: float
    attack: tuple[str, ...]
    reference: str
    false_positives: str
    category: str | None
    capability: str | None
    cwe: tuple[str, ...]
    scope: tuple[str, ...]  # as declared (``("any",)`` when not declared)
    kinds: frozenset[str]  # scope expanded to file kinds
    raw_meta: tuple[tuple[str, str | int | bool], ...]  # the metadata as written, sorted by key

    def applies_to(self, kind: str) -> bool:
        return kind in self.kinds


@dataclass(frozen=True)
class RuleSource:
    namespace: str
    path: Path
    text: str
    sha256: str


@dataclass(frozen=True)
class LoadedRuleset:
    """Validated rule sources ready to compile, with metadata keyed by ``(namespace, rule name)``."""

    ruleset: str
    sources: tuple[RuleSource, ...]
    rules: Mapping[tuple[str, str], YaraRuleMeta]
    digest: str

    def source_map(self) -> dict[str, str]:
        return {source.namespace: source.text for source in self.sources}

    def by_id(self) -> dict[str, YaraRuleMeta]:
        return {meta.rule_id: meta for meta in self.rules.values()}


# --------------------------------------------------------------------------- reader
@dataclass(frozen=True)
class _Token:
    kind: str  # ident | string | regex | hex | number | strref | punct
    value: str
    line: int


def _unescape(raw: str, line: int) -> str:
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1:i + 2]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        elif nxt == "x" and _HEX2_RE.fullmatch(raw[i + 2:i + 4]):
            out.append(chr(int(raw[i + 2:i + 4], 16)))
            i += 4
        else:
            raise RuleSyntaxError("illegal escape sequence in string", line)
    return "".join(out)


def _scan_delimited(text: str, start: int, delimiter: str, line: int, what: str) -> int:
    """Index of the closing ``delimiter`` for a string/regex opened at ``start`` (escapes honoured)."""
    j = start + 1
    n = len(text)
    while j < n and text[j] != delimiter:
        if text[j] == "\n":
            raise RuleSyntaxError(f"unterminated {what}", line)
        j += 2 if text[j] == "\\" else 1
    if j >= n:
        raise RuleSyntaxError(f"unterminated {what}", line)
    return j


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v﻿":
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise RuleSyntaxError("unterminated comment", line)
            line += text.count("\n", i, end)
            i = end + 2
            continue
        prev = tokens[-1] if tokens else None
        after_assign = prev is not None and prev.kind == "punct" and prev.value == "="
        if ch == '"':
            end = _scan_delimited(text, i, '"', line, "string")
            tokens.append(_Token("string", _unescape(text[i + 1:end], line), line))
            i = end + 1
            continue
        if ch == "{" and after_assign:  # hex string
            end = text.find("}", i)
            if end < 0:
                raise RuleSyntaxError("unterminated hex string", line)
            tokens.append(_Token("hex", text[i + 1:end], line))
            line += text.count("\n", i, end)
            i = end + 1
            continue
        if ch == "/" and (after_assign or (prev is not None and prev.kind == "ident" and prev.value == "matches")):
            end = _scan_delimited(text, i, "/", line, "regular expression")
            tokens.append(_Token("regex", text[i + 1:end], line))
            i = end + 1
            while i < n and text[i] in "is":
                i += 1
            continue
        if ch == "!" and text.startswith("!=", i):
            tokens.append(_Token("punct", "!=", line))
            i += 2
            continue
        if ch in "$#@!":
            match = _STRING_REF_RE.match(text, i)
            assert match is not None  # the class always matches one character
            tokens.append(_Token("strref", match.group(0), line))
            i = match.end()
            continue
        match = _IDENT_RE.match(text, i)
        if match:
            tokens.append(_Token("ident", match.group(0), line))
            i = match.end()
            continue
        match = _NUMBER_RE.match(text, i)
        if match:
            tokens.append(_Token("number", match.group(0), line))
            i = match.end()
            continue
        if text[i:i + 2] in _TWO_CHAR_PUNCT:
            tokens.append(_Token("punct", text[i:i + 2], line))
            i += 2
            continue
        tokens.append(_Token("punct", ch, line))
        i += 1
    return tokens


def _meta_int(token: _Token, negative: bool) -> int:
    value = token.value
    if value.startswith("0x"):
        number = int(value, 16)
    elif value.startswith("0o"):
        number = int(value[2:], 8)
    elif value.isdigit():
        number = int(value)
    else:
        raise RuleSyntaxError(f"unsupported metadata number {value!r}", token.line)
    return -number if negative else number


class _Reader:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset: int = 0) -> _Token | None:
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def take(self, kind: str, value: str | None = None, what: str | None = None) -> _Token:
        tok = self.peek()
        if tok is None or tok.kind != kind or (value is not None and tok.value != value):
            expected = what or (repr(value) if value is not None else kind)
            found = "end of file" if tok is None else repr(tok.value[:_MAX_PROBLEM_VALUE_CHARS])
            raise RuleSyntaxError(f"expected {expected}, found {found}", tok.line if tok else None)
        self.pos += 1
        return tok

    def at(self, kind: str, value: str | None = None, offset: int = 0) -> bool:
        tok = self.peek(offset)
        return tok is not None and tok.kind == kind and (value is None or tok.value == value)


def parse_rule_text(text: str, namespace: str) -> ParsedRuleFile:
    """Read imports, includes, rules, tags, metadata and condition string references."""
    reader = _Reader(_tokenize(text))
    imports: list[str] = []
    includes: list[str] = []
    rules: list[ParsedRule] = []
    while reader.peek() is not None:
        if reader.at("ident", "import") or reader.at("ident", "include"):
            keyword = reader.take("ident").value
            target = reader.take("string", what=f"a quoted {keyword} target").value
            (imports if keyword == "import" else includes).append(target)
            continue
        rules.append(_parse_rule(reader))
    return ParsedRuleFile(namespace, tuple(imports), tuple(includes), tuple(rules))


def _parse_rule(reader: _Reader) -> ParsedRule:
    first = reader.peek()
    start_line = first.line if first else 0
    is_private = is_global = False
    while reader.at("ident", "private") or reader.at("ident", "global"):
        if reader.take("ident").value == "private":
            is_private = True
        else:
            is_global = True
    reader.take("ident", "rule", what="'rule'")
    name = reader.take("ident", what="a rule name").value
    tags: list[str] = []
    if reader.at("punct", ":"):
        reader.take("punct", ":")
        while reader.at("ident"):
            tags.append(reader.take("ident").value)
    reader.take("punct", "{", what="'{'")

    meta: dict[str, str | int | bool] = {}
    duplicates: list[str] = []
    conflicts: list[str] = []
    seen: list[str] = []
    section: str | None = None
    while True:
        tok = reader.peek()
        if tok is None:
            raise RuleSyntaxError(f"rule {name}: missing closing brace", start_line)
        if tok.kind == "punct" and tok.value == "}":
            reader.pos += 1
            break
        if tok.kind == "ident" and tok.value in _SECTIONS and reader.at("punct", ":", offset=1):
            if tok.value in seen:
                raise RuleSyntaxError(f"rule {name}: duplicate '{tok.value}' section", tok.line)
            if seen and _SECTIONS.index(tok.value) < _SECTIONS.index(seen[-1]):
                raise RuleSyntaxError(f"rule {name}: '{tok.value}' section out of order", tok.line)
            seen.append(tok.value)
            section = tok.value
            reader.pos += 2
            continue
        if section is None:
            raise RuleSyntaxError(f"rule {name}: expected 'meta:', 'strings:' or 'condition:'", tok.line)
        if section == "meta":
            key = reader.take("ident", what="a metadata key").value
            reader.take("punct", "=", what="'=' after metadata key")
            value: str | int | bool
            if reader.at("string"):
                value = reader.take("string").value
            elif reader.at("ident", "true") or reader.at("ident", "false"):
                value = reader.take("ident").value == "true"
            elif reader.at("punct", "-") and reader.at("number", offset=1):
                reader.pos += 1
                value = _meta_int(reader.take("number"), negative=True)
            elif reader.at("number"):
                value = _meta_int(reader.take("number"), negative=False)
            else:
                raise RuleSyntaxError(f"rule {name}: metadata '{key}' needs a string, integer or boolean", tok.line)
            if key in meta:
                duplicates.append(key)
            meta[key] = value
            continue
        if section == "condition" and tok.kind == "strref" and tok.value[:1] in "#@!":
            conflicts.append(tok.value)
        reader.pos += 1
    if "condition" not in seen:
        raise RuleSyntaxError(f"rule {name}: missing 'condition:' section", start_line)
    return ParsedRule(
        name=name, line=start_line, tags=tuple(tags), is_private=is_private, is_global=is_global,
        meta=MappingProxyType(meta), duplicate_meta=tuple(duplicates), fast_mode_conflicts=tuple(conflicts),
    )


# --------------------------------------------------------------------------- validation
def _show(value: object) -> str:
    text = repr(value)
    return text if len(text) <= _MAX_PROBLEM_VALUE_CHARS else text[:_MAX_PROBLEM_VALUE_CHARS - 1] + "…"


def expand_scope(tokens: Iterable[str]) -> frozenset[str]:
    kinds: set[str] = set()
    for token in tokens:
        kinds.update(SCOPE_ALIASES.get(token, (token,)))
    return frozenset(kinds)


def validate_meta(meta: Mapping[str, object], *, name: str, namespace: str, ruleset: str) -> YaraRuleMeta:
    """Validate one public rule's metadata; raises :class:`RuleValidationError` listing every problem."""
    if ruleset not in RULESETS:
        raise ValueError(f"unknown ruleset {ruleset!r}")
    packaged = ruleset == PACKAGED_RULESET
    where = f"{namespace}:{name}"
    problems: list[str] = []

    def text(key: str, *, required: bool = True, max_len: int = 300, pattern: re.Pattern[str] | None = None,
             ) -> str | None:
        value = meta.get(key)
        if value is None:
            if required:
                problems.append(f"{where}: missing meta '{key}'")
            return None
        if not isinstance(value, str):
            problems.append(f"{where}: meta '{key}' must be a string, got {type(value).__name__}")
            return None
        if not value.strip() or value != value.strip():
            problems.append(f"{where}: meta '{key}' must be non-empty without surrounding whitespace")
            return None
        if len(value) > max_len:
            problems.append(f"{where}: meta '{key}' is longer than {max_len} characters")
            return None
        if pattern is not None and not pattern.fullmatch(value):
            problems.append(f"{where}: meta '{key}' has an invalid value {_show(value)}")
            return None
        return value

    def id_list(key: str, pattern: re.Pattern[str], *, required: bool) -> tuple[str, ...]:
        raw = text(key, required=required)
        if raw is None:
            return ()
        items = tuple(part.strip() for part in raw.split(","))
        bad = [item for item in items if not pattern.fullmatch(item)]
        if bad:
            problems.append(f"{where}: meta '{key}' has invalid entries {_show(bad)}")
        if len(set(items)) != len(items):
            problems.append(f"{where}: meta '{key}' lists an entry more than once")
        return items

    rule_id = text("id", pattern=_PACKAGED_ID_RE if packaged else _ORG_ID_RE)
    if rule_id and not packaged and rule_id.startswith(PACKAGED_ID_PREFIX):
        problems.append(f"{where}: organisational rules must not use the reserved '{PACKAGED_ID_PREFIX}' id prefix")
    version = text("version", pattern=_VERSION_RE)
    author = text("author", max_len=120)
    if packaged and author is not None and author != PACKAGED_AUTHOR:
        problems.append(f"{where}: packaged rules must have author {PACKAGED_AUTHOR!r}")
    date = text("date", pattern=_DATE_RE)
    if date is not None:
        try:
            _dt.date.fromisoformat(date)
        except ValueError:
            problems.append(f"{where}: meta 'date' is not a valid calendar date")
    description = text("description", max_len=MAX_DESCRIPTION_CHARS)
    severity = text("severity")
    if severity is not None and severity not in SEVERITIES:
        problems.append(f"{where}: meta 'severity' must be one of {', '.join(SEVERITIES)}")
    confidence_raw = text("confidence", pattern=_CONFIDENCE_RE)
    confidence = float(confidence_raw) if confidence_raw is not None else 0.0
    attack = id_list("attack", _ATTACK_RE, required=True)
    reference = text("reference", pattern=_REFERENCE_RE)
    false_positives = text("false_positives", max_len=MAX_FALSE_POSITIVES_CHARS)

    category = text("category", required=False)
    if category is not None and category not in YARA_CATEGORIES:
        problems.append(f"{where}: meta 'category' must be one of {', '.join(sorted(YARA_CATEGORIES))}")
    capability = text("capability", required=False)
    if capability is not None and capability not in CAPABILITIES:
        problems.append(f"{where}: meta 'capability' {_show(capability)} is not a known capability tag")
    cwe = id_list("cwe", _CWE_RE, required=False)

    scope_raw = text("scope", required=packaged)
    scope: tuple[str, ...] = ("any",)
    if scope_raw is not None:
        scope = tuple(part.strip() for part in scope_raw.split(","))
        unknown = [t for t in scope if not _SCOPE_TOKEN_RE.fullmatch(t) or (t not in SCOPE_ALIASES and
                                                                          t not in FILE_KINDS)]
        if unknown:
            problems.append(f"{where}: meta 'scope' has unknown file kinds {_show(unknown)}")

    if packaged:
        unknown_keys = sorted(set(meta) - set(REQUIRED_META) - set(OPTIONAL_META))
        if unknown_keys:
            problems.append(f"{where}: unknown meta keys {_show(unknown_keys)} (packaged rules use a fixed schema)")
    if problems:
        raise RuleValidationError(problems)
    assert rule_id and version and author and date and description and severity and reference and false_positives
    return YaraRuleMeta(
        rule_id=rule_id, name=name, namespace=namespace, ruleset=ruleset, version=version, author=author,
        date=date, description=description, severity=severity, confidence=confidence, attack=attack,
        reference=reference, false_positives=false_positives, category=category, capability=capability, cwe=cwe,
        scope=scope, kinds=expand_scope(scope),
        raw_meta=tuple(sorted((str(k), v) for k, v in meta.items())),  # type: ignore[misc]
    )


def structural_problems(parsed: ParsedRuleFile, *, ruleset: str, source: str) -> list[str]:
    """Constraint violations that do not concern metadata values."""
    problems: list[str] = []
    packaged = ruleset == PACKAGED_RULESET
    if not parsed.rules:
        problems.append(f"{source}: contains no rules")
    if parsed.includes:
        problems.append(f"{source}: include directives are not supported (rules compile with includes disabled)")
    if packaged and parsed.imports:
        problems.append(f"{source}: packaged rules must not import YARA modules")
    names: set[str] = set()
    for rule in parsed.rules:
        where = f"{parsed.namespace}:{rule.name}"
        if rule.name in names:
            problems.append(f"{where}: duplicate rule name in namespace")
        names.add(rule.name)
        if rule.duplicate_meta:
            problems.append(f"{where}: duplicate meta keys {_show(sorted(set(rule.duplicate_meta)))}")
        if rule.fast_mode_conflicts:
            problems.append(
                f"{where}: condition uses string count/offset/length references "
                f"{_show(sorted(set(rule.fast_mode_conflicts)))}, which are unreliable in fast-mode scanning"
            )
        if packaged and (rule.is_private or rule.is_global):
            problems.append(f"{where}: packaged rules must not be private or global")
    return problems


def namespace_for(path: Path, *, ruleset: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_]", "_", path.stem) or "rules"
    return stem if ruleset == PACKAGED_RULESET else ORG_NAMESPACE_PREFIX + stem


def list_rule_files(directory: Path) -> tuple[Path, ...]:
    """``*.yar`` / ``*.yara`` regular files directly inside ``directory`` (sorted by name, bounded)."""
    files: list[Path] = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.suffix.lower() in YARA_RULE_SUFFIXES and entry.is_file():
            files.append(entry)
            if len(files) > MAX_RULE_FILES:
                raise RuleValidationError([f"more than {MAX_RULE_FILES} rule files in the rules directory"])
    return tuple(files)


def _read_rule_file(path: Path) -> str:
    with path.open("rb") as handle:
        data = handle.read(MAX_RULE_FILE_BYTES + 1)
    if len(data) > MAX_RULE_FILE_BYTES:
        raise RuleValidationError([f"{path.name}: larger than {MAX_RULE_FILE_BYTES} bytes"])
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleValidationError([f"{path.name}: not valid UTF-8"]) from None


def load_ruleset(directory: Path | str, *, ruleset: str) -> LoadedRuleset:
    """Read and validate every rule file in ``directory``; raises :class:`RuleValidationError`."""
    if ruleset not in RULESETS:
        raise ValueError(f"unknown ruleset {ruleset!r}")
    root = Path(directory)
    try:
        if not root.is_dir():
            raise RuleValidationError([f"rules directory {_show(str(root))} does not exist or is not a directory"])
        files = list_rule_files(root)
    except OSError as exc:
        raise RuleValidationError([f"rules directory is not readable ({type(exc).__name__})"]) from None
    if not files:
        raise RuleValidationError([f"rules directory {_show(str(root))} contains no .yar/.yara files"])

    problems: list[str] = []
    sources: list[RuleSource] = []
    metas: dict[tuple[str, str], YaraRuleMeta] = {}
    ids: dict[str, str] = {}
    namespaces: set[str] = set()
    for path in files:
        namespace = namespace_for(path, ruleset=ruleset)
        if namespace in namespaces:
            problems.append(f"{path.name}: namespace {namespace!r} is already used by another rule file")
            continue
        namespaces.add(namespace)
        try:
            text = _read_rule_file(path)
            parsed = parse_rule_text(text, namespace)
        except RuleValidationError as exc:
            problems.extend(exc.problems)
            continue
        except RuleSyntaxError as exc:
            problems.append(f"{path.name}: {exc}")
            continue
        except OSError as exc:
            problems.append(f"{path.name}: unreadable ({type(exc).__name__})")
            continue
        problems.extend(structural_problems(parsed, ruleset=ruleset, source=path.name))
        for rule in parsed.rules:
            if rule.is_private:
                continue  # private rules never produce matches, so they carry no finding metadata
            try:
                meta = validate_meta(rule.meta, name=rule.name, namespace=namespace, ruleset=ruleset)
            except RuleValidationError as exc:
                problems.extend(exc.problems)
                continue
            where = f"{namespace}:{rule.name}"
            if meta.rule_id in ids:
                problems.append(f"{where}: rule id {meta.rule_id} is already used by {ids[meta.rule_id]}")
            ids.setdefault(meta.rule_id, where)
            metas[(namespace, rule.name)] = meta
        sources.append(RuleSource(namespace, path, text, hashlib.sha256(text.encode("utf-8")).hexdigest()))
    if problems:
        raise RuleValidationError(problems)
    digest = hashlib.sha256(
        "\n".join(f"{s.namespace}:{s.sha256}" for s in sources).encode("utf-8")
    ).hexdigest()
    return LoadedRuleset(ruleset, tuple(sources), MappingProxyType(metas), digest)


# Import-time validation of the packaged rules: an invalid rule must fail loudly, not disable detection.
PACKAGED_YARA_RULES: LoadedRuleset = load_ruleset(YARA_RULES_PATH, ruleset=PACKAGED_RULESET)

__all__ = [
    "CAPABILITIES",
    "CODE_KINDS",
    "FILE_KINDS",
    "OPTIONAL_META",
    "ORGANISATIONAL_RULESET",
    "ORG_NAMESPACE_PREFIX",
    "PACKAGED_RULESET",
    "PACKAGED_YARA_RULES",
    "REQUIRED_META",
    "RULES_ROOT",
    "SCOPE_ALIASES",
    "SEVERITIES",
    "YARA_CATEGORIES",
    "YARA_RULES_PATH",
    "LoadedRuleset",
    "ParsedRule",
    "ParsedRuleFile",
    "RuleSource",
    "RuleSyntaxError",
    "RuleValidationError",
    "YaraRuleMeta",
    "expand_scope",
    "list_rule_files",
    "load_ruleset",
    "namespace_for",
    "parse_rule_text",
    "structural_problems",
    "validate_meta",
]
