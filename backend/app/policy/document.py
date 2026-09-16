"""Policy-as-code documents (``apiVersion: warden.dev/v1``, ``kind: Policy``).

A policy document is the reviewable, versionable form of an organisational policy::

    apiVersion: warden.dev/v1
    kind: Policy
    metadata: {name: prod-strict, environment: production}
    spec:
      thresholds: {warn: 40, block: 70}
      min_package_age_days: 0
      deny:
        packages: []
        codes: [IOC_MATCH]
        categories: [malicious_behavior, attack_chain, dependency_confusion]
        capabilities: [install_hook_exec, ioc]
        vulnerabilities: {known_exploited: true, min_severity: critical, min_cvss: 9.0, min_epss: null}
        min_confidence: 0.7
      warn: {codes: [], categories: [obfuscation], capabilities: [], vulnerabilities: {min_severity: high},
             min_confidence: 0.5}
      require: {provenance: null, hash_verified: false, sbom: false}
      allow: {packages: []}
      exceptions:
        - {package: internal-package, version: "<2.0", codes: [], categories: [], expires: 2026-12-01,
           reason: "...", approved_by: sec-team}

Validation is strict because a typo in a security policy silently disables a control:

* unknown keys are rejected at every level (``extra="forbid"``);
* finding codes must exist in :class:`app.analysis.signals.Code` or the taxonomy registry,
  categories in :class:`app.analysis.findings.Category`, capabilities in
  :class:`app.analysis.signals.Capability`; package names must follow the PEP 508 project-name
  grammar and are stored PEP 503-normalised;
* thresholds and confidences are range-checked numbers (booleans and numeric strings are not
  coerced); ``thresholds.warn`` must not exceed ``thresholds.block``;
* an exception needs an ``expires`` date at most :data:`MAX_EXCEPTION_DAYS` days ahead and a
  ``reason``; it may never name a non-overridable code (``IOC_MATCH``, ``HASH_MISMATCH``). An
  exception stops applying at 00:00 UTC on its ``expires`` date.

Documents are **normalised**: list values are de-duplicated and sorted, names normalised, version
specifiers canonicalised and exceptions ordered, so :func:`canonical_json` (sorted keys, compact
separators) and :func:`policy_hash` (SHA-256 of the canonical JSON) identify the policy content
reproducibly regardless of key order, list order or YAML-vs-JSON source.

Parsing hostile text is bounded: :data:`MAX_POLICY_BYTES` of UTF-8, :data:`MAX_POLICY_DEPTH`
levels of nesting and :data:`MAX_POLICY_NODES` elements. YAML is read with a ``SafeLoader``
subclass that additionally rejects aliases (the "billion laughs" expansion), merge keys and
duplicate keys (a second ``deny:`` would silently replace the first); JSON rejects duplicate
keys and ``NaN``/``Infinity``. Errors are reported as ``{"loc", "msg"}`` pairs, plus the YAML
``line`` when it is known. Messages never contain control characters or high-confidence
secret patterns (they pass through :func:`app.core.redaction.sanitize_text`).

Stored documents are re-validated with ``lenient`` vocabulary checks (see
:func:`effective_policy`): a code or capability that a later Warden version renamed must not
turn a stored policy into an unreadable one, while structural damage still fails validation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated, Any, Literal

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from app.analysis import taxonomy
from app.analysis.findings import Category
from app.analysis.signals import Capability, Code
from app.core.redaction import sanitize_text
from app.sbom.models import normalize_name
from app.schemas.exception import (
    MAX_EXCEPTION_DAYS,
    MAX_JUSTIFICATION_CHARS,
    MIN_JUSTIFICATION_CHARS,
    NON_OVERRIDABLE_CODES,
)
from app.schemas.scan import PYPI_NAME_RE, validate_environment

API_VERSION = "warden.dev/v1"
KIND = "Policy"

MAX_POLICY_BYTES = 256 * 1024
MAX_POLICY_DEPTH = 16
MAX_POLICY_NODES = 50_000
MAX_PACKAGES = 1000
MAX_CODES = 300
MAX_CAPABILITIES = 100
MAX_EXCEPTIONS = 500
MAX_ERRORS = 50

DEFAULT_MIN_CONFIDENCE = 0.7
# Warnings are advisory, so their default gate is the floor of the heuristic confidence band.
DEFAULT_WARN_MIN_CONFIDENCE = 0.5

# Provenance states produced by the orchestrator's provenance summary.
PROVENANCE_STATES: tuple[str, ...] = ("attested", "unverified", "failed", "not_run")
VULNERABILITY_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

# Validation-context keys.
LENIENT = "lenient_vocabulary"
TODAY = "today"

_CODE_SHAPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_TOKEN_SHAPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_LOC_PART_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")


# =========================================================================== vocabulary
def known_codes() -> frozenset[str]:
    """Finding codes accepted in documents (the ``Code`` catalogue plus taxonomy registrations)."""
    catalogue = {v for k, v in vars(Code).items() if not k.startswith("_") and isinstance(v, str)}
    return frozenset(catalogue | set(taxonomy.all_codes()))


def known_categories() -> frozenset[str]:
    return frozenset(c.value for c in Category)


def known_capabilities() -> frozenset[str]:
    return frozenset(v for k, v in vars(Capability).items() if not k.startswith("_") and isinstance(v, str))


def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _lenient(info: ValidationInfo) -> bool:
    ctx = info.context
    return bool(isinstance(ctx, Mapping) and ctx.get(LENIENT))


def _today(info: ValidationInfo) -> date:
    ctx = info.context
    value = ctx.get(TODAY) if isinstance(ctx, Mapping) else None
    return value if isinstance(value, date) and not isinstance(value, datetime) else utc_today()


# =========================================================================== item validators
def _code_item(value: str, info: ValidationInfo) -> str:
    code = value.strip().upper()
    if not _CODE_SHAPE_RE.match(code):
        raise ValueError("finding codes look like NETWORK_EGRESS: upper-case letters, digits and underscores")
    if not _lenient(info) and code not in known_codes():
        raise ValueError(f"unknown finding code {code}")
    return code


def _exception_code_item(value: str, info: ValidationInfo) -> str:
    code = _code_item(value, info)
    if code in NON_OVERRIDABLE_CODES:
        raise ValueError(f"{code} findings are non-overridable and cannot be excepted")
    return code


def _category_item(value: str, info: ValidationInfo) -> str:
    category = value.strip().lower()
    if not _TOKEN_SHAPE_RE.match(category):
        raise ValueError("categories look like malicious_behavior: lower-case letters, digits and underscores")
    if not _lenient(info) and category not in known_categories():
        raise ValueError(f"unknown finding category {category}")
    return category


def _capability_item(value: str, info: ValidationInfo) -> str:
    capability = value.strip().lower()
    if not _TOKEN_SHAPE_RE.match(capability):
        raise ValueError("capabilities look like install_hook_exec: lower-case letters, digits and underscores")
    if not _lenient(info) and capability not in known_capabilities():
        raise ValueError(f"unknown capability {capability}")
    return capability


def _package_item(value: str, info: ValidationInfo) -> str:
    name = value.strip()
    if not PYPI_NAME_RE.match(name):
        if _lenient(info):
            return normalize_name(name)
        raise ValueError("invalid package name: PEP 508 project names use letters, digits, '.', '_' and '-'")
    return normalize_name(name)


CodeItem = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_code_item)]
ExceptionCodeItem = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_exception_code_item)]
CategoryItem = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_category_item)]
CapabilityItem = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_capability_item)]
PackageItem = Annotated[str, Field(min_length=1, max_length=214), AfterValidator(_package_item)]
Confidence = Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
Threshold = Annotated[int, Field(strict=True, ge=0, le=100)]


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


# =========================================================================== models
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Thresholds(_Strict):
    warn: Threshold = 40
    block: Threshold = 70

    @model_validator(mode="after")
    def _ordered(self, info: ValidationInfo) -> Thresholds:
        if self.warn > self.block and not _lenient(info):
            raise ValueError("thresholds.warn must be less than or equal to thresholds.block")
        return self


class VulnerabilityRule(_Strict):
    """A vulnerability matches when ANY configured criterion matches (logical OR)."""

    known_exploited: StrictBool = False
    min_severity: Literal["critical", "high", "medium", "low"] | None = None
    min_cvss: Annotated[float, Field(strict=True, ge=0.0, le=10.0)] | None = None
    min_epss: Confidence | None = None

    @field_validator("min_severity", mode="before")
    @classmethod
    def _severity_case(cls, v: object) -> object:
        return v.strip().lower() if isinstance(v, str) else v

    @property
    def configured(self) -> bool:
        return bool(self.known_exploited or self.min_severity or self.min_cvss is not None
                    or self.min_epss is not None)


class DenyRules(_Strict):
    packages: list[PackageItem] = Field(default_factory=list, max_length=MAX_PACKAGES)
    codes: list[CodeItem] = Field(default_factory=list, max_length=MAX_CODES)
    categories: list[CategoryItem] = Field(default_factory=list, max_length=len(Category))
    capabilities: list[CapabilityItem] = Field(default_factory=list, max_length=MAX_CAPABILITIES)
    vulnerabilities: VulnerabilityRule = Field(default_factory=VulnerabilityRule)
    # Code, category and capability rules only fire for findings at or above this confidence.
    min_confidence: Confidence = DEFAULT_MIN_CONFIDENCE

    @field_validator("packages", "codes", "categories", "capabilities")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        return _sorted_unique(v)


class WarnRules(_Strict):
    codes: list[CodeItem] = Field(default_factory=list, max_length=MAX_CODES)
    categories: list[CategoryItem] = Field(default_factory=list, max_length=len(Category))
    capabilities: list[CapabilityItem] = Field(default_factory=list, max_length=MAX_CAPABILITIES)
    vulnerabilities: VulnerabilityRule = Field(default_factory=VulnerabilityRule)
    min_confidence: Confidence = DEFAULT_WARN_MIN_CONFIDENCE

    @field_validator("codes", "categories", "capabilities")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        return _sorted_unique(v)


class Requirements(_Strict):
    # Accepted provenance states; ``None`` = no provenance requirement.
    provenance: list[Literal["attested", "unverified", "failed", "not_run"]] | None = Field(
        default=None, min_length=1, max_length=len(PROVENANCE_STATES))
    hash_verified: StrictBool = False
    sbom: StrictBool = False

    @field_validator("provenance")
    @classmethod
    def _states(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted(set(v))


class AllowRules(_Strict):
    packages: list[PackageItem] = Field(default_factory=list, max_length=MAX_PACKAGES)

    @field_validator("packages")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        return _sorted_unique(v)


class ExceptionEntry(_Strict):
    """A time-boxed waiver written into the document (reviewed through ``policy:write``)."""

    package: PackageItem
    version: str | None = Field(default=None, max_length=100, description='PEP 440 specifier set, e.g. "<2.0"')
    codes: list[ExceptionCodeItem] = Field(default_factory=list, max_length=50)
    categories: list[CategoryItem] = Field(default_factory=list, max_length=len(Category))
    expires: date
    reason: str = Field(min_length=1, max_length=MAX_JUSTIFICATION_CHARS)
    approved_by: str | None = Field(default=None, max_length=120)

    @field_validator("codes", "categories")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        return _sorted_unique(v)

    @field_validator("version")
    @classmethod
    def _version(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        try:
            spec = SpecifierSet(v.strip())
        except InvalidSpecifier as exc:
            raise ValueError("version must be a PEP 440 specifier set such as '<2.0' or '==1.4.2'") from exc
        normalised = str(spec)
        if not normalised or len(normalised) > 100:
            raise ValueError("version must be a non-empty specifier set of at most 100 characters")
        return normalised

    @field_validator("expires", mode="before")
    @classmethod
    def _expires_type(cls, v: object) -> object:
        if isinstance(v, (bool, int, float)):
            raise ValueError("expires must be a calendar date such as 2026-12-01")
        return v

    @field_validator("expires")
    @classmethod
    def _expires_window(cls, v: date, info: ValidationInfo) -> date:
        limit = _today(info) + timedelta(days=MAX_EXCEPTION_DAYS)
        if v > limit:
            raise ValueError(f"expires must be at most {MAX_EXCEPTION_DAYS} days ahead")
        return v

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < MIN_JUSTIFICATION_CHARS:
            raise ValueError(f"reason must be at least {MIN_JUSTIFICATION_CHARS} characters")
        return sanitize_text(v, max_len=MAX_JUSTIFICATION_CHARS, keep_newlines=True)

    @field_validator("approved_by")
    @classmethod
    def _approved_by(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return sanitize_text(v.strip(), max_len=120)

    @property
    def expires_at(self) -> datetime:
        """The instant the exception stops applying: 00:00 UTC on the ``expires`` date."""
        return datetime.combine(self.expires, time.min, tzinfo=timezone.utc)

    @property
    def whole_package(self) -> bool:
        return not self.codes and not self.categories


class PolicyMetadata(_Strict):
    name: str = Field(min_length=1, max_length=120)
    environment: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str, info: ValidationInfo) -> str:
        v = v.strip()
        if not v:
            raise ValueError("metadata.name must not be blank")
        clean = sanitize_text(v, max_len=0, redact=False)
        if clean != v:
            if _lenient(info):
                return clean[:120]
            raise ValueError("metadata.name must not contain control or bidirectional-override characters")
        return v

    @field_validator("environment")
    @classmethod
    def _environment(cls, v: str | None, info: ValidationInfo) -> str | None:
        try:
            return validate_environment(v)
        except ValueError:
            if _lenient(info):
                return None
            raise


class PolicySpec(_Strict):
    thresholds: Thresholds = Field(default_factory=Thresholds)
    min_package_age_days: Annotated[int, Field(strict=True, ge=0, le=3650)] = 0
    deny: DenyRules = Field(default_factory=DenyRules)
    warn: WarnRules = Field(default_factory=WarnRules)
    require: Requirements = Field(default_factory=Requirements)
    allow: AllowRules = Field(default_factory=AllowRules)
    exceptions: list[ExceptionEntry] = Field(default_factory=list, max_length=MAX_EXCEPTIONS)

    @field_validator("exceptions")
    @classmethod
    def _order_exceptions(cls, v: list[ExceptionEntry]) -> list[ExceptionEntry]:
        unique: dict[str, ExceptionEntry] = {}
        for entry in v:
            unique.setdefault(canonical_json(entry.model_dump(mode="json")), entry)
        return [unique[key] for key in sorted(unique)]

    @model_validator(mode="after")
    def _consistent(self, info: ValidationInfo) -> PolicySpec:
        if not _lenient(info):
            overlap = sorted(set(self.deny.packages) & set(self.allow.packages))
            if overlap:
                raise ValueError(f"packages cannot be both denied and allowed: {', '.join(overlap[:5])}")
        return self


class PolicyDocument(_Strict):
    api_version: Literal["warden.dev/v1"] = Field(alias="apiVersion")
    kind: Literal["Policy"]
    metadata: PolicyMetadata
    spec: PolicySpec

    def to_dict(self) -> dict[str, Any]:
        """Normalised JSON-compatible form (the stored and hashed representation)."""
        return self.model_dump(mode="json", by_alias=True)

    def canonical_json(self) -> str:
        return canonical_json(self)

    @property
    def policy_hash(self) -> str:
        return policy_hash(self)

    def with_environment(self, environment: str | None) -> PolicyDocument:
        """A copy whose ``metadata.environment`` is ``environment`` (validated)."""
        env = validate_environment(environment)
        if env == self.metadata.environment:
            return self
        return self.model_copy(update={"metadata": self.metadata.model_copy(update={"environment": env})})


# =========================================================================== canonical form
def canonical_json(value: PolicyDocument | Mapping[str, Any] | Any) -> str:
    """Sorted-key, compact JSON; the basis of :func:`policy_hash`."""
    data = value.to_dict() if isinstance(value, PolicyDocument) else value
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def policy_hash(value: PolicyDocument | Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the canonical JSON of a normalised document."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# =========================================================================== errors / outcome
class PolicyDocumentError(ValueError):
    """A policy document could not be parsed or validated; ``errors`` holds ``{loc, msg[, line]}``."""

    def __init__(self, errors: list[dict[str, Any]]):
        self.errors = errors or [{"loc": "document", "msg": "invalid policy document"}]
        super().__init__(f"{self.errors[0]['loc']}: {self.errors[0]['msg']}")


@dataclass(frozen=True)
class ValidationOutcome:
    valid: bool
    errors: list[dict[str, Any]] = field(default_factory=list)
    document: PolicyDocument | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def normalized(self) -> dict[str, Any] | None:
        return self.document.to_dict() if self.document is not None else None

    @property
    def policy_hash(self) -> str | None:
        return self.document.policy_hash if self.document is not None else None


def _error(loc: str, msg: str, line: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"loc": loc, "msg": sanitize_text(msg, max_len=200)}
    if line is not None:
        out["line"] = line
    return out


def _format_loc(loc: tuple[Any, ...]) -> str:
    parts: list[str] = []
    for part in loc[:12]:
        if isinstance(part, int) and not isinstance(part, bool):
            parts.append(str(part))
        elif isinstance(part, str) and _LOC_PART_RE.match(part):
            parts.append(part)
        else:
            parts.append("<key>")
    return ".".join(parts) or "document"


def _error_message(err: Mapping[str, Any]) -> str:
    etype = str(err.get("type") or "")
    msg = str(err.get("msg") or "invalid value")
    if etype == "value_error":
        msg = msg.removeprefix("Value error, ")
    elif etype == "extra_forbidden":
        msg = f"unknown field (not part of the {API_VERSION} {KIND} schema)"
    elif etype.endswith("_parsing") or etype.startswith(("date_", "datetime_", "decimal_")):
        msg = msg.split(",", 1)[0]
    return msg


def _line_for(loc: tuple[Any, ...], positions: Mapping[tuple, int] | None) -> int | None:
    if not positions:
        return None
    for end in range(len(loc), -1, -1):
        line = positions.get(tuple(loc[:end]))
        if line is not None:
            return line
    return None


def _convert_errors(exc: ValidationError, positions: Mapping[tuple, int] | None) -> list[dict[str, Any]]:
    out = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False)[:MAX_ERRORS]:
        loc = tuple(err.get("loc") or ())
        out.append(_error(_format_loc(loc), _error_message(err), _line_for(loc, positions)))
    return out


def _check_shape(data: Any) -> dict[str, Any] | None:
    """Iteratively bound depth and element count before any recursive processing."""
    stack: list[tuple[Any, int]] = [(data, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_POLICY_NODES:
            return _error("document", f"document has more than {MAX_POLICY_NODES} elements")
        if depth > MAX_POLICY_DEPTH:
            return _error("document", f"document is nested deeper than {MAX_POLICY_DEPTH} levels")
        if isinstance(value, Mapping):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, (list, tuple)):
            stack.extend((v, depth + 1) for v in value)
    return None


def _warnings(doc: PolicyDocument, today: date) -> list[str]:
    out: list[str] = []
    for index, entry in enumerate(doc.spec.exceptions):
        if entry.expires <= today:
            out.append(f"spec.exceptions.{index} (normalised order) for {entry.package} expired on "
                       f"{entry.expires.isoformat()} and is ignored")
    if doc.spec.deny.min_confidence < 0.5:
        out.append("spec.deny.min_confidence is below 0.5: weak or contextual evidence can block packages")
    if doc.spec.deny.vulnerabilities.configured:
        out.append("spec.deny.vulnerabilities needs vulnerability intelligence: a scan without it (offline or "
                   "intelligence unavailable) is warned with 'vulnerability status unknown', never silently allowed")
    if doc.spec.require.sbom:
        out.append("spec.require.sbom is only satisfied by evaluations that carry project SBOM context; "
                   "package scans without it are warned")
    return out


def validate_policy_data(
    data: Any,
    *,
    lenient: bool = False,
    today: date | None = None,
    positions: Mapping[tuple, int] | None = None,
) -> ValidationOutcome:
    """Validate an already-parsed document (a mapping). Never raises for invalid input."""
    if not isinstance(data, Mapping):
        return ValidationOutcome(False, [_error("document", "a policy document must be a mapping (object)")])
    shape = _check_shape(data)
    if shape is not None:
        return ValidationOutcome(False, [shape])
    try:
        size = len(canonical_json(data).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return ValidationOutcome(False, [_error("document", "document is not JSON-serialisable")])
    if size > MAX_POLICY_BYTES:
        return ValidationOutcome(False, [_error("document", f"document exceeds {MAX_POLICY_BYTES} bytes")])
    effective_today = today or utc_today()
    try:
        doc = PolicyDocument.model_validate(dict(data), context={LENIENT: lenient, TODAY: effective_today})
    except ValidationError as exc:
        return ValidationOutcome(False, _convert_errors(exc, positions))
    return ValidationOutcome(True, [], doc, _warnings(doc, effective_today))


# =========================================================================== text parsing
class _PolicyYamlLoader(yaml.SafeLoader):
    """``SafeLoader`` without aliases, merge keys or duplicate keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not allowed in policy documents", event.start_mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, yaml.MappingNode):
            seen: set[Any] = set()
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise yaml.constructor.ConstructorError(
                        None, None, "YAML merge keys ('<<') are not allowed in policy documents", key_node.start_mark)
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in seen
                except TypeError:  # unhashable key: the base constructor reports it
                    continue
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        None, None, "duplicate key in mapping", key_node.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _yaml_positions(root: Any) -> dict[tuple, int]:
    positions: dict[tuple, int] = {(): root.start_mark.line + 1}
    stack: list[tuple[tuple, Any]] = [((), root)]
    nodes = 0
    while stack:
        path, node = stack.pop()
        nodes += 1
        if nodes > MAX_POLICY_NODES:
            raise PolicyDocumentError([_error("document", f"document has more than {MAX_POLICY_NODES} elements")])
        if len(path) > MAX_POLICY_DEPTH:
            raise PolicyDocumentError([_error("document", f"document is nested deeper than {MAX_POLICY_DEPTH} levels")])
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode):
                    child = (*path, key_node.value)
                    positions.setdefault(child, key_node.start_mark.line + 1)
                    stack.append((child, value_node))
        elif isinstance(node, yaml.SequenceNode):
            for i, value_node in enumerate(node.value):
                child = (*path, i)
                positions.setdefault(child, value_node.start_mark.line + 1)
                stack.append((child, value_node))
    return positions


def _mark_error(exc: yaml.YAMLError) -> dict[str, Any]:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or "invalid YAML"
    if mark is not None:
        return _error(f"line {mark.line + 1}, column {mark.column + 1}", str(problem), mark.line + 1)
    return _error("document", str(problem))


def _parse_yaml(text: str) -> tuple[Any, dict[tuple, int]]:
    loader = _PolicyYamlLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            return None, {}
        positions = _yaml_positions(node)
        return loader.construct_document(node), positions
    except yaml.YAMLError as exc:
        raise PolicyDocumentError([_mark_error(exc)]) from None
    finally:
        loader.dispose()


class _DuplicateKey(ValueError):
    pass


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey(key)
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a valid number in a policy document")


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise PolicyDocumentError([_error(f"line {exc.lineno}, column {exc.colno}", exc.msg, exc.lineno)]) from None
    except _DuplicateKey:
        raise PolicyDocumentError([_error("document", "duplicate key in object")]) from None
    except ValueError as exc:
        raise PolicyDocumentError([_error("document", str(exc))]) from None


def parse_policy_text(text: str | bytes, fmt: str | None = None) -> tuple[Any, dict[tuple, int]]:
    """Parse YAML or JSON policy text into plain data plus a ``path -> line`` index (YAML only).

    ``fmt`` is ``"yaml"``/``"yml"``, ``"json"`` or ``None``/``"auto"`` (JSON when the text starts
    with ``{``). Raises :class:`PolicyDocumentError`.
    """
    if isinstance(text, (bytes, bytearray)):
        if len(text) > MAX_POLICY_BYTES:
            raise PolicyDocumentError([_error("document", f"document exceeds {MAX_POLICY_BYTES} bytes")])
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            raise PolicyDocumentError([_error("document", "document is not valid UTF-8")]) from None
    if not isinstance(text, str):
        raise PolicyDocumentError([_error("document", "document text must be a string")])
    if len(text) > MAX_POLICY_BYTES or len(text.encode("utf-8", "surrogatepass")) > MAX_POLICY_BYTES:
        raise PolicyDocumentError([_error("document", f"document exceeds {MAX_POLICY_BYTES} bytes")])
    mode = (fmt or "auto").strip().lower()
    if mode == "auto":
        mode = "json" if text.lstrip().startswith("{") else "yaml"
    if mode not in {"yaml", "yml", "json"}:
        raise ValueError("fmt must be 'yaml', 'json' or 'auto'")
    try:
        if mode == "json":
            data, positions = _parse_json(text), {}
        else:
            data, positions = _parse_yaml(text)
    except RecursionError:
        raise PolicyDocumentError([_error("document", "document is nested too deeply")]) from None
    shape = _check_shape(data)
    if shape is not None:
        raise PolicyDocumentError([shape])
    return data, positions


def validate_policy_text(text: str | bytes, fmt: str | None = None, *, today: date | None = None,
                         lenient: bool = False) -> ValidationOutcome:
    """Parse and validate policy text; never raises for invalid input."""
    try:
        data, positions = parse_policy_text(text, fmt)
    except PolicyDocumentError as exc:
        return ValidationOutcome(False, list(exc.errors))
    return validate_policy_data(data, lenient=lenient, today=today, positions=positions)


def load_policy_text(text: str | bytes, fmt: str | None = None, *, today: date | None = None,
                     lenient: bool = False) -> PolicyDocument:
    """Parse and validate policy text; raises :class:`PolicyDocumentError` with located errors."""
    outcome = validate_policy_text(text, fmt, today=today, lenient=lenient)
    if outcome.document is None:
        raise PolicyDocumentError(outcome.errors)
    return outcome.document


# =========================================================================== legacy policies
_LEGACY_DEFAULTS = {"warn_threshold": 40, "block_threshold": 70, "min_package_age_days": 0}


def _read(policy: Any, key: str) -> Any:
    if isinstance(policy, Mapping):
        return policy.get(key)
    return getattr(policy, key, None)


def _legacy_int(policy: Any, key: str) -> int:
    value = _read(policy, key)
    return value if isinstance(value, int) and not isinstance(value, bool) else _LEGACY_DEFAULTS[key]


def _legacy_strings(policy: Any, key: str, *, max_len: int) -> list[str]:
    raw = _read(policy, key)
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return []
    out = []
    for item in raw:
        if isinstance(item, str) and item.strip() and len(item.strip()) <= max_len:
            out.append(item.strip())
    return out


def from_legacy(policy: Any, *, name: str | None = None) -> PolicyDocument:
    """Convert a v1 policy (a ``Policy`` row or a mapping of its columns) into a document.

    ``warn_threshold``/``block_threshold``/``min_package_age_days`` become ``spec.thresholds`` and
    ``spec.min_package_age_days`` (v1 column defaults when unset), ``denylist`` → ``deny.packages``,
    ``blocked_capabilities`` → ``deny.capabilities`` (lower-cased; entries that are not capability-shaped
    are dropped because no finding can carry them), ``allowlist`` → ``allow.packages``. Vocabulary checks
    are lenient and ``deny.min_confidence`` is the default 0.7.
    """
    capabilities = [c.lower() for c in _legacy_strings(policy, "blocked_capabilities", max_len=64)
                    if _TOKEN_SHAPE_RE.match(c.lower())]
    env_raw = _read(policy, "environment")
    try:
        environment = validate_environment(env_raw) if isinstance(env_raw, str) else None
    except ValueError:
        environment = None
    raw_name = name or _read(policy, "name")
    doc_name = raw_name.strip()[:120] if isinstance(raw_name, str) and raw_name.strip() else "legacy-policy"
    data = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"name": doc_name, "environment": environment},
        "spec": {
            "thresholds": {"warn": _legacy_int(policy, "warn_threshold"),
                           "block": _legacy_int(policy, "block_threshold")},
            "min_package_age_days": _legacy_int(policy, "min_package_age_days"),
            "deny": {"packages": _legacy_strings(policy, "denylist", max_len=214), "capabilities": capabilities},
            "allow": {"packages": _legacy_strings(policy, "allowlist", max_len=214)},
        },
    }
    return PolicyDocument.model_validate(data, context={LENIENT: True, TODAY: utc_today()})


# =========================================================================== effective policy
@dataclass(frozen=True)
class EffectivePolicy:
    """The document a policy evaluates as, its hash, and whether it came from a document or legacy columns.

    ``document`` is ``None`` when a stored document failed validation; ``policy_hash`` is then the
    SHA-256 of the canonical JSON of the raw stored value so the failure is still reproducible.
    """

    document: PolicyDocument | None
    policy_hash: str
    source: Literal["document", "legacy"]
    errors: tuple[dict[str, Any], ...] = ()

    @property
    def valid(self) -> bool:
        return self.document is not None


def _raw_hash(raw: Any) -> str:
    try:
        return policy_hash(raw)
    except (TypeError, ValueError, RecursionError):
        return hashlib.sha256(b"<unserialisable policy document>").hexdigest()


def effective_policy(policy: Any) -> EffectivePolicy:
    """Resolve a ``PolicyDocument``, a document mapping, a policy row/mapping with a ``document``, or a
    legacy policy row/mapping into an :class:`EffectivePolicy` (stored documents validated leniently)."""
    if isinstance(policy, PolicyDocument):
        return EffectivePolicy(policy, policy.policy_hash, "document")
    if isinstance(policy, Mapping) and "apiVersion" in policy:
        raw: Any = policy
    else:
        raw = _read(policy, "document")
    if raw is not None:
        shape = _check_shape(raw) if isinstance(raw, (Mapping, list, tuple)) else None
        if shape is not None:
            return EffectivePolicy(None, hashlib.sha256(b"<oversized policy document>").hexdigest(), "document",
                                   (shape,))
        outcome = validate_policy_data(raw, lenient=True)
        if outcome.document is not None:
            return EffectivePolicy(outcome.document, outcome.document.policy_hash, "document")
        return EffectivePolicy(None, _raw_hash(raw), "document", tuple(outcome.errors))
    try:
        doc = from_legacy(policy)
    except ValidationError as exc:
        errors = tuple(_convert_errors(exc, None))
        snapshot = {key: _read(policy, key) for key in (
            "name", "environment", "warn_threshold", "block_threshold", "min_package_age_days",
            "blocked_capabilities", "allowlist", "denylist")}
        return EffectivePolicy(None, _raw_hash(snapshot), "legacy", errors)
    return EffectivePolicy(doc, doc.policy_hash, "legacy")


def policy_hash_for(policy: Any) -> str | None:
    """Hash of the policy content a row/mapping evaluates as (``None`` only if it cannot be computed)."""
    try:
        return effective_policy(policy).policy_hash
    except Exception:  # an output-model helper must never break a listing
        return None


__all__ = [
    "API_VERSION",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_WARN_MIN_CONFIDENCE",
    "KIND",
    "MAX_POLICY_BYTES",
    "PROVENANCE_STATES",
    "AllowRules",
    "DenyRules",
    "EffectivePolicy",
    "ExceptionEntry",
    "PolicyDocument",
    "PolicyDocumentError",
    "PolicyMetadata",
    "PolicySpec",
    "Requirements",
    "Thresholds",
    "ValidationOutcome",
    "VulnerabilityRule",
    "WarnRules",
    "canonical_json",
    "effective_policy",
    "from_legacy",
    "known_capabilities",
    "known_categories",
    "known_codes",
    "load_policy_text",
    "parse_policy_text",
    "policy_hash",
    "policy_hash_for",
    "utc_today",
    "validate_policy_data",
    "validate_policy_text",
]
