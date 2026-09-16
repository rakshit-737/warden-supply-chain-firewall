"""Attack-chain correlation engine.

``correlate(findings)`` combines individual findings into ordered attack chains described by
the declarative templates in :mod:`app.analysis.correlation.chains`, and emits one derived
``ATTACK_CHAIN`` finding per chain. It is designed to surface *coherent combinations* of
findings that analyzers already produced (for example install-time execution + credential
access + network egress); it performs no detection of its own and cannot see behaviour that
no analyzer reported. Nothing here executes, imports or decodes package content.

Input normalisation
===================

* Non-``Finding`` items are accepted when they are mappings (``Finding.from_dict``); anything
  else, or any finding whose fields cannot be read, is skipped — malformed input never raises.
* ``ATTACK_CHAIN`` findings are ignored (no chains of chains). Duplicate ``finding_id`` s are
  collapsed, and input is ordered by importance and id before the ``MAX_INPUT_FINDINGS`` bound
  is applied, so results do not depend on input order.
* **Files** of a finding: ``location.file``, ``evidence["file"]`` and the ``file`` of up to
  ``MAX_LOCATIONS_PER_FINDING`` entries of ``evidence["locations"]``.
* **Context** is read from ``evidence["context"]`` / ``evidence["contexts"]`` (finding level) and
  from ``context`` inside location entries (file level), compared after lower-casing and reading
  ``-`` and spaces as ``_``. Labels in :data:`INSTALL_CONTEXTS` (``install_time``,
  ``install-time``, ``interpreter_startup``, ``build`` ...) or starting with ``install_`` mean
  install-time; labels in :data:`NON_EXECUTING_CONTEXTS` (``test``, ``test-file``,
  ``documentation`` ...) or starting with ``test_`` mean the code is not run as part of the
  package. Other labels (``import_time``, ``runtime``, ``build_config``, ``data``, ``unknown``)
  carry no install-time meaning.
* **Test-only findings are excluded**: a finding with a non-executing context, or whose every
  known file is a test file (a ``test``/``tests``/``__tests__`` directory, ``test_*.py``,
  ``*_test.py``, ``tests.py`` or ``conftest.py``), never contributes to a chain. Test paths are
  dropped from the files of findings that also have non-test files.
* **Install-time files** are the files of install-vector findings (``INSTALL_HOOK_EXEC``,
  ``PTH_STARTUP_HOOK``, ``BUILD_BACKEND_HOOK``), files carrying location-level install context,
  and a ``setup.py`` at the distribution root (top level, or directly under an sdist's
  ``<name>-<version>/`` directory). A finding is install-time when it has finding-level install
  context or one of its files is install-time. Findings matched by an ``identity`` step (package
  name, registry history) never supply install-time evidence, whatever their label: the
  dependency-confusion analyzer labels its findings ``install-time`` because the risk materialises
  when an installer resolves the name, not because package code runs there.

Matching
========

A template matches when every required step is satisfied by at least one (non-test) finding
whose code is in the step's ``codes_any`` (steps with ``context="install"`` accept only
install-time findings with a non-install-vector code). Only the best-scoring variant per
``chain_id`` is reported.

Evidence grades (per finding): **capability-grade** = confidence < 0.7 or category
``capability``; **strong** = confidence ≥ 0.85 and category not ``capability``. A required step
is capability-grade when all of its matched findings are.

**Co-location**: the *located behaviour steps* are the required steps of kind ``behavior``
whose findings have files. When there are at least two, the co-located file is a file shared by
all of them (install-time files preferred, then lexical order).

Emission guards (false-positive control)
========================================

1. A template with a single required step needs a strong finding in that step.
2. When no required step is capability-grade, the chain is emitted.
3. When some required step is capability-grade, the chain is emitted only if either

   a. there is a co-located file covering every capability-grade step, and in that file there
      is install-time context (the file is install-time, or a required non-identity finding
      located in it has install context), an evasion finding that is not itself a required
      finding, or a strong required finding; or
   b. the variant does not require co-location, some required step is not capability-grade,
      and every capability-grade step is a ``behavior`` step with an install-time finding whose
      code is not an install vector (an install vector never corroborates itself). A
      capability-grade identity or artifact step can therefore never be corroborated by (b).

   With every required step capability-grade, only (a) can apply — co-location *and* install or
   evasion context, the guard from the specification. (a) and (b) extend it to mixed chains so
   that, for example, a legitimate SSH/upload tool that references ``~/.ssh/id_*`` or
   ``.pypirc`` (confidence 0.7) and uses the network (capability) yields no chain, and an SDK that
   reads ``AWS_*`` variables in ``credentials.py`` and makes HTTPS calls in ``endpoint.py`` yields
   no chain however confident the credential finding is.
4. Variants with ``require_colocation`` are emitted only with a co-located file.

Confidence
==========

::

    base       = mean over required steps of (max confidence of the step's findings)
    confidence = base
               + 0.08 per satisfied booster group (matched by a finding that is not a required finding)
               + 0.07 if a co-located file exists
               + 0.05 if install-time evidence is part of the chain (a required, optional or booster
                 finding outside identity steps has an install-vector code or is install-time)
    confidence = min(0.97, confidence), rounded to 4 decimals

Chains below 0.5 are not emitted. Severity is the template's, lowered one band when confidence
is below 0.6. The derived finding's weight follows severity: critical 12, high 8, medium 4,
low 2. Chains are ordered by severity, confidence and ``chain_id`` and bounded by
``MAX_CHAINS``.

Derived finding
===============

``ATTACK_CHAIN`` with the chain's severity, weight and confidence; ``related`` = the chain's
``finding_ids``; ``attack`` = the step technique ids; ``location`` = the co-located file (file
only — no line is invented); evidence ``{chain_id, title, step_codes}``; provenance
``correlation``. The analyzer fields are stamped here (``correlation`` / :data:`VERSION`) so the
``finding_id`` quoted in the chain dict is the id the orchestrator keeps. The id depends on the
chain id, title, per-step codes and co-located file — not on confidences — so re-scans with
re-tuned analyzer confidences keep chain ids stable.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.analysis import taxonomy
from app.analysis.correlation import chains as chain_defs
from app.analysis.correlation.chains import (
    BEHAVIOR,
    EVASION_CODES,
    IDENTITY,
    INSTALL_CONTEXT,
    INSTALL_VECTOR_CODES,
    ChainTemplate,
    StepSpec,
)
from app.analysis.findings import Category, Finding, Location, Provenance, Severity, sort_key
from app.analysis.signals import Code
from app.core.redaction import sanitize_text

# An sdist's top-level directory: "<name>-<version>", e.g. "demo-1.0" or "demo-helper-0.0.1".
_SDIST_TOP_DIR_RE = re.compile(r"-v?\d")

VERSION = "2.0.0"
ANALYZER_NAME = "correlation"

MAX_INPUT_FINDINGS = 5000
MAX_CHAINS = 20
MAX_LOCATIONS_PER_FINDING = 50
MAX_FILES_PER_FINDING = 64
MAX_STEP_FINDINGS = 8
MAX_CHAIN_FINDINGS = 24  # below sanitize_evidence's list bound, so ids are never elided
MAX_SUMMARY_CHARS = 300
_MAX_CONTEXT_VALUES = 16
_MAX_HINT_STRINGS = 64
_FILE_KEY_CHARS = 299  # evidence strings are cut at 300 chars ("…" last), locations at 512

CAPABILITY_GRADE_BELOW = 0.7
STRONG_CONFIDENCE = 0.85
EMIT_MIN_CONFIDENCE = 0.5
DOWNGRADE_BELOW = 0.6
BOOSTER_BONUS = 0.08
COLOCATION_BONUS = 0.07
INSTALL_TIME_BONUS = 0.05
CONFIDENCE_CAP = 0.97

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.critical: 12.0, Severity.high: 8.0, Severity.medium: 4.0, Severity.low: 2.0, Severity.info: 0.0,
}
_DOWNGRADE = {
    Severity.critical: Severity.high, Severity.high: Severity.medium, Severity.medium: Severity.low,
    Severity.low: Severity.info, Severity.info: Severity.info,
}

# Context labels as analyzers write them (``install_time``, ``install-time``, ``interpreter_startup``,
# ``import_time``, ``runtime``, ``test``, ``test-file``, ``documentation``, ``build_config`` ...),
# compared after lower-casing and reading ``-`` / spaces as ``_``.
INSTALL_CONTEXTS = frozenset({
    "install", "install_time", "installation", "setup", "setup_time", "build", "build_time", "build_backend",
    "preinstall", "pre_install", "postinstall", "post_install", "interpreter_startup", "startup_hook",
})
# Code that is not run as part of the package: test suites and documentation. ``build_config``
# (values in setup.cfg / pyproject.toml) is deliberately in neither set.
NON_EXECUTING_CONTEXTS = frozenset({"test", "tests", "test_file", "test_files", "testing", "documentation", "docs"})
_INSTALL, _TEST = "install", "test"  # _TEST marks every non-executing context
_TEST_DIRS = frozenset({"test", "tests", "__tests__"})


# --------------------------------------------------------------------------- output model
@dataclass(frozen=True)
class ChainStep:
    order: int
    tactic: str | None
    technique_id: str | None
    technique_name: str | None
    description: str
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "description": self.description,
            "finding_ids": list(self.finding_ids),
        }


@dataclass(frozen=True)
class AttackChain:
    chain_id: str
    variant: str
    title: str
    summary: str
    severity: Severity
    confidence: float
    finding_id: str
    finding_ids: tuple[str, ...]
    attack: tuple[str, ...]
    steps: tuple[ChainStep, ...]
    colocated_file: str | None
    install_time: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            # ``id`` is what the dashboard keys chains by; one chain per chain_id makes it unique.
            "id": self.chain_id,
            "chain_id": self.chain_id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "finding_id": self.finding_id,
            "finding_ids": list(self.finding_ids),
            "attack": list(self.attack),
            "steps": [s.to_dict() for s in self.steps],
            "colocated_file": self.colocated_file,
            "context": {"install_time": self.install_time, "variant": self.variant},
        }


@dataclass
class CorrelationResult:
    # Chains in report order; ``findings[i]`` is the ATTACK_CHAIN finding of ``chains[i]``.
    chains: list[AttackChain] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# --------------------------------------------------------------------------- normalisation
@dataclass(frozen=True, eq=False)
class _Obs:
    """A normalised, test-free view of one input finding."""

    finding: Finding
    fid: str
    code: str
    confidence: float
    category: str
    files: frozenset[str]
    install_context: bool  # finding-level install context
    install_files: frozenset[str]  # files with location-level install context
    rank: tuple

    @property
    def capability_grade(self) -> bool:
        return self.confidence < CAPABILITY_GRADE_BELOW or self.category == Category.CAPABILITY.value

    @property
    def strong(self) -> bool:
        return self.confidence >= STRONG_CONFIDENCE and self.category != Category.CAPABILITY.value


def _context_tokens(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        values: Iterable[Any] = (value,)
    elif isinstance(value, (list, tuple)):
        values = value[:_MAX_CONTEXT_VALUES]
    else:
        return frozenset()
    out: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        token = item.strip().lower().replace("-", "_").replace(" ", "_")[:40]
        if token in INSTALL_CONTEXTS or token.startswith("install_"):
            out.add(_INSTALL)
        elif token in NON_EXECUTING_CONTEXTS or token.startswith("test_"):
            out.add(_TEST)
    return frozenset(out)


def _file_key(path: str) -> str | None:
    """Comparable file key; long paths are cut the way evidence strings are, so they still match."""
    text = path.strip()
    if not text:
        return None
    return text if len(text) <= _FILE_KEY_CHARS else text[:_FILE_KEY_CHARS] + "…"


def _parts(path: str) -> list[str]:
    return [p for p in path.replace("\\", "/").split("/") if p]


def is_test_path(path: str) -> bool:
    """True for files conventionally holding tests (not importable runtime ``testing`` helpers)."""
    parts = _parts(path)
    if not parts:
        return False
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]):
        return True
    name = parts[-1].lower()
    return (name in {"conftest.py", "tests.py"} or (name.startswith("test_") and name.endswith(".py"))
            or name.endswith("_test.py"))


def is_root_setup_script(path: str) -> bool:
    """``setup.py`` at the distribution root.

    Sdists wrap their contents in one ``<name>-<version>/`` directory, so ``demo-1.0/setup.py``
    qualifies while a module such as ``mypkg/setup.py`` (e.g. inside a wheel) does not.
    """
    parts = _parts(path)
    if not parts or parts[-1].lower() != "setup.py":
        return False
    return len(parts) == 1 or (len(parts) == 2 and _SDIST_TOP_DIR_RE.search(parts[0]) is not None)


def _coerce(item: Any) -> Finding | None:
    if isinstance(item, Finding):
        return item
    if isinstance(item, Mapping):
        try:
            return Finding.from_dict(dict(item))
        except Exception:  # malformed legacy dicts are skipped, never fatal
            return None
    return None


def _observe(finding: Finding) -> _Obs | None:
    """Normalise one finding; ``None`` for test-only, chain or unreadable findings."""
    try:
        code = finding.code
        if not isinstance(code, str) or not code or code == Code.ATTACK_CHAIN:
            return None
        confidence = float(finding.confidence)
        if not math.isfinite(confidence):
            return None
        category = finding.category.value if isinstance(finding.category, Category) else finding.category
        if not isinstance(category, str) or not category:
            info = taxonomy.get(code)
            category = info.category if info else Category.OTHER.value
        evidence = finding.evidence if isinstance(finding.evidence, Mapping) else {}
        finding_context = _context_tokens(evidence.get("context")) | _context_tokens(evidence.get("contexts"))
        if _TEST in finding_context:
            return None

        raw: list[tuple[str, frozenset[str]]] = []
        location = finding.location
        if isinstance(location, Location) and isinstance(location.file, str):
            raw.append((location.file, frozenset()))
        if isinstance(evidence.get("file"), str):
            raw.append((evidence["file"], frozenset()))
        locations = evidence.get("locations")
        if isinstance(locations, (list, tuple)):
            for entry in locations[:MAX_LOCATIONS_PER_FINDING]:
                if isinstance(entry, Mapping) and isinstance(entry.get("file"), str):
                    raw.append((entry["file"], _context_tokens(entry.get("context"))))

        files: set[str] = set()
        install_files: set[str] = set()
        saw_test = False
        for path, tokens in raw:
            key = _file_key(path)
            if key is None:
                continue
            if _TEST in tokens or is_test_path(key):
                saw_test = True
                continue
            if len(files) < MAX_FILES_PER_FINDING or key in files:
                files.add(key)
                if _INSTALL in tokens:
                    install_files.add(key)
        if saw_test and not files:
            return None
        fid = finding.finding_id
        rank = (*sort_key(finding), fid)
    except Exception:  # a finding whose fields cannot be read is skipped, never fatal
        return None
    return _Obs(finding=finding, fid=fid, code=code, confidence=confidence, category=category,
                files=frozenset(files), install_context=_INSTALL in finding_context,
                install_files=frozenset(install_files), rank=rank)


def _normalise(findings: Iterable[Any]) -> list[_Obs]:
    observed: dict[str, _Obs] = {}
    for item in findings if findings is not None else ():
        finding = _coerce(item)
        obs = _observe(finding) if finding is not None else None
        if obs is not None and obs.fid not in observed:
            observed[obs.fid] = obs
    return sorted(observed.values(), key=lambda o: o.rank)[:MAX_INPUT_FINDINGS]


# --------------------------------------------------------------------------- evaluation
@dataclass(frozen=True, eq=False)
class _Candidate:
    template: ChainTemplate
    index: int
    confidence: float
    severity: Severity
    matched: dict[int, list[_Obs]]
    booster_obs: list[_Obs]
    colocated_file: str | None
    install_time: bool
    evasion: bool


class _Context:
    """Per-call indexes shared by all template evaluations."""

    def __init__(self, observations: list[_Obs]) -> None:
        self.observations = observations
        self.by_code: dict[str, list[_Obs]] = {}
        for o in observations:
            self.by_code.setdefault(o.code, []).append(o)
        install_files: set[str] = set()
        for o in observations:
            install_files |= o.install_files
            if o.code in INSTALL_VECTOR_CODES:
                install_files |= o.files
            install_files |= {f for f in o.files if is_root_setup_script(f)}
        self.install_files = frozenset(install_files)

    def install_time(self, o: _Obs) -> bool:
        return o.install_context or bool(o.files & self.install_files)

    def candidates(self, codes: Iterable[str]) -> list[_Obs]:
        seen: dict[str, _Obs] = {}
        for code in sorted(codes):
            for o in self.by_code.get(code, ()):
                seen.setdefault(o.fid, o)
        return sorted(seen.values(), key=lambda o: (-o.confidence, o.rank))


def _match_step(step: StepSpec, ctx: _Context) -> list[_Obs]:
    hits = ctx.candidates(step.codes_any)
    if step.context == INSTALL_CONTEXT:
        hits = [o for o in hits if o.code not in INSTALL_VECTOR_CODES and ctx.install_time(o)]
    return hits


def _colocated_file(template: ChainTemplate, matched: dict[int, list[_Obs]],
                    ctx: _Context) -> tuple[str | None, set[int]]:
    located = {
        i for i, step in enumerate(template.steps)
        if step.required and step.kind == BEHAVIOR and any(o.files for o in matched[i])
    }
    if len(located) < 2:
        return None, located
    common: frozenset[str] | None = None
    for i in sorted(located):
        step_files = frozenset().union(*(o.files for o in matched[i]))
        common = step_files if common is None else common & step_files
    if not common:
        return None, located
    return min(common, key=lambda p: (p not in ctx.install_files, p)), located


def _evaluate(template: ChainTemplate, index: int, ctx: _Context) -> _Candidate | None:
    matched = {i: _match_step(step, ctx) for i, step in enumerate(template.steps)}
    required = [i for i, step in enumerate(template.steps) if step.required]
    if any(not matched[i] for i in required):
        return None

    required_obs = {o.fid: o for i in required for o in matched[i]}
    # Identity findings describe the package name or registry history; an "install-time" label on
    # them (e.g. dependency confusion) says when the risk materialises, not where code runs.
    identity_fids = {o.fid for i, step in enumerate(template.steps) if step.kind == IDENTITY for o in matched[i]}
    colocated, located = _colocated_file(template, matched, ctx)
    if template.require_colocation and colocated is None:
        return None

    def install_linked(path: str | None) -> bool:
        return path is not None and (
            path in ctx.install_files
            or any(o.install_context and path in o.files
                   for o in required_obs.values() if o.fid not in identity_fids)
        )

    def evasion_linked(path: str | None) -> bool:
        return path is not None and any(
            o.fid not in required_obs and path in o.files
            for code in EVASION_CODES for o in ctx.by_code.get(code, ())
        )

    if len(required) == 1:
        if not any(o.strong for o in required_obs.values()):
            return None
    else:
        weak = [i for i in required if all(o.capability_grade for o in matched[i])]
        if weak:
            corroborated = colocated is not None and all(i in located for i in weak) and (
                install_linked(colocated) or evasion_linked(colocated)
                or any(o.strong and colocated in o.files for o in required_obs.values())
            )
            if not corroborated and not template.require_colocation and len(weak) < len(required):
                # Only behaviour steps can be placed at install time (identity findings have no code
                # location; artifact findings are shipped files, not code that runs).
                corroborated = all(
                    template.steps[i].kind == BEHAVIOR
                    and any(o.code not in INSTALL_VECTOR_CODES and ctx.install_time(o) for o in matched[i])
                    for i in weak
                )
            if not corroborated:
                return None

    booster_obs: dict[str, _Obs] = {}
    satisfied = 0
    for booster in template.boosters:
        hits = [o for o in ctx.candidates(booster.codes_any) if o.fid not in required_obs]
        if hits:
            satisfied += 1
            for o in hits:
                booster_obs.setdefault(o.fid, o)

    chain_obs = [*required_obs.values(), *booster_obs.values(),
                 *(o for i, step in enumerate(template.steps) if not step.required for o in matched[i])]
    install_time = any(o.code in INSTALL_VECTOR_CODES or ctx.install_time(o)
                       for o in chain_obs if o.fid not in identity_fids)
    evasion = any(o.code in EVASION_CODES for o in chain_obs)

    base = sum(max(o.confidence for o in matched[i]) for i in required) / len(required)
    confidence = base + BOOSTER_BONUS * satisfied
    confidence += COLOCATION_BONUS if colocated is not None else 0.0
    confidence += INSTALL_TIME_BONUS if install_time else 0.0
    confidence = round(min(CONFIDENCE_CAP, confidence), 4)
    if confidence < EMIT_MIN_CONFIDENCE:
        return None
    severity = template.severity if confidence >= DOWNGRADE_BELOW else _DOWNGRADE[template.severity]
    return _Candidate(template=template, index=index, confidence=confidence, severity=severity,
                      matched=matched, booster_obs=sorted(booster_obs.values(), key=lambda o: o.rank),
                      colocated_file=colocated, install_time=install_time, evasion=evasion)


# --------------------------------------------------------------------------- rendering
def _hint_strings(value: Any, out: list[str], depth: int = 0) -> None:
    if len(out) >= _MAX_HINT_STRINGS or depth > 3:
        return
    if isinstance(value, str):
        out.append(value[:300].lower())
    elif isinstance(value, Mapping):
        for key in sorted(value, key=str)[:32]:
            _hint_strings(value[key], out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value[:32]:
            _hint_strings(item, out, depth + 1)


def resolve_technique(step: StepSpec, finding: Finding) -> tuple[str | None, str | None]:
    """``(tactic, technique_id)`` for a step, refined by its most confident finding.

    A per-code override wins over the step default. An unmapped technique is taken from the
    finding's own ATT&CK mapping when exactly one of its ids is a hinted candidate, otherwise
    from keyword hints when they identify exactly one technique; otherwise it stays ``None``.
    """
    tactic, technique = step.tactic, step.technique_id
    code = getattr(finding, "code", None)
    override = step.overrides.get(code) if isinstance(code, str) else None
    if override is not None:
        tactic, technique = override
    if technique is None and step.technique_hints:
        candidates = {tid for _, tid in step.technique_hints}
        attack = getattr(finding, "attack", None)
        attack = attack[:_MAX_HINT_STRINGS] if isinstance(attack, (tuple, list)) else ()
        own = {tid for tid in attack if isinstance(tid, str) and tid in candidates}
        if len(own) == 1:
            return tactic, next(iter(own))
        strings: list[str] = []
        _hint_strings(getattr(finding, "evidence", None), strings)
        hinted = {tid for keyword, tid in step.technique_hints if any(keyword in s for s in strings)}
        if len(hinted) == 1:
            technique = next(iter(hinted))
    return tactic, technique


def _build(candidate: _Candidate) -> tuple[AttackChain, Finding]:
    template = candidate.template
    steps: list[ChainStep] = []
    step_codes: list[list[str]] = []
    chain_ids: list[str] = []
    for i, spec in sorted(enumerate(template.steps), key=lambda item: item[1].order):
        hits = candidate.matched[i]
        if not hits:
            continue
        tactic, technique = resolve_technique(spec, hits[0].finding)
        ids = tuple(o.fid for o in hits[:MAX_STEP_FINDINGS])
        steps.append(ChainStep(
            order=len(steps) + 1, tactic=tactic, technique_id=technique,
            technique_name=taxonomy.ATTACK_TECHNIQUES.get(technique) if technique else None,
            description=spec.description, finding_ids=ids,
        ))
        step_codes.append(sorted({o.code for o in hits}))
        chain_ids.extend(ids)
    chain_ids.extend(o.fid for o in candidate.booster_obs)
    finding_ids = tuple(dict.fromkeys(chain_ids))[:MAX_CHAIN_FINDINGS]
    attack = tuple(dict.fromkeys(s.technique_id for s in steps if s.technique_id))

    facts = [" -> ".join("/".join(codes) for codes in step_codes)]
    if candidate.colocated_file:
        facts.append(f"co-located in {candidate.colocated_file}")
    if candidate.install_time:
        facts.append("install-time execution evidence")
    if candidate.evasion:
        facts.append("evasion present")
    summary = sanitize_text(f"{template.summary} Evidence: {'; '.join(facts)}.", max_len=MAX_SUMMARY_CHARS)

    finding = Finding(
        Code.ATTACK_CHAIN, candidate.severity, SEVERITY_WEIGHTS[candidate.severity], summary,
        {"chain_id": template.chain_id, "title": template.title, "step_codes": step_codes},
        None,
        confidence=candidate.confidence,
        title=template.title,
        analyzer=ANALYZER_NAME,
        analyzer_version=VERSION,
        location=Location(file=candidate.colocated_file) if candidate.colocated_file else None,
        attack=attack,
        provenance=Provenance.CORRELATION,
        related=finding_ids,
    ).with_defaults(analyzer=ANALYZER_NAME, analyzer_version=VERSION)

    chain = AttackChain(
        chain_id=template.chain_id, variant=template.variant, title=template.title, summary=finding.message,
        severity=candidate.severity, confidence=finding.confidence, finding_id=finding.finding_id,
        finding_ids=finding_ids, attack=attack, steps=tuple(steps), colocated_file=candidate.colocated_file,
        install_time=candidate.install_time,
    )
    return chain, finding


# --------------------------------------------------------------------------- entry point
def correlate(findings: Iterable[Any], *, templates: Sequence[ChainTemplate] | None = None) -> CorrelationResult:
    """Correlate findings into attack chains (formulas and guards in the module docstring).

    ``templates`` defaults to :data:`app.analysis.correlation.chains.TEMPLATES`. Output is
    deterministic for the same set of findings, whatever their order.
    """
    selected = chain_defs.TEMPLATES if templates is None else tuple(templates)
    ctx = _Context(_normalise(findings))
    if not ctx.observations:
        return CorrelationResult()

    best: dict[str, _Candidate] = {}
    for index, template in enumerate(selected):
        candidate = _evaluate(template, index, ctx)
        if candidate is None:
            continue
        current = best.get(template.chain_id)
        if current is None or (candidate.confidence, candidate.severity.rank, -candidate.index) > (
                current.confidence, current.severity.rank, -current.index):
            best[template.chain_id] = candidate

    ordered = sorted(best.values(), key=lambda c: (-c.severity.rank, -c.confidence, c.template.chain_id))
    result = CorrelationResult()
    for candidate in ordered[:MAX_CHAINS]:
        chain, finding = _build(candidate)
        result.chains.append(chain)
        result.findings.append(finding)
    return result


__all__ = [
    "ANALYZER_NAME",
    "INSTALL_CONTEXTS",
    "MAX_CHAINS",
    "NON_EXECUTING_CONTEXTS",
    "SEVERITY_WEIGHTS",
    "VERSION",
    "AttackChain",
    "ChainStep",
    "CorrelationResult",
    "correlate",
    "is_root_setup_script",
    "is_test_path",
    "resolve_technique",
]
