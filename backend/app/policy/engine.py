"""Policy engine v2 — maps an analysis result to an enforcement decision (allow / warn / block).

``evaluate(result, policy)`` keeps its v1 signature; Warden adds keyword arguments::

    evaluate(result, policy, *, exceptions=(), environment=None, now=None) -> PolicyDecision

``policy`` may be ``None`` (built-in :data:`DEFAULT_POLICY`), a ``Policy`` row (its ``document`` when
present, otherwise the v1 columns via :func:`app.policy.document.from_legacy`), a mapping of v1
columns, a document mapping, or a :class:`~app.policy.document.PolicyDocument`.

Evaluation order (SPEC section 11)
==================================

1. **denylist** → BLOCK.
2. **non-overridable** → BLOCK: any ``IOC_MATCH`` finding (or a legacy ``ioc`` capability with no
   finding behind it), a ``critical`` ``ATTACK_CHAIN`` finding with confidence ≥ 0.9, any
   ``HASH_MISMATCH`` finding. Exceptions and the allowlist are never consulted for these.
3. **exceptions** — active database exceptions (``exceptions=``, see :mod:`app.policy.exceptions`)
   followed by unexpired document exceptions remove the findings they cover (code OR category scope;
   an unscoped exception covers every finding of the package). The first matching exception, in that
   order, is credited. Every exception that removed something is reported in ``exceptions_applied``
   and as an ``exempt`` reason.
4. **allowlist** → ALLOW.
5. **deny codes / categories / capabilities** → BLOCK, only for findings whose confidence is at or
   above ``deny.min_confidence`` (default 0.7). v1 ``blocked_capabilities`` are deny capabilities. A
   capability listed in ``result.capabilities`` that no finding carries (legacy inputs) is treated as
   present; a capability whose findings all sit below the gate does not fire.
6. **vulnerability deny** → BLOCK (see below).
7. **requirements** (provenance states, verified artifact hash, SBOM) → BLOCK.
8. **block threshold** → BLOCK when the (exception-adjusted) risk score ≥ ``thresholds.block``.
9. **minimum release age** → BLOCK.
10. **warn codes / categories / capabilities / vulnerabilities** (gate ``warn.min_confidence``,
    default 0.5) → WARN.
11. **warn threshold** → WARN.
12. otherwise ALLOW (``clean``).

Stages 1–2 and 5–9 record *every* matching rule of the stage group, so a blocked package lists all
of its blocking reasons; ``matched_rules`` holds the rules whose effect equals the final decision.

Fail-safe behaviour
===================

* **Unknown vulnerability status.** Vulnerability rules read ``result.vulnerabilities`` (withdrawn
  advisories ignored) and treat ``intel_status["status"]`` other than ``ok`` as unknown. A vulnerability
  matches a rule when ANY configured criterion matches: KEV listing, severity (derived from the CVSS
  v3 qualitative bands when no label is present), CVSS (bounded by the severity band when no score is
  present), EPSS. When a *deny* rule cannot be fully evaluated — intelligence not ``ok``, or a known
  vulnerability lacks the data a criterion needs — the result is a WARN reason
  ``vulnerability_status_unknown``, never a silent allow. For *warn* rules the same situation is an
  ``info`` reason only.
* **Unknown requirement data** (provenance ``not_run``/missing, unknown hash verification, no SBOM
  context, unknown release age with a minimum age configured) yields a WARN reason; a known violation
  yields BLOCK.
* **Invalid stored document** → BLOCK ``policy_document_invalid`` (the policy cannot be understood,
  so nothing is allowed on its authority).
* **Oversized results** (more than :data:`MAX_EVALUATED_FINDINGS` findings or
  :data:`MAX_EVALUATED_VULNERABILITIES` vulnerabilities) → BLOCK ``evaluation_limits_exceeded``.
* A finding dict whose ``confidence`` is missing or not a finite number is evaluated at 0.8, the
  :class:`~app.analysis.findings.Finding` default, so malformed evidence cannot slip under a gate.

Exceptions and the risk score
=============================

When exceptions removed anything (or an unscoped exception applies), thresholds use
``min(result.risk_score, recomputed)`` where ``recomputed`` is the maximum of the rule score of the
remaining findings (:func:`app.analysis.scoring.compute_rule_score`), the worst remaining
vulnerability score (:func:`app.analysis.risk.vulnerability_score`) and — unless an unscoped exception
applies — the ML score (it cannot be attributed to individual findings, so a scoped exception keeps
it), raised to the critical high-confidence floor (80) when a floor-triggering finding remains.
Requirements and the minimum release age are waived by an unscoped exception, or when every finding
behind the violation (``PROVENANCE_FAILED``/``PROVENANCE_UNVERIFIED``; ``NEW_PACKAGE``) was removed.

Reasons are ``{rule, effect, detail, finding_ids}`` (plus ``exception_id`` / ``vulnerability_ids``
where relevant) with ``effect`` in ``block | warn | allow | exempt | info``. Details are sanitised.
Evaluation is pure and deterministic for identical inputs (including ``now``).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.analysis import risk as risk_engine
from app.analysis import scoring, taxonomy
from app.analysis.findings import Category
from app.analysis.signals import Capability, Code
from app.core.redaction import sanitize_text
from app.db.base import utcnow
from app.db.models import Decision
from app.policy.document import EffectivePolicy, PolicyDocument, VulnerabilityRule, effective_policy
from app.policy.exceptions import SOURCE_DOCUMENT, ExceptionGrant, aware_utc, coerce_grant, grant_from_entry
from app.sbom.models import normalize_name
from app.schemas.scan import validate_environment

if TYPE_CHECKING:  # pragma: no cover - annotations only: evaluating a policy never imports the analyzer registry
    from app.analysis.orchestrator import AnalysisResult
    from app.db.models import Policy

BLOCK, WARN, ALLOW, EXEMPT, INFO = "block", "warn", "allow", "exempt", "info"

NON_OVERRIDABLE_CODES = frozenset({Code.IOC_MATCH, Code.HASH_MISMATCH})
ATTACK_CHAIN_NON_OVERRIDABLE_CONFIDENCE = 0.9
DEFAULT_FINDING_CONFIDENCE = 0.8
MAX_EVALUATED_FINDINGS = 20_000
MAX_EVALUATED_VULNERABILITIES = 5_000
MAX_REASON_IDS = 50
MAX_REASONS = 200
BUILTIN_POLICY_NAME = "builtin-default"

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# CVSS v3.x qualitative severity rating scale (FIRST CVSS v3.1 specification, table 14).
_CVSS_BANDS = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (0.0, 3.9)}
_CRITERIA = ("known_exploited", "severity", "cvss", "epss")
_KNOWN_PROVENANCE_VERDICTS = frozenset({"attested", "unverified", "failed"})
_PROVENANCE_VIOLATION_CODES = frozenset({Code.PROVENANCE_FAILED, Code.PROVENANCE_UNVERIFIED})
_PROVENANCE_CODES = frozenset({*_PROVENANCE_VIOLATION_CODES, Code.PROVENANCE_ATTESTED, Code.REPO_MISMATCH})


@dataclass
class PolicyDecision:
    decision: Decision
    matched_rules: list[str]
    reasons: list[dict] = field(default_factory=list)
    exceptions_applied: list[dict] = field(default_factory=list)
    environment: str | None = None
    policy_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "matched_rules": list(self.matched_rules),
            "reasons": [dict(r) for r in self.reasons],
            "exceptions_applied": [dict(e) for e in self.exceptions_applied],
            "environment": self.environment,
            "policy_hash": self.policy_hash,
        }


# Sensible built-in default used when no policy row exists yet (v1 columns only).
DEFAULT_POLICY = dict(
    warn_threshold=40,
    block_threshold=70,
    min_package_age_days=0,
    blocked_capabilities=[Capability.INSTALL_EXEC, Capability.IOC],
    allowlist=[],
    denylist=[],
)


# =========================================================================== input views
@dataclass(frozen=True)
class _Finding:
    index: int
    code: str
    category: str
    capability: str | None
    confidence: float
    severity: str
    weight: float
    finding_id: str | None
    evidence: Mapping[str, Any]


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _score(value: Any) -> int:
    number = _number(value)
    return 0 if number is None else int(max(0.0, min(100.0, number)))


def _view(index: int, raw: Any) -> _Finding | None:
    if not isinstance(raw, Mapping) and callable(getattr(raw, "to_dict", None)):
        try:
            raw = raw.to_dict()
        except Exception:  # a broken finding object is skipped, never fatal
            return None
    if not isinstance(raw, Mapping):
        return None
    code = raw.get("code")
    code = code.strip()[:64] if isinstance(code, str) else ""
    category = raw.get("category")
    if not (isinstance(category, str) and category.strip()):
        info = taxonomy.get(code)
        category = info.category if info else Category.OTHER.value
    capability = raw.get("capability")
    confidence = _number(raw.get("confidence"))
    finding_id = raw.get("finding_id")
    evidence = raw.get("evidence")
    return _Finding(
        index=index,
        code=code,
        category=category.strip().lower()[:64],
        capability=capability.strip().lower()[:64] if isinstance(capability, str) and capability.strip() else None,
        confidence=DEFAULT_FINDING_CONFIDENCE if confidence is None else min(1.0, max(0.0, confidence)),
        severity=str(raw.get("severity") or "").strip().lower(),
        weight=max(0.0, _number(raw.get("weight")) or 0.0),
        finding_id=finding_id if isinstance(finding_id, str) and 0 < len(finding_id) <= 64 else None,
        evidence=evidence if isinstance(evidence, Mapping) else {},
    )


def _critical_chain(f: _Finding) -> bool:
    return (f.code == Code.ATTACK_CHAIN and f.severity == "critical"
            and f.confidence >= ATTACK_CHAIN_NON_OVERRIDABLE_CONFIDENCE)


def _non_overridable(f: _Finding) -> bool:
    return f.code in NON_OVERRIDABLE_CODES or _critical_chain(f)


def _floor_trigger(f: _Finding) -> bool:
    return (f.severity == "critical" and f.confidence >= risk_engine.FLOOR_MIN_CONFIDENCE
            and (f.category in risk_engine.FLOOR_CATEGORIES or f.code in risk_engine.FLOOR_CODES))


def _vulnerability_id(f: _Finding) -> str | None:
    if f.code not in risk_engine.VULNERABILITY_CODES:
        return None
    record = f.evidence.get("vulnerability")
    if isinstance(record, Mapping) and record.get("id"):
        return str(record["id"])
    return None


def _read(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def _join(values: Iterable[str], limit: int = 10) -> str:
    items = list(values)
    text = ", ".join(items[:limit])
    return text + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


# =========================================================================== vulnerability criteria
def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def vulnerability_criteria(vuln: Mapping[str, Any], rule: VulnerabilityRule) -> dict[str, bool | None]:
    """Per configured criterion: ``True`` (matches), ``False`` (does not) or ``None`` (data missing)."""
    out: dict[str, bool | None] = {}
    severity = str(vuln.get("severity") or "").strip().lower()
    severity = severity if severity in _SEVERITY_RANK else None
    cvss = _number(vuln.get("cvss_score"))
    cvss = cvss if cvss is not None and 0.0 <= cvss <= 10.0 else None
    if rule.known_exploited:
        out["known_exploited"] = vuln.get("kev") is True
    if rule.min_severity:
        effective = severity or (_severity_from_cvss(cvss) if cvss is not None else None)
        out["severity"] = None if effective is None else _SEVERITY_RANK[effective] >= _SEVERITY_RANK[rule.min_severity]
    if rule.min_cvss is not None:
        if cvss is not None:
            out["cvss"] = cvss >= rule.min_cvss
        elif severity is not None:
            low, high = _CVSS_BANDS[severity]
            out["cvss"] = True if low >= rule.min_cvss else False if high < rule.min_cvss else None
        else:
            out["cvss"] = None
    if rule.min_epss is not None:
        epss = _number(vuln.get("epss_score"))
        out["epss"] = None if epss is None or not 0.0 <= epss <= 1.0 else epss >= rule.min_epss
    return out


def _criterion_text(criterion: str, rule: VulnerabilityRule) -> str:
    if criterion == "known_exploited":
        return "listed in CISA KEV"
    if criterion == "severity":
        return f"severity >= {rule.min_severity}"
    if criterion == "cvss":
        return f"CVSS >= {rule.min_cvss:g}"
    return f"EPSS >= {rule.min_epss:g}"


# =========================================================================== evaluation
@dataclass
class _ExceptionState:
    remaining: list[_Finding]
    removed: set[int]
    unbacked_capabilities: set[str]
    vulnerabilities: list[Mapping[str, Any]]
    applied: list[dict]
    whole_package: bool
    original_score: int
    score: int


class _Evaluator:
    def __init__(self, result: Any, policy: Any, effective: EffectivePolicy, environment: str | None,
                 now: datetime) -> None:
        self.result = result
        self.effective = effective
        self.doc: PolicyDocument | None = effective.document
        self.environment = environment
        self.now = now
        policy_id = None if isinstance(policy, PolicyDocument) else _read(policy, "id")
        self.policy_id = str(policy_id) if policy_id is not None else None
        self.package = normalize_name(str(getattr(result, "name", "") or ""))
        version = getattr(result, "version", None)
        self.version = version if isinstance(version, str) else None

        signals = getattr(result, "signals", None)
        signals = list(signals) if isinstance(signals, (list, tuple)) else []
        vulns = getattr(result, "vulnerabilities", None)
        vulns = list(vulns) if isinstance(vulns, (list, tuple)) else []
        self.limits_exceeded = len(signals) > MAX_EVALUATED_FINDINGS or len(vulns) > MAX_EVALUATED_VULNERABILITIES
        self.findings = [f for f in (_view(i, s) for i, s in enumerate(signals[:MAX_EVALUATED_FINDINGS]))
                         if f is not None]
        caps = getattr(result, "capabilities", None)
        caps = caps if isinstance(caps, (list, tuple, set, frozenset)) else []
        self.capabilities = sorted({c.strip().lower() for c in caps if isinstance(c, str) and c.strip()})
        self.backed_capabilities = {f.capability for f in self.findings if f.capability}
        self.vulnerabilities = [v for v in vulns[:MAX_EVALUATED_VULNERABILITIES]
                                if isinstance(v, Mapping) and not v.get("withdrawn")]
        self.reasons: list[dict] = []

    # ------------------------------------------------------------------ reasons
    def _add(self, effect: str, rule: str, detail: str, findings: Iterable[_Finding] = (), **extra: Any) -> None:
        ids: list[str] = []
        for f in findings:
            if f.finding_id and f.finding_id not in ids:
                ids.append(f.finding_id)
        reason: dict[str, Any] = {
            "rule": sanitize_text(rule, max_len=120),
            "effect": effect,
            "detail": sanitize_text(detail, max_len=400),
            "finding_ids": ids[:MAX_REASON_IDS],
        }
        if len(ids) > MAX_REASON_IDS:
            reason["finding_count"] = len(ids)
        reason.update(extra)
        self.reasons.append(reason)

    def _has(self, effect: str, rule: str | None = None) -> bool:
        return any(r["effect"] == effect and (rule is None or r["rule"] == rule) for r in self.reasons)

    def _decision(self, decision: Decision, applied: list[dict]) -> PolicyDecision:
        matched: list[str] = []
        for reason in self.reasons:
            if reason["effect"] == decision.value and reason["rule"] not in matched:
                matched.append(reason["rule"])
        reasons = self.reasons
        if len(reasons) > MAX_REASONS:
            omitted = len(reasons) - (MAX_REASONS - 1)
            reasons = reasons[: MAX_REASONS - 1] + [{"rule": "reasons_truncated", "effect": INFO,
                                                     "detail": f"{omitted} further reason(s) omitted",
                                                     "finding_ids": []}]
        return PolicyDecision(decision, matched, reasons, applied, self.environment, self.effective.policy_hash)

    # ------------------------------------------------------------------ entry
    def run(self, exceptions: Iterable[Any]) -> PolicyDecision:
        grants = [coerce_grant(e) for e in (exceptions or ())]
        doc = self.doc
        if doc is None:
            first = self.effective.errors[0] if self.effective.errors else {"loc": "document", "msg": "invalid"}
            self._add(BLOCK, "policy_document_invalid",
                      f"The policy failed validation ({first.get('loc')}: {first.get('msg')}); evaluation fails "
                      "closed until the policy is fixed")
            return self._decision(Decision.block, [])

        # 1-2. denylist, evaluation limits, non-overridable indicators
        if self.limits_exceeded:
            self._add(BLOCK, "evaluation_limits_exceeded",
                      f"The result has more than {MAX_EVALUATED_FINDINGS} findings or "
                      f"{MAX_EVALUATED_VULNERABILITIES} vulnerabilities; evaluation fails closed")
        if self.package in set(doc.spec.deny.packages):
            self._add(BLOCK, "denylist", f"{self.package} is on the policy denylist")
        self._non_overridable()
        if self._has(BLOCK):
            return self._decision(Decision.block, [])

        # 3. exceptions
        state = self._apply_exceptions(grants, doc)

        # 4. allowlist
        if self.package in set(doc.spec.allow.packages):
            self._add(ALLOW, "allowlist", f"{self.package} is on the policy allowlist")
            return self._decision(Decision.allow, state.applied)

        # 5-9. blocking rules
        self._finding_rules(state, doc.spec.deny, BLOCK)
        self._vulnerability_rules(state, doc.spec.deny.vulnerabilities, BLOCK)
        self._requirements(state, doc)
        block_at = doc.spec.thresholds.block
        if state.score >= block_at:
            self._add(BLOCK, "block_threshold", f"Risk score {state.score}{self._score_note(state)} >= block "
                                                f"threshold {block_at}")
        self._min_age(state, doc.spec.min_package_age_days)
        if self._has(BLOCK):
            return self._decision(Decision.block, state.applied)

        # 10-11. warnings
        self._finding_rules(state, doc.spec.warn, WARN)
        self._vulnerability_rules(state, doc.spec.warn.vulnerabilities, WARN)
        warn_at = doc.spec.thresholds.warn
        if state.score >= warn_at:
            self._add(WARN, "warn_threshold", f"Risk score {state.score}{self._score_note(state)} >= warn "
                                              f"threshold {warn_at}")
        if self._has(WARN):
            return self._decision(Decision.warn, state.applied)

        self._add(ALLOW, "clean", "No policy rule matched")
        return self._decision(Decision.allow, state.applied)

    @staticmethod
    def _score_note(state: _ExceptionState) -> str:
        return f" (after exceptions; analysed {state.original_score})" if state.score != state.original_score else ""

    # ------------------------------------------------------------------ stages
    def _non_overridable(self) -> None:
        iocs = [f for f in self.findings if f.code == Code.IOC_MATCH]
        legacy_ioc = Capability.IOC in self.capabilities and Capability.IOC not in self.backed_capabilities
        if iocs or legacy_ioc:
            self._add(BLOCK, "known_malicious_indicator",
                      "A known malicious indicator matched; exceptions and the allowlist cannot waive it", iocs)
        chains = [f for f in self.findings if _critical_chain(f)]
        if chains:
            self._add(BLOCK, "critical_attack_chain",
                      f"A critical attack chain was correlated with confidence >= "
                      f"{ATTACK_CHAIN_NON_OVERRIDABLE_CONFIDENCE:g}; non-overridable", chains)
        mismatches = [f for f in self.findings if f.code == Code.HASH_MISMATCH]
        if mismatches:
            self._add(BLOCK, "artifact_hash_mismatch",
                      "The analysed artifact does not match the registry digest; non-overridable", mismatches)

    def _apply_exceptions(self, grants: list[ExceptionGrant], doc: PolicyDocument) -> _ExceptionState:
        candidates = [*grants, *(grant_from_entry(entry) for entry in doc.spec.exceptions)]
        active = [g for g in candidates
                  if g.is_active(self.now)
                  and g.applies_to(self.package, self.version, environment=self.environment, policy_id=self.policy_id)]
        whole = next((pos for pos, g in enumerate(active) if g.whole_package), None)

        waived: dict[int, list[_Finding]] = {}
        removed: set[int] = set()
        for f in self.findings:
            if _non_overridable(f):
                continue
            for pos, grant in enumerate(active):
                if grant.covers(f.code, f.category):
                    removed.add(f.index)
                    waived.setdefault(pos, []).append(f)
                    break
        remaining = [f for f in self.findings if f.index not in removed]

        unbacked = {c for c in self.capabilities if c not in self.backed_capabilities}
        waived_caps = sorted(c for c in unbacked if c != Capability.IOC) if whole is not None else []
        unbacked -= set(waived_caps)

        referenced = {vid for f in self.findings if (vid := _vulnerability_id(f))}
        still_referenced = {vid for f in remaining if (vid := _vulnerability_id(f))}
        vulnerabilities: list[Mapping[str, Any]] = []
        unbacked_vulns: list[str] = []
        for vuln in self.vulnerabilities:
            vid = str(vuln.get("id") or "")
            if vid in referenced and vid not in still_referenced:
                continue
            if vid not in referenced and whole is not None:
                unbacked_vulns.append(vid)
                continue
            vulnerabilities.append(vuln)

        applied: list[dict] = []
        for pos, grant in enumerate(active):
            findings = waived.get(pos, [])
            vuln_ids = sorted({vid for f in findings if (vid := _vulnerability_id(f))} - still_referenced)
            caps = waived_caps if pos == whole else []
            if pos == whole:
                vuln_ids = sorted(set(vuln_ids) | set(unbacked_vulns))
            if not findings and not caps and not vuln_ids:
                continue
            ids = list(dict.fromkeys(f.finding_id for f in findings if f.finding_id))
            applied.append({**grant.to_dict(), "finding_ids": ids[:MAX_REASON_IDS], "finding_count": len(findings),
                            "capabilities": caps, "vulnerability_ids": vuln_ids[:MAX_REASON_IDS]})
            label = "policy-document" if grant.source == SOURCE_DOCUMENT else "approved"
            scope = f" {grant.version_spec}" if grant.version_spec else ""
            self._add(EXEMPT, "exception",
                      f"{len(findings)} finding(s) waived by {label} exception {grant.id} for {grant.package}{scope} "
                      f"(expires {grant.expires_at.isoformat()})", findings, exception_id=grant.id)

        original = _score(getattr(self.result, "risk_score", 0))
        score = original
        if removed or waived_caps or unbacked_vulns or whole is not None:
            score = min(original, self._recomputed_score(remaining, vulnerabilities, whole is not None))
            if score != original:
                self._add(INFO, "risk_score_after_exceptions",
                          f"Risk score {original} -> {score} after exceptions (rule score of remaining findings, "
                          f"remaining vulnerabilities{'' if whole is not None else ', ML score'})")
        return _ExceptionState(remaining, removed, unbacked, vulnerabilities, applied, whole is not None,
                               original, score)

    def _recomputed_score(self, remaining: list[_Finding], vulns: list[Mapping[str, Any]], whole: bool) -> int:
        value = scoring.compute_rule_score([{"code": f.code, "weight": f.weight} for f in remaining])
        if not whole and getattr(self.result, "ml_available", False) is True:
            value = max(value, _score(getattr(self.result, "ml_score", 0)))
        value = max([value, *(risk_engine.vulnerability_score(v) for v in vulns)])
        if any(_floor_trigger(f) for f in remaining):
            value = max(value, risk_engine.FLOOR_SCORE)
        return int(max(0, min(100, value)))

    def _finding_rules(self, state: _ExceptionState, rules: Any, effect: str) -> None:
        codes, categories, capabilities = set(rules.codes), set(rules.categories), set(rules.capabilities)
        if not (codes or categories or capabilities):
            return
        gate = rules.min_confidence
        prefix = "deny" if effect == BLOCK else "warn"
        capability_rule = "blocked_capability" if effect == BLOCK else "warn_capability"
        gated = [f for f in state.remaining if f.confidence >= gate]
        for code in sorted(codes):
            hits = [f for f in gated if f.code == code]
            if hits:
                self._add(effect, f"{prefix}_code:{code}",
                          f"{len(hits)} finding(s) with code {code} at confidence >= {gate:g}", hits)
        for category in sorted(categories):
            hits = [f for f in gated if f.category == category]
            if hits:
                self._add(effect, f"{prefix}_category:{category}",
                          f"{len(hits)} finding(s) in category {category} at confidence >= {gate:g}", hits)
        for capability in sorted(capabilities):
            hits = [f for f in gated if f.capability == capability]
            if hits:
                self._add(effect, f"{capability_rule}:{capability}",
                          f"{len(hits)} finding(s) with capability {capability} at confidence >= {gate:g}", hits)
            elif capability in state.unbacked_capabilities:
                self._add(effect, f"{capability_rule}:{capability}",
                          f"Capability {capability} is reported without a supporting finding and is treated as "
                          "present")
        below = [f for f in state.remaining if f.confidence < gate
                 and (f.code in codes or f.category in categories or f.capability in capabilities)]
        if below:
            self._add(INFO, f"{prefix}_rules_below_min_confidence",
                      f"{len(below)} finding(s) matched {prefix} rules below min_confidence {gate:g} and did not fire",
                      below)

    def _intel_status(self) -> str:
        intel = getattr(self.result, "intel_status", None)
        status = intel.get("status") if isinstance(intel, Mapping) else None
        return sanitize_text(status.strip().lower(), max_len=40) if isinstance(status, str) and status.strip() \
            else "unknown"

    def _vulnerability_rules(self, state: _ExceptionState, rule: VulnerabilityRule, effect: str) -> None:
        if not rule.configured:
            return
        prefix = "deny_vulnerability" if effect == BLOCK else "warn_vulnerability"
        matched: dict[str, list[str]] = {}
        undetermined: list[str] = []
        for vuln in state.vulnerabilities:
            vid = sanitize_text(str(vuln.get("id") or "unidentified"), max_len=100)
            outcome = vulnerability_criteria(vuln, rule)
            hits = [criterion for criterion, ok in outcome.items() if ok is True]
            for criterion in hits:
                matched.setdefault(criterion, []).append(vid)
            if not hits and any(ok is None for ok in outcome.values()):
                undetermined.append(vid)
        for criterion in _CRITERIA:
            ids = matched.get(criterion)
            if ids:
                wanted = set(ids)
                refs = [f for f in state.remaining if _vulnerability_id(f) in wanted]
                self._add(effect, f"{prefix}:{criterion}",
                          f"Vulnerability {_criterion_text(criterion, rule)}: {_join(ids)}", refs,
                          vulnerability_ids=ids[:MAX_REASON_IDS])
        status = self._intel_status()
        if status == "ok" and not undetermined:
            return
        parts = []
        if status != "ok":
            parts.append(f"vulnerability intelligence status is '{status}'")
        if undetermined:
            parts.append(f"{len(undetermined)} known vulnerability record(s) lack the data the rule needs")
        if effect == BLOCK:
            if not self._has(WARN, "vulnerability_status_unknown"):
                self._add(WARN, "vulnerability_status_unknown",
                          f"Vulnerability status unknown: {'; '.join(parts)}. The deny rule cannot be fully "
                          "evaluated, so the package is warned rather than allowed",
                          vulnerability_ids=undetermined[:MAX_REASON_IDS])
        elif not (self._has(WARN, "vulnerability_status_unknown") or self._has(INFO, "vulnerability_status_unknown")):
            self._add(INFO, "vulnerability_status_unknown",
                      f"Vulnerability status unknown: {'; '.join(parts)}; warning rules could not be fully evaluated",
                      vulnerability_ids=undetermined[:MAX_REASON_IDS])

    def _waived(self, state: _ExceptionState, codes: frozenset[str]) -> bool:
        if state.whole_package:
            return True
        backing = [f for f in self.findings if f.code in codes]
        return bool(backing) and all(f.index in state.removed for f in backing)

    def _requirements(self, state: _ExceptionState, doc: PolicyDocument) -> None:
        require = doc.spec.require
        provenance = getattr(self.result, "provenance", None)
        provenance = provenance if isinstance(provenance, Mapping) else {}

        if require.provenance is not None:
            raw = provenance.get("status")
            status = raw.strip().lower() if isinstance(raw, str) and raw.strip() else None
            allowed = ", ".join(require.provenance)
            refs = [f for f in self.findings if f.code in _PROVENANCE_CODES]
            if status in require.provenance:
                pass
            elif status in _KNOWN_PROVENANCE_VERDICTS:
                if self._waived(state, _PROVENANCE_VIOLATION_CODES):
                    self._add(EXEMPT, "requirement_waived:provenance",
                              f"Provenance status '{status}' is outside the required states ({allowed}); waived by "
                              "exception", refs)
                else:
                    self._add(BLOCK, "requirement:provenance",
                              f"Provenance status '{status}' is not one of the required states ({allowed})", refs)
            elif state.whole_package:
                self._add(EXEMPT, "requirement_waived:provenance", "Provenance status unknown; waived by exception")
            else:
                shown = "not available" if status is None else f"'{sanitize_text(status, max_len=40)}'"
                self._add(WARN, "provenance_status_unknown",
                          f"Provenance status is {shown}, so the requirement ({allowed}) cannot be verified", refs)

        if require.hash_verified:
            if "hash_verified" in provenance:
                verified = provenance.get("hash_verified")
            else:
                intel = getattr(self.result, "package_intel", None)
                artifact = intel.get("artifact") if isinstance(intel, Mapping) else None
                verified = artifact.get("hash_verified") if isinstance(artifact, Mapping) else None
            if verified is True:
                pass
            elif state.whole_package:
                self._add(EXEMPT, "requirement_waived:hash_verified", "Artifact hash not verified; waived by exception")
            elif verified is False:
                self._add(BLOCK, "requirement:hash_verified",
                          "The analysed artifact's hash could not be verified against the registry digest")
            else:
                self._add(WARN, "hash_verification_unknown",
                          "Artifact hash verification status is unknown, so the requirement cannot be verified")

        if require.sbom:
            present = self._sbom_state()
            if present is True:
                pass
            elif state.whole_package:
                self._add(EXEMPT, "requirement_waived:sbom", "SBOM requirement waived by exception")
            elif present is False:
                self._add(BLOCK, "requirement:sbom", "The evaluation context reports that no SBOM was generated")
            else:
                self._add(WARN, "sbom_status_unknown",
                          "No SBOM context accompanies this evaluation, so the SBOM requirement cannot be verified")

    def _sbom_state(self) -> bool | None:
        sbom = getattr(self.result, "sbom", None)
        if sbom is True or (isinstance(sbom, Mapping) and sbom):
            return True
        options = getattr(self.result, "scan_options", None)
        context = options.get("project_context") if isinstance(options, Mapping) else None
        value = context.get("sbom") if isinstance(context, Mapping) else None
        if value is True or (isinstance(value, Mapping) and value):
            return True
        if value is False:
            return False
        return None

    def _age_days(self) -> float | None:
        intel = getattr(self.result, "package_intel", None)
        age = _number(intel.get("age_days")) if isinstance(intel, Mapping) else None
        if age is not None and age >= 0:
            return age
        for f in self.findings:
            if f.code == Code.NEW_PACKAGE:
                value = _number(f.evidence.get("age_days"))
                if value is not None and value >= 0:
                    return value
        return None

    def _min_age(self, state: _ExceptionState, minimum: int) -> None:
        if minimum <= 0:
            return
        age = self._age_days()
        refs = [f for f in self.findings if f.code == Code.NEW_PACKAGE]
        if age is not None and age >= minimum:
            return
        if self._waived(state, frozenset({Code.NEW_PACKAGE})):
            self._add(EXEMPT, "requirement_waived:min_package_age",
                      f"Minimum release age of {minimum} day(s) waived by exception", refs)
        elif age is None:
            self._add(WARN, "package_age_unknown",
                      f"Release age is unknown, so the minimum age of {minimum} day(s) cannot be verified")
        else:
            self._add(BLOCK, "min_package_age",
                      f"Release is {age:.1f} day(s) old; the policy requires at least {minimum}", refs)


# =========================================================================== public API
def _resolve(policy: Any) -> EffectivePolicy:
    if policy is None:
        return effective_policy({"name": BUILTIN_POLICY_NAME, **DEFAULT_POLICY})
    return effective_policy(policy)


def _decision_environment(environment: str | None, effective: EffectivePolicy, policy: Any) -> str | None:
    if environment is not None and str(environment).strip():
        return validate_environment(str(environment))
    candidates = (effective.document.metadata.environment if effective.document else None,
                  None if isinstance(policy, PolicyDocument) else _read(policy, "environment"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            try:
                return validate_environment(candidate)
            except ValueError:
                continue
    return None


def evaluate(
    result: AnalysisResult,
    policy: Policy | PolicyDocument | Mapping[str, Any] | None,
    *,
    exceptions: Iterable[Any] = (),
    environment: str | None = None,
    now: datetime | None = None,
) -> PolicyDecision:
    """Evaluate ``result`` under ``policy`` (see the module docstring for order and semantics).

    ``exceptions`` accepts :class:`~app.policy.exceptions.ExceptionGrant` objects (as returned by
    :func:`~app.policy.exceptions.load_active_exceptions`), ``PolicyException`` rows or mappings;
    inactive or inapplicable ones are ignored. ``now`` defaults to the current UTC time; a naive
    value is interpreted as UTC. Raises ``ValueError`` for an unknown ``environment`` and ``TypeError``
    for an unsupported exception object.
    """
    current = aware_utc(now) if now is not None else utcnow()
    effective = _resolve(policy)
    env = _decision_environment(environment, effective, policy)
    return _Evaluator(result, policy, effective, env, current).run(exceptions)


def policy_hash_of(policy: Policy | PolicyDocument | Mapping[str, Any] | None) -> str:
    """The ``policy_hash`` an evaluation under ``policy`` records."""
    return _resolve(policy).policy_hash


def _extract_age_days(result: AnalysisResult) -> float | None:
    """v1 helper (kept for compatibility): release age from ``NEW_PACKAGE`` evidence."""
    for s in result.signals:
        if isinstance(s, Mapping) and s.get("code") == Code.NEW_PACKAGE:
            evidence = s.get("evidence")
            return evidence.get("age_days") if isinstance(evidence, Mapping) else None
    return None


__all__ = [
    "DEFAULT_POLICY",
    "NON_OVERRIDABLE_CODES",
    "PolicyDecision",
    "evaluate",
    "policy_hash_of",
    "vulnerability_criteria",
]
