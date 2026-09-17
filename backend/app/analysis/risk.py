"""Risk Engine 2.0 — multi-dimensional, explainable package risk.

v1 produced one number. Warden X keeps that number (``final_score``, 0–100, same severity
bands) but derives it from separately reported **dimensions**, so "this package behaves
maliciously" is distinguishable from "this package is benign but has a known CVE", and
"no vulnerabilities" is distinguishable from "vulnerability intelligence was unavailable".

Every dimension reports ``score`` (0–100, or ``None`` = unknown), ``confidence`` (0–1),
``contributors`` (finding ids) and a human ``rationale``. Unknown is never reported as 0.

Formulas
========

``malicious_risk``
    The v1 fused score from :func:`app.analysis.scoring.score`:
    ``rule_score`` (vulnerability/secret/container findings excluded; primary codes at full
    weight, support weights capped at 9, saturation 22) fused with ``ml_score`` by
    ``SCORE_FUSION``. It is additionally clamped to ``≥ rule_score`` so the model can never
    lower a deterministic score.

``vulnerability_risk`` (per vulnerability, worst one wins)
    ``base = round_half_up(cvss_score × 10)`` when a CVSS base score in [0, 10] is known,
    otherwise a severity bucket: critical 90, high 70, medium 45, low 20; an unknown
    severity is treated as medium (45) so a known-but-unrated vulnerability is never zero.
    Then ``KEV listed → max(base, 90)``; ``EPSS ≥ 0.5 → base + 10``; capped at 100.
    Withdrawn advisories are ignored. With no vulnerabilities the score is 0 only when
    intelligence status is ``ok``; for any other status it is ``None`` (unknown).

``final_score``
    ``max(malicious_risk, vulnerability_risk or 0)``, then the **critical high-confidence
    floor**: if any finding has severity ``critical`` and confidence ≥ 0.9 and its category
    is one of ioc, malicious_behavior, attack_chain, install_time_execution,
    credential_access, obfuscation — or its code is ``HASH_MISMATCH`` — then
    ``final_score = max(final_score, 80)``. The floor is applied after fusion, so ML output
    can never pull a floored score below 80.

``severity``
    v1 bands on ``final_score``: ≥80 critical, ≥60 high, ≥35 medium, ≥15 low, else info.

Dimensions
==========

* ``behavioral`` / ``provenance`` / ``reputation`` / ``dependency`` / ``integrity`` —
  the rule-score formula applied to the findings whose taxonomy dimension matches.
  With no contributing findings the score is 0 when an analyzer that examines that
  dimension ran successfully (``DIMENSION_ANALYZERS``) and ``None`` otherwise.
  Confidence is the weight-weighted mean confidence of the contributors; with no
  contributors it is 0.5 ("examined, nothing found" is only moderate evidence of absence),
  reduced to 0.25 when the analysis was incomplete (``ANALYZER_ERROR`` / ``FETCH_FAILED``).
* ``vulnerability`` — ``vulnerability_risk`` (confidence 0.9 with status ok, 0.6 otherwise,
  0 when unknown).
* ``exploitability`` — worst of: 100 for a KEV-listed vulnerability, ``round(EPSS × 100)``;
  0 when intel is ok and there are no vulnerabilities; ``None`` when unknown — including when
  vulnerabilities are known but none has a KEV listing or an EPSS value (a missing value usually
  means a source failed or the advisory has no CVE alias, not "not exploitable"). When the scan's
  intelligence was not fully ok and the KEV source did not report ``ok``, an EPSS-based score is
  a lower bound: confidence 0.5 and the rationale says so.
* ``anomaly`` — ``round(anomaly_score × 100)`` from the IsolationForest novelty score when
  the model is available, else ``None``. Confidence 0.4 (unsupervised, uncalibrated).
* ``blast_radius`` — ``round(blast_radius × 100)`` from project context (fraction 0–1),
  only when a project dependency graph supplied one; otherwise ``None``.

Top-level ``confidence`` is the confidence of whichever component determined
``final_score`` (floor-triggering findings, the vulnerability dimension, the ML model (0.6)
or the rule-score contributors), capped at 0.5 when analysis was incomplete.

All functions here are pure and deterministic for identical inputs.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.analysis import scoring, taxonomy
from app.analysis.findings import Category, Finding, Severity, sort_key
from app.analysis.signals import Code
from app.analysis.taxonomy import Dimension

METHOD = "warden-risk-2.0"

DIMENSIONS: tuple[str, ...] = (
    "behavioral", "vulnerability", "provenance", "reputation", "dependency",
    "integrity", "anomaly", "exploitability", "blast_radius",
)

FLOOR_SCORE = 80
FLOOR_MIN_CONFIDENCE = 0.9
FLOOR_CATEGORIES = frozenset({
    Category.IOC.value,
    Category.MALICIOUS_BEHAVIOR.value,
    Category.ATTACK_CHAIN.value,
    Category.INSTALL_TIME.value,
    Category.CREDENTIAL_ACCESS.value,
    Category.OBFUSCATION.value,
})
# Integrity findings trigger the floor only for a verified digest mismatch.
FLOOR_CODES = frozenset({Code.HASH_MISMATCH})

SEVERITY_BUCKET_SCORES = {"critical": 90, "high": 70, "medium": 45, "low": 20}
UNKNOWN_SEVERITY_SCORE = 45
KEV_MINIMUM = 90
EPSS_BOOST_THRESHOLD = 0.5
EPSS_BOOST = 10

VULNERABILITY_CODES = frozenset({Code.KNOWN_VULNERABILITY, Code.KNOWN_EXPLOITED_VULNERABILITY})
INCOMPLETE_CODES = frozenset({Code.ANALYZER_ERROR, Code.FETCH_FAILED})
# Analyzer names whose successful run means intelligence was consulted.
VULNERABILITY_ANALYZER_NAMES = frozenset({"vulnerability"})
# Analyzers whose successful run means a dimension was examined (a zero score is then
# "examined, nothing found" rather than "unknown").
DIMENSION_ANALYZERS: dict[str, frozenset[str]] = {
    Dimension.BEHAVIORAL: frozenset({
        "static_code", "install_script", "install_vectors", "obfuscation", "typosquat", "ioc", "yara_scan",
        "semgrep_scan",
    }),
    Dimension.REPUTATION: frozenset({"metadata"}),
    Dimension.PROVENANCE: frozenset({"provenance"}),
    Dimension.DEPENDENCY: frozenset({"dependency_confusion"}),
    Dimension.INTEGRITY: frozenset({"inventory"}),
    Dimension.SECRET: frozenset({"secrets"}),
}
_OK_INTEL = "ok"
# Source name of the CISA KEV feed in ``intel_status["sources"]`` (app.intel.models.SOURCE_KEV).
KEV_SOURCE = "cisa-kev"


@dataclass
class DimensionScore:
    score: int | None
    confidence: float
    contributors: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "contributors": list(self.contributors),
            "rationale": self.rationale,
        }


@dataclass
class RiskBreakdown:
    final_score: int
    severity: str
    confidence: float
    malicious_risk: int
    rule_score: int
    ml_score: int
    vulnerability_risk: int | None
    dimensions: dict[str, DimensionScore]
    floors_applied: list[dict]
    # Not part of the serialised ``risk`` dict, but needed by the orchestrator.
    ml_available: bool = False
    anomaly_score: float = 0.0
    features: dict = field(default_factory=dict)
    rule_contributions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": METHOD,
            "final_score": self.final_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "malicious_risk": self.malicious_risk,
            "rule_score": self.rule_score,
            "ml_score": self.ml_score,
            "vulnerability_risk": self.vulnerability_risk,
            "dimensions": {name: self.dimensions[name].to_dict() for name in DIMENSIONS},
            "floors_applied": [dict(f) for f in self.floors_applied],
        }


# --------------------------------------------------------------------------- helpers
def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _round_half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


def _category(f: Finding) -> str:
    if f.category:
        return str(f.category)
    info = taxonomy.get(f.code)
    return info.category if info else Category.OTHER.value


def _ordered_ids(findings: Iterable[Finding]) -> list[str]:
    """Finding ids, most important first, de-duplicated, deterministic."""
    ordered = sorted(findings, key=lambda f: (sort_key(f), f.finding_id))
    seen: set[str] = set()
    out: list[str] = []
    for f in ordered:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            out.append(f.finding_id)
    return out


def _weighted_confidence(findings: Sequence[Finding]) -> float:
    weights = [max(0.0, f.weight) for f in findings]
    total = sum(weights)
    if total > 0:
        return round(sum(f.confidence * w for f, w in zip(findings, weights)) / total, 2)
    return round(sum(f.confidence for f in findings) / len(findings), 2) if findings else 0.0


def _successful_runs(analyzer_runs: Sequence[Mapping[str, Any]] | None) -> set[str] | None:
    if analyzer_runs is None:
        return None
    return {str(r.get("name")) for r in analyzer_runs if r.get("status") == "ok"}


# --------------------------------------------------------------------------- vulnerabilities
def extract_vulnerabilities(findings: Iterable[Finding]) -> list[dict]:
    """Vulnerability records from ``KNOWN_(EXPLOITED_)VULNERABILITY`` findings.

    Reads ``evidence["vulnerability"]`` (a ``Vulnerability.to_dict()``), de-duplicates by
    ``id`` (first occurrence wins, upgraded to a KEV-flagged record if one appears) and
    marks records from a ``KNOWN_EXPLOITED_VULNERABILITY`` finding as ``kev: true``, since
    that finding code itself asserts the KEV listing. Findings without a usable record
    (missing dict or id) are skipped rather than invented.
    """
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for f in findings:
        if f.code not in VULNERABILITY_CODES:
            continue
        record = f.evidence.get("vulnerability") if isinstance(f.evidence, dict) else None
        if not isinstance(record, dict) or not record.get("id"):
            continue
        record = dict(record)
        if f.code == Code.KNOWN_EXPLOITED_VULNERABILITY and not record.get("kev"):
            record["kev"] = True
        vid = str(record["id"])
        if vid not in by_id:
            by_id[vid] = record
            order.append(vid)
        elif record.get("kev") and not by_id[vid].get("kev"):
            by_id[vid] = record
    return [by_id[v] for v in order]


def derive_intel_status(
    findings: Iterable[Finding],
    analyzer_runs: Sequence[Mapping[str, Any]] | None = None,
    *,
    intel_requested: bool = True,
) -> dict[str, Any]:
    """Vulnerability-intelligence status for a scan.

    * ``INTEL_UNAVAILABLE`` findings win: status from ``evidence["status"]`` (worst of
      unavailable > partial > disabled), sources merged from ``evidence["sources"]``.
    * ``intel_requested=False`` (the scan switched intelligence off) with no vulnerability
      findings → ``not_run``. An analyzer that honours the switch returns no findings and a
      successful run; that must read as "not consulted", never as "ok, no vulnerabilities".
    * Otherwise the vulnerability analyzer's run decides: ``ok`` → ``{"status": "ok"}``;
      skipped → ``not_run`` with the skip reason; unavailable (its ``availability()``
      reported intelligence switched off by configuration) → ``disabled``; error/timeout →
      ``unavailable``.
    * No vulnerability analyzer in ``analyzer_runs`` → ``{"status": "not_run"}``.
    * Without ``analyzer_runs`` (direct callers), vulnerability findings imply ``ok``.
    """
    findings = list(findings)
    unavailable = [f for f in findings if f.code == Code.INTEL_UNAVAILABLE]
    if unavailable:
        sources: dict[str, Any] = {}
        statuses: list[str] = []
        for f in unavailable:
            src = f.evidence.get("sources")
            if isinstance(src, dict):
                sources.update(src)
            statuses.append(str(f.evidence.get("status") or "unavailable").lower())
        status = "unavailable"
        for candidate in ("unavailable", "partial", "disabled"):
            if candidate in statuses:
                status = candidate
                break
        return {"status": status, "sources": sources, "finding_ids": _ordered_ids(unavailable)}

    has_vulnerabilities = any(f.code in VULNERABILITY_CODES for f in findings)
    if not intel_requested and not has_vulnerabilities:
        return {"status": "not_run", "reason": "disabled in scan options"}

    if analyzer_runs is None:
        return {"status": _OK_INTEL, "sources": {}} if has_vulnerabilities else {"status": "not_run"}

    runs = [r for r in analyzer_runs if str(r.get("name")) in VULNERABILITY_ANALYZER_NAMES]
    if not runs:
        return {"status": "not_run"}
    run = runs[0]
    status = run.get("status")
    if status == "ok":
        return {"status": _OK_INTEL, "sources": {}}
    if status == "skipped":
        return {"status": "not_run", "reason": run.get("detail")}
    if status == "unavailable":
        return {"status": "disabled", "reason": run.get("detail")}
    return {"status": "unavailable", "reason": f"analyzer_{status}"}


def vulnerability_score(vuln: Mapping[str, Any]) -> int:
    """Score one vulnerability record (formula in the module docstring)."""
    cvss = _float(vuln.get("cvss_score"))
    if cvss is not None and 0.0 <= cvss <= 10.0:
        base = _round_half_up(cvss * 10.0)
    else:
        severity = str(vuln.get("severity") or "").strip().lower()
        base = SEVERITY_BUCKET_SCORES.get(severity, UNKNOWN_SEVERITY_SCORE)
    if vuln.get("kev") is True:
        base = max(base, KEV_MINIMUM)
    epss = _float(vuln.get("epss_score"))
    if epss is not None and epss >= EPSS_BOOST_THRESHOLD:
        base += EPSS_BOOST
    return int(max(0, min(100, base)))


def _live(vulns: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [v for v in vulns if not v.get("withdrawn")]


def _vulnerability_dimension(
    vulns: list[Mapping[str, Any]], status: str, findings: list[Finding]
) -> DimensionScore:
    contributors = _ordered_ids(f for f in findings if f.code in VULNERABILITY_CODES)
    if not vulns:
        if status == _OK_INTEL:
            return DimensionScore(0, 0.9, contributors, "Vulnerability intelligence consulted; none known.")
        return DimensionScore(None, 0.0, contributors, f"Vulnerability status unknown (intelligence {status}).")
    scored = sorted(((vulnerability_score(v), str(v.get("id"))) for v in vulns), key=lambda t: (-t[0], t[1]))
    worst_score, worst_id = scored[0]
    worst = next(v for v in vulns if str(v.get("id")) == worst_id)
    details = []
    cvss = _float(worst.get("cvss_score"))
    if cvss is not None:
        details.append(f"CVSS {cvss:g}")
    else:
        details.append(f"severity {worst.get('severity') or 'unknown'}")
    if worst.get("kev") is True:
        details.append("CISA KEV")
    epss = _float(worst.get("epss_score"))
    if epss is not None:
        details.append(f"EPSS {epss:.2f}")
    noun = "vulnerability" if len(vulns) == 1 else "vulnerabilities"
    rationale = f"Worst of {len(vulns)} known {noun}: {worst_id} ({', '.join(details)})."
    confidence = 0.9 if status == _OK_INTEL else 0.6
    return DimensionScore(worst_score, confidence, contributors, rationale)


def _exploitability_dimension(
    vulns: list[Mapping[str, Any]], status: str, findings: list[Finding], sources: Mapping[str, Any] | None = None
) -> DimensionScore:
    contributors = _ordered_ids(f for f in findings if f.code in VULNERABILITY_CODES)
    if not vulns:
        if status == _OK_INTEL:
            return DimensionScore(0, 0.8, [], "No known vulnerabilities to exploit.")
        return DimensionScore(None, 0.0, [], f"Exploitability unknown (intelligence {status}).")
    best = 0
    signals_known = False
    reasons: list[str] = []
    for v in sorted(vulns, key=lambda item: str(item.get("id"))):
        if v.get("kev") is True:
            signals_known = True
            best = max(best, 100)
            reasons.append(f"{v.get('id')} is CISA KEV listed")
        epss = _float(v.get("epss_score"))
        if epss is not None and 0.0 <= epss <= 1.0:
            signals_known = True
            best = max(best, _round_half_up(epss * 100.0))
    if not signals_known:
        return DimensionScore(None, 0.0, contributors, f"Exploitability unknown: no KEV listing or EPSS data for "
                                                        f"the known vulnerabilities (intelligence {status}).")
    if reasons:
        return DimensionScore(best, 0.8, contributors, "; ".join(reasons[:3]))
    kev_status = str((sources or {}).get(KEV_SOURCE, "")).lower()
    if status != _OK_INTEL and kev_status != _OK_INTEL:
        return DimensionScore(best, 0.5, contributors, "Highest EPSS probability across known vulnerabilities; KEV "
                                                        "status unknown, so this is a lower bound.")
    return DimensionScore(best, 0.8, contributors, "Highest EPSS probability across known vulnerabilities.")


# --------------------------------------------------------------------------- rule dimensions
def _rule_dimension(
    dimension: str,
    findings: list[Finding],
    successful: set[str] | None,
    *,
    incomplete: bool,
    fallback_examined: bool,
) -> DimensionScore:
    members = [f for f in findings if taxonomy.dimension_for(f.code) == dimension]
    if members:
        score = scoring.compute_rule_score(members)
        codes = sorted({f.code for f in members})
        return DimensionScore(
            score, _weighted_confidence(members), _ordered_ids(members),
            f"{len(members)} finding(s): {', '.join(codes[:6])}{'…' if len(codes) > 6 else ''}.",
        )
    if successful is None:
        examined = fallback_examined
    else:
        examined = bool(successful & DIMENSION_ANALYZERS.get(dimension, frozenset()))
    if not examined:
        return DimensionScore(None, 0.0, [], "Not examined by any analyzer in this scan.")
    return DimensionScore(0, 0.25 if incomplete else 0.5, [], "Examined; no contributing findings.")


def _anomaly_dimension(result: scoring.RiskResult) -> DimensionScore:
    if not result.ml_available:
        return DimensionScore(None, 0.0, [], "ML model unavailable.")
    anomaly = _float(result.anomaly_score) or 0.0
    return DimensionScore(
        _round_half_up(max(0.0, min(1.0, anomaly)) * 100.0), 0.4, [],
        "IsolationForest novelty of the feature vector (unsupervised, uncalibrated).",
    )


def _blast_radius_dimension(project_context: Mapping[str, Any] | None) -> DimensionScore:
    raw = project_context.get("blast_radius") if isinstance(project_context, Mapping) else None
    # Only a real number counts: a string such as "0.4" is rejected rather than coerced.
    value = _float(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else None
    if value is None or not 0.0 <= value <= 1.0:
        return DimensionScore(None, 0.0, [], "No project dependency context supplied.")
    dependents = project_context.get("transitive_dependents")
    extra = f" ({dependents} transitive dependents)" if isinstance(dependents, int) else ""
    return DimensionScore(
        _round_half_up(value * 100.0), 0.8, [],
        f"{value:.0%} of project packages transitively depend on this package{extra}.",
    )


def _floor_triggers(findings: Iterable[Finding]) -> list[Finding]:
    return [
        f for f in findings
        if f.severity == Severity.critical
        and f.confidence >= FLOOR_MIN_CONFIDENCE
        and (_category(f) in FLOOR_CATEGORIES or f.code in FLOOR_CODES)
    ]


# --------------------------------------------------------------------------- entry point
def assess(
    findings: Iterable[Finding],
    ctx: Any = None,
    *,
    vulnerabilities: Sequence[Mapping[str, Any]] | None = None,
    intel_status: Mapping[str, Any] | None = None,
    analyzer_runs: Sequence[Mapping[str, Any]] | None = None,
    project_context: Mapping[str, Any] | None = None,
) -> RiskBreakdown:
    """Compute the full risk breakdown for one package scan.

    ``vulnerabilities`` / ``intel_status`` default to values derived from ``findings``;
    ``project_context`` defaults to ``ctx.options.project_context`` when present.
    """
    findings = [f for f in findings if isinstance(f, Finding)]
    fused = scoring.score(findings, ctx)
    rule_score = int(fused.rule_score)
    ml_score = int(fused.ml_score) if fused.ml_available else 0
    malicious = int(max(rule_score, fused.risk_score))

    vulns = _live(extract_vulnerabilities(findings) if vulnerabilities is None else vulnerabilities)
    status_info = dict(intel_status) if intel_status is not None else derive_intel_status(findings, analyzer_runs)
    status = str(status_info.get("status") or "not_run")
    incomplete = any(f.code in INCOMPLETE_CODES for f in findings)
    successful = _successful_runs(analyzer_runs)

    if project_context is None:
        options = getattr(ctx, "options", None)
        project_context = getattr(options, "project_context", None)

    has_metadata = bool(getattr(ctx, "metadata", None))
    dimensions: dict[str, DimensionScore] = {
        "behavioral": _rule_dimension(Dimension.BEHAVIORAL, findings, successful,
                                      incomplete=incomplete, fallback_examined=True),
        "vulnerability": _vulnerability_dimension(vulns, status, findings),
        "provenance": _rule_dimension(Dimension.PROVENANCE, findings, successful,
                                      incomplete=incomplete, fallback_examined=False),
        "reputation": _rule_dimension(Dimension.REPUTATION, findings, successful,
                                      incomplete=incomplete, fallback_examined=has_metadata),
        "dependency": _rule_dimension(Dimension.DEPENDENCY, findings, successful,
                                      incomplete=incomplete, fallback_examined=False),
        "integrity": _rule_dimension(Dimension.INTEGRITY, findings, successful,
                                     incomplete=incomplete, fallback_examined=False),
        "anomaly": _anomaly_dimension(fused),
        "exploitability": _exploitability_dimension(vulns, status, findings,
                                                    status_info.get("sources") if isinstance(
                                                        status_info.get("sources"), Mapping) else None),
        "blast_radius": _blast_radius_dimension(project_context),
    }
    vulnerability_risk = dimensions["vulnerability"].score

    pre_floor = max(malicious, vulnerability_risk or 0)
    final = pre_floor
    floors: list[dict] = []
    triggers = _floor_triggers(findings)
    if triggers:
        final = max(final, FLOOR_SCORE)
        floors.append({
            "rule": "critical_high_confidence_finding",
            "minimum": FLOOR_SCORE,
            "previous_score": pre_floor,
            "raised": final > pre_floor,
            "codes": sorted({f.code for f in triggers}),
            "finding_ids": _ordered_ids(triggers),
        })
    final = int(max(0, min(100, final)))

    rule_members = [f for f in findings if scoring.counts_toward_rule_score(f.code) and f.weight > 0]
    if triggers and final > pre_floor:
        confidence = max(f.confidence for f in triggers)
    elif vulnerability_risk is not None and vulnerability_risk > 0 and vulnerability_risk >= malicious:
        confidence = dimensions["vulnerability"].confidence
    elif fused.ml_available and fused.risk_score > rule_score:
        confidence = 0.6
    elif rule_members:
        confidence = _weighted_confidence(rule_members)
    else:
        confidence = 0.5
    if incomplete:
        confidence = min(confidence, 0.5)

    return RiskBreakdown(
        final_score=final,
        severity=scoring.severity_for(final).value,
        confidence=round(float(confidence), 2),
        malicious_risk=malicious,
        rule_score=rule_score,
        ml_score=ml_score,
        vulnerability_risk=vulnerability_risk,
        dimensions=dimensions,
        floors_applied=floors,
        ml_available=bool(fused.ml_available),
        anomaly_score=float(fused.anomaly_score or 0.0),
        features=fused.features,
        rule_contributions=scoring.rule_contributions(findings),
    )


__all__ = [
    "DIMENSIONS",
    "METHOD",
    "DimensionScore",
    "RiskBreakdown",
    "assess",
    "derive_intel_status",
    "extract_vulnerabilities",
    "vulnerability_score",
]
