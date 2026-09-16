"""Hybrid malicious-risk scoring (v1 rule/ML fusion, preserved for Warden X).

Two independent scores are produced and fused:

* **rule_score** — a transparent, deterministic weighted sum of finding weights, normalised
  to 0–100. Fully explainable; needs no model.
* **ml_score** — the supervised model's malicious probability (with an unsupervised
  novelty bump), 0–100.

Rule score formula::

    counted  = findings whose taxonomy dimension is NOT vulnerability, secret or container
    primary  = Σ max(0, weight) over counted findings with a primary code
    support  = Σ max(0, weight) over the remaining counted findings
    rule     = int(min(100, (primary + min(support, 9)) / 22 × 100))

* The primary set is the v1 primary codes ∪ ``taxonomy.primary_codes()``.
* Vulnerability, secret and container findings are excluded: *being vulnerable* or
  *containing a leaked credential* is not evidence of *malicious behaviour* and is scored by
  its own risk dimension instead (see :mod:`app.analysis.risk`).
* Pipeline and integrity findings do count (fail closed): ``FETCH_FAILED`` (3.0) and
  ``ANALYZER_ERROR`` (2.0) raise the score because analysis was incomplete; info-level
  status findings (``TOOL_UNAVAILABLE``, ``INTEL_UNAVAILABLE``) carry weight 0.
* Negative weights are clamped to 0 so no finding can *lower* the score.

Fusion (``settings.SCORE_FUSION``):

* ``max`` (default) — ``risk = max(rule, ml)``: either subsystem may raise the alarm.
* ``mean`` — ``risk = max(rule, round((rule + ml) / 2))``: the mean may raise a low rule
  score, but the ML model can never pull a deterministic rule score *down*.
* model unavailable — ``risk = rule``.

The final severity is derived from the fused score with the v1 bands.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.analysis import taxonomy
from app.analysis.features import build_features
from app.analysis.model_store import get_model_store
from app.analysis.signals import Code, Severity, Signal
from app.analysis.taxonomy import Dimension
from app.core import metrics
from app.core.config import settings

# The rule score normaliser: the weighted-sum value that maps to 100. Calibrated so a
# single strong indicator (install-time exec ~12, IOC ~12, typosquat ~10) lands in the
# high band, while a benign library's incidental low-weight capabilities stay in low/info.
_RULE_SATURATION = 22.0
RULE_SATURATION = _RULE_SATURATION

# v1 primary indicators: any one of these is, on its own, a strong sign of malice and is
# allowed to drive the score into the high/critical band at full weight.
_PRIMARY_CODES = {
    Code.INSTALL_HOOK_EXEC, Code.IOC_MATCH, Code.TYPOSQUAT, Code.ENCODED_EXEC,
    Code.OBFUSCATION, Code.ENV_HARVEST, Code.FS_SENSITIVE,
}
# Supporting signals (network egress, subprocessing, dynamic exec, dangerous imports,
# provenance). Legitimate complex libraries accumulate many of these, so their *combined*
# contribution is capped: they raise suspicion to "medium" but cannot alone reach "high".
# This is the key control that keeps precision high on large benign packages (e.g. numpy).
_SUPPORT_CAP = 9.0

# Above this rule score the deterministic layer has real evidence, and the model is allowed
# to raise the verdict freely. Below it, the model may add at most ML_ESCALATION_MARGIN.
ML_TRUSTED_RULE_SCORE = 35
ML_ESCALATION_MARGIN = 25
SUPPORT_CAP = _SUPPORT_CAP

# Dimensions scored elsewhere and excluded from the behavioural rule score.
EXCLUDED_DIMENSIONS = frozenset({Dimension.VULNERABILITY, Dimension.SECRET, Dimension.CONTAINER})


@dataclass
class RiskResult:
    rule_score: int
    ml_score: int
    risk_score: int
    severity: Severity
    features: dict
    anomaly_score: float
    ml_available: bool


def severity_for(score: int | float) -> Severity:
    """v1 severity bands: ≥80 critical, ≥60 high, ≥35 medium, ≥15 low, else info."""
    if score >= 80:
        return Severity.critical
    if score >= 60:
        return Severity.high
    if score >= 35:
        return Severity.medium
    if score >= 15:
        return Severity.low
    return Severity.info


_severity_for = severity_for  # v1 private name


def primary_codes() -> frozenset[str]:
    """v1 primary codes ∪ taxonomy primary codes (evaluated at call time)."""
    return frozenset(_PRIMARY_CODES) | taxonomy.primary_codes()


def counts_toward_rule_score(code: str) -> bool:
    return taxonomy.dimension_for(code) not in EXCLUDED_DIMENSIONS


def _code_weight(signal: Signal | Mapping[str, Any]) -> tuple[str, float]:
    """(code, clamped weight) for a Finding/Signal or a legacy signal dict."""
    if isinstance(signal, Mapping):
        code = str(signal.get("code", ""))
        try:
            weight = float(signal.get("weight", 0.0) or 0.0)
        except (TypeError, ValueError):
            weight = 0.0
    else:
        code, weight = signal.code, float(signal.weight)
    if math.isnan(weight):
        weight = 0.0
    return code, max(0.0, weight)


def _partition(signals: Iterable[Signal | Mapping[str, Any]]) -> tuple[list, list]:
    primary_set = primary_codes()
    primary: list[tuple[Any, str, float]] = []
    support: list[tuple[Any, str, float]] = []
    for s in signals:
        code, weight = _code_weight(s)
        if not counts_toward_rule_score(code):
            continue
        (primary if code in primary_set else support).append((s, code, weight))
    return primary, support


def compute_rule_score(signals: Iterable[Signal | Mapping[str, Any]]) -> int:
    """Transparent 0–100 rule score (formula in the module docstring)."""
    primary, support = _partition(signals)
    primary_total = sum(w for _, _, w in primary)
    support_total = sum(w for _, _, w in support)
    total = primary_total + min(support_total, _SUPPORT_CAP)
    return int(min(100.0, (total / _RULE_SATURATION) * 100.0))


def rule_contributions(signals: Iterable[Signal | Mapping[str, Any]]) -> list[dict]:
    """Per-finding contribution (in score points) to the rule score, largest first.

    Primary findings contribute ``weight / 22 × 100``. Support findings share the support
    cap proportionally: each contributes ``weight × min(1, 9 / Σ support) / 22 × 100``.
    Points are *pre-clamp*: they can sum to more than 100 when the score saturates.
    """
    primary, support = _partition(signals)
    support_total = sum(w for _, _, w in support)
    scale = min(1.0, _SUPPORT_CAP / support_total) if support_total > 0 else 1.0
    rows: list[dict] = []
    for kind, items, factor in (("primary", primary, 1.0), ("support", support, scale)):
        for s, code, weight in items:
            if weight <= 0:
                continue
            finding_id = s.get("finding_id") if isinstance(s, Mapping) else s.finding_id
            rows.append({
                "finding_id": finding_id,
                "code": code,
                "kind": kind,
                "weight": weight,
                "points": round(weight * factor / _RULE_SATURATION * 100.0, 2),
            })
    rows.sort(key=lambda r: (-r["points"], r["code"], str(r["finding_id"])))
    return rows


def fuse(rule_score: int, ml_score: int, ml_available: bool, mode: str | None = None) -> int:
    """Fuse rule and ML scores; the result is never below ``rule_score``.

    The model may sharpen a verdict the deterministic rules already support, but it may not
    create one on its own. Its training distribution is mostly synthetic, and measurements on
    real packages showed it scoring ordinary libraries (whose only traits were a network
    import and test-fixture credentials) as malicious. So when the rules see little
    (``rule_score`` below :data:`ML_TRUSTED_RULE_SCORE`) the model can add at most
    :data:`ML_ESCALATION_MARGIN` points. That keeps a model-only opinion inside the
    medium band, where it prompts review rather than blocking a build, while leaving the
    model free to escalate once real evidence exists.
    """
    if not ml_available:
        return int(max(0, min(100, rule_score)))
    if (mode or settings.SCORE_FUSION) == "mean":
        risk = max(rule_score, round((rule_score + ml_score) / 2))
    else:  # "max" — conservative default
        risk = max(rule_score, ml_score)
    if rule_score < ML_TRUSTED_RULE_SCORE:
        risk = min(risk, rule_score + ML_ESCALATION_MARGIN)
    return int(max(0, min(100, risk)))


def score(signals: list[Signal], ctx) -> RiskResult:
    """Build features, compute the rule score, run the model (if any) and fuse."""
    features = build_features(signals, ctx)
    rule_score = compute_rule_score(signals)

    model = get_model_store()
    if model.available:
        # Only real inference is timed; the unavailable-model fallback would skew the histogram.
        with metrics.time_ml():
            ml_score, anomaly = model.predict(features)
    else:
        ml_score, anomaly = model.predict(features)

    risk = fuse(rule_score, int(ml_score), model.available)
    return RiskResult(
        rule_score=rule_score,
        ml_score=ml_score,
        risk_score=risk,
        severity=severity_for(risk),
        features=features,
        anomaly_score=anomaly,
        ml_available=model.available,
    )
