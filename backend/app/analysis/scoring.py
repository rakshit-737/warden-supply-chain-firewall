"""Hybrid risk scoring.

Two independent scores are produced and fused:

* **rule_score** — a transparent, deterministic weighted sum of signal weights, normalised
  to 0–100. Fully explainable; needs no model.
* **ml_score** — the supervised model's malicious probability (with an unsupervised
  novelty bump), 0–100.

Fusion is ``max`` by default: a conservative "either subsystem may raise the alarm" rule,
so the model can never silently suppress a strong rule signal and vice-versa. The final
severity is derived from the fused risk score.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.features import build_features
from app.analysis.model_store import get_model_store
from app.analysis.signals import Code, Severity, Signal
from app.core.config import settings

# The rule score normaliser: the weighted-sum value that maps to 100. Calibrated so a
# single strong indicator (install-time exec ~12, IOC ~12, typosquat ~10) lands in the
# high band, while a benign library's incidental low-weight capabilities stay in low/info.
_RULE_SATURATION = 22.0

# Primary indicators: any one of these is, on its own, a strong sign of malice and is
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


@dataclass
class RiskResult:
    rule_score: int
    ml_score: int
    risk_score: int
    severity: Severity
    features: dict
    anomaly_score: float
    ml_available: bool


def _severity_for(score: int) -> Severity:
    if score >= 80:
        return Severity.critical
    if score >= 60:
        return Severity.high
    if score >= 35:
        return Severity.medium
    if score >= 15:
        return Severity.low
    return Severity.info


def compute_rule_score(signals: list[Signal]) -> int:
    primary = sum(s.weight for s in signals if s.code in _PRIMARY_CODES)
    support = sum(s.weight for s in signals if s.code not in _PRIMARY_CODES)
    total = primary + min(support, _SUPPORT_CAP)
    return int(min(100.0, (total / _RULE_SATURATION) * 100.0))


def score(signals: list[Signal], ctx) -> RiskResult:
    features = build_features(signals, ctx)
    rule_score = compute_rule_score(signals)

    model = get_model_store()
    ml_score, anomaly = model.predict(features)

    if not model.available:
        risk = rule_score
    elif settings.SCORE_FUSION == "mean":
        risk = round((rule_score + ml_score) / 2)
    else:  # "max" — conservative default
        risk = max(rule_score, ml_score)

    risk = int(max(0, min(100, risk)))
    return RiskResult(
        rule_score=rule_score,
        ml_score=ml_score,
        risk_score=risk,
        severity=_severity_for(risk),
        features=features,
        anomaly_score=anomaly,
        ml_available=model.available,
    )
