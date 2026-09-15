"""CVSS v3.0 / v3.1 base-score calculator.

Implements the Base metric group equations of the FIRST *Common Vulnerability Scoring
System* specifications (v3.0 section 8.1, v3.1 section 7.1)::

    ISS            = 1 - (1 - C) * (1 - I) * (1 - A)
    Impact         = 6.42 * ISS                                   (Scope Unchanged)
                   = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15 (Scope Changed)
    Exploitability = 8.22 * AV * AC * PR * UI
    BaseScore      = 0                                            if Impact <= 0
                   = Roundup(min(Impact + Exploitability, 10))        (Unchanged)
                   = Roundup(min(1.08 * (Impact + Exploitability), 10)) (Changed)

The versions differ only in ``Roundup`` for the base score:

* **v3.1** (Appendix A) defines an integer-based ``Roundup`` so that floating-point noise
  (``4.000000000000001``) cannot bump a score by 0.1. It is implemented exactly as the
  specification's pseudocode, including half-up rounding to five decimal places.
* **v3.0** defines Roundup mathematically ("the smallest number, specified to one decimal
  place, that is equal to or higher than its input"). Evaluating that definition with binary
  floats is what produced inconsistent v3.0 calculators, so v3.0 scores are computed here in
  exact rational arithmetic (``fractions.Fraction``) and are therefore spec-exact and
  platform-independent.

Vector strings are hostile-ish input (they come from third-party advisory databases), so
parsing is strict: the ``CVSS:3.x/`` prefix, every mandatory Base metric exactly once, known
Temporal/Environmental metrics with valid values, no duplicates, no unknown metrics, bounded
length. Any violation yields ``None`` — this module never raises into its callers. Only the
Base score is computed; Temporal and Environmental metrics are validated but not applied.

CVSS v4.0 (and v2) vectors are recognised by :func:`vector_version` so callers can *carry*
them, but they are deliberately not scored: v4.0 scoring is a lookup over MacroVectors, not
these equations, and a wrong number would be worse than none.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from fractions import Fraction

MAX_VECTOR_LENGTH = 256

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Base metric weights (v3.0 and v3.1 are identical), as decimal strings so the same table
# serves float and exact-rational evaluation.
_WEIGHTS: dict[str, dict[str, str]] = {
    "AV": {"N": "0.85", "A": "0.62", "L": "0.55", "P": "0.2"},
    "AC": {"L": "0.77", "H": "0.44"},
    "PR": {"N": "0.85", "L": "0.62", "H": "0.27"},  # Scope Unchanged
    "UI": {"N": "0.85", "R": "0.62"},
    "S": {"U": "0", "C": "0"},  # scope selects equations; it has no weight of its own
    "C": {"H": "0.56", "L": "0.22", "N": "0"},
    "I": {"H": "0.56", "L": "0.22", "N": "0"},
    "A": {"H": "0.56", "L": "0.22", "N": "0"},
}
_PR_SCOPE_CHANGED = {"N": "0.85", "L": "0.68", "H": "0.5"}

# Temporal and Environmental metrics: validated, not scored. X = Not Defined.
_OPTIONAL_METRICS: dict[str, frozenset[str]] = {
    "E": frozenset("XUPFH"),
    "RL": frozenset("XOTWU"),
    "RC": frozenset("XURC"),
    "CR": frozenset("XLMH"),
    "IR": frozenset("XLMH"),
    "AR": frozenset("XLMH"),
    "MAV": frozenset("XNALP"),
    "MAC": frozenset("XLH"),
    "MPR": frozenset("XNLH"),
    "MUI": frozenset("XNR"),
    "MS": frozenset("XUC"),
    "MC": frozenset("XNLH"),
    "MI": frozenset("XNLH"),
    "MA": frozenset("XNLH"),
}

# ``\Z`` (not ``$``) everywhere: ``$`` also matches before a trailing newline, which would let
# "C:H\n" through as a valid metric.
_V3_PREFIX_RE = re.compile(r"^CVSS:3\.([01])/")
_METRIC_RE = re.compile(r"^([A-Z]{1,3}):([A-Z])\Z")
_V4_RE = re.compile(r"^CVSS:4\.0/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z])*\Z")
# v2 vectors are sometimes wrapped in parentheses; ``(?(1)\))`` requires the closing one only
# when the opening one is present, so unbalanced wrappers are rejected.
_V2_RE = re.compile(
    r"^(\()?AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC](?:/[A-Za-z]{1,3}:[A-Z]{1,3})*(?(1)\))\Z"
)


@dataclass(frozen=True)
class CvssScore:
    version: str  # "3.0" | "3.1"
    vector: str
    base_score: float
    rating: str  # none | low | medium | high | critical (CVSS qualitative severity rating scale)


def roundup_v31(value: float) -> float:
    """CVSS v3.1 Appendix A ``Roundup``: smallest one-decimal number >= value, float-noise safe."""
    int_input = math.floor(value * 100000 + 0.5)  # round_to_nearest_integer (half up)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def roundup_v30_exact(value: Fraction) -> float:
    """CVSS v3.0 ``Roundup`` evaluated exactly: smallest one-decimal number >= value."""
    return math.ceil(value * 10) / 10.0


def severity_rating(score: float | None) -> str | None:
    """CVSS qualitative severity rating: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0."""
    if score is None or isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    if not math.isfinite(score) or score < 0 or score > 10:
        return None
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def vector_version(vector: object) -> str | None:
    """Recognise a CVSS vector's version ("3.1", "3.0", "4.0", "2.0") without validating it fully."""
    if not isinstance(vector, str) or len(vector) > MAX_VECTOR_LENGTH:
        return None
    v = vector.strip()
    m = _V3_PREFIX_RE.match(v)
    if m:
        return f"3.{m.group(1)}"
    if _V4_RE.match(v):
        return "4.0"
    if _V2_RE.match(v):
        return "2.0"
    return None


def parse_vector(vector: object) -> tuple[str, dict[str, str]] | None:
    """Strictly parse a CVSS v3.0/v3.1 vector into ``(version, {metric: value})`` or ``None``."""
    if not isinstance(vector, str) or len(vector) > MAX_VECTOR_LENGTH:
        return None
    v = vector.strip()
    m = _V3_PREFIX_RE.match(v)
    if not m:
        return None
    version = f"3.{m.group(1)}"
    metrics: dict[str, str] = {}
    for part in v[m.end():].split("/"):
        pm = _METRIC_RE.match(part)
        if not pm:
            return None  # empty component (e.g. trailing "/"), bad syntax, lower case, ...
        name, value = pm.group(1), pm.group(2)
        if name in metrics:
            return None  # the specification forbids repeating a metric
        if name in _WEIGHTS:
            if value not in _WEIGHTS[name]:
                return None
        elif name in _OPTIONAL_METRICS:
            if value not in _OPTIONAL_METRICS[name]:
                return None
        else:
            return None
        metrics[name] = value
    if any(name not in metrics for name in _BASE_METRICS):
        return None
    return version, metrics


def _base_score_float(m: dict[str, str]) -> float:
    w = {name: float(_WEIGHTS[name][m[name]]) for name in _BASE_METRICS if name not in ("S", "PR")}
    changed = m["S"] == "C"
    pr = float((_PR_SCOPE_CHANGED if changed else _WEIGHTS["PR"])[m["PR"]])
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup_v31(min(1.08 * (impact + exploitability), 10))
    return roundup_v31(min(impact + exploitability, 10))


def _base_score_exact(m: dict[str, str]) -> float:
    w = {name: Fraction(_WEIGHTS[name][m[name]]) for name in _BASE_METRICS if name not in ("S", "PR")}
    changed = m["S"] == "C"
    pr = Fraction((_PR_SCOPE_CHANGED if changed else _WEIGHTS["PR"])[m["PR"]])
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    if changed:
        impact = Fraction("7.52") * (iss - Fraction("0.029")) - Fraction("3.25") * (iss - Fraction("0.02")) ** 15
    else:
        impact = Fraction("6.42") * iss
    exploitability = Fraction("8.22") * w["AV"] * w["AC"] * pr * w["UI"]
    if impact <= 0:
        return 0.0
    total = Fraction("1.08") * (impact + exploitability) if changed else impact + exploitability
    return roundup_v30_exact(min(total, Fraction(10)))


def score_vector(vector: object) -> CvssScore | None:
    """Base score for a CVSS v3.0/v3.1 vector, or ``None`` if the vector is not valid v3.x."""
    parsed = parse_vector(vector)
    if parsed is None:
        return None
    version, metrics = parsed
    try:
        score = _base_score_exact(metrics) if version == "3.0" else _base_score_float(metrics)
    except (ArithmeticError, KeyError, ValueError):  # pragma: no cover - tables are exhaustive
        return None
    rating = severity_rating(score)
    if rating is None:  # pragma: no cover - equations are bounded to [0, 10]
        return None
    return CvssScore(version=version, vector=str(vector).strip(), base_score=score, rating=rating)


def base_score(vector: object) -> float | None:
    """Convenience wrapper: the base score, or ``None`` for an invalid / non-v3 vector."""
    result = score_vector(vector)
    return result.base_score if result else None
