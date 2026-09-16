"""Findings -> numeric feature vector for the behaviour model (feature set v2).

:func:`build_features` is the single reduction from a scan's findings (plus a few registry
metadata values) to a fixed-order numeric vector. Serving calls it directly; the synthetic
training generator (``ml/generate_dataset.py``) samples vectors in the value domains
documented in :data:`FEATURE_DESCRIPTIONS`; and the model store refuses an artifact trained on
a different feature layout (:func:`feature_schema_hash`), so a model is only ever served with
the layout it was trained on.

Versioning
----------
* :data:`FEATURE_ORDER` is append-only: the 16 v1 features keep their names and positions and
  feature set v2 appends 20 features for the phase-2 finding codes.
* :data:`FEATURE_SET_VERSION` is bumped whenever names, order *or semantics* change.
* :func:`feature_schema_hash` covers names, order and version.

Semantics
---------
* v1 features keep their v1 meaning, with guards for hostile values: non-numeric or
  non-finite evidence reads as 0 and counts are capped. One deliberate change:
  ``dynamic_exec`` also counts one-finding-per-call-site analyzers (see its description).
* v2 *strength* features are the highest ``confidence`` among findings with the feature's
  code, so analyzer uncertainty reaches the model. A finding whose ``evidence["context"]`` is
  ``"test"`` counts at half strength: behaviour confined to test files is weaker evidence than
  the same behaviour at install, import or run time.
* v2 *count* features (``attack_chain_count``, ``secrets_count``) are context-weighted counts
  with caps.
* Per-code truncation summaries (a finding whose evidence carries an integer ``omitted`` count,
  emitted when an analyzer caps its findings) are not observations and are ignored by v2
  features.
* Vulnerability findings are deliberately **not** features: the model scores *behaviour*;
  known vulnerabilities are scored by the separate vulnerability risk dimension.

Drift helpers
-------------
:func:`reference_bins`, :func:`bin_proportions` and :func:`population_stability_index`
summarise a feature's training distribution with quantile bins and compare a recent sample
against it (``GET /ml/drift``). All helpers are pure and deterministic.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from app.analysis.signals import Code, Signal

if TYPE_CHECKING:  # pragma: no cover - typing only (keeps this module light for ml/ tooling)
    from app.analysis.analyzers.base import PackageContext

FEATURE_SET_VERSION = "2"

_V1_FEATURES: tuple[str, ...] = (
    "install_hook_exec",
    "network_egress",
    "subprocess_exec",
    "dynamic_exec",
    "obfuscation_score",
    "encoded_exec",
    "env_harvest",
    "fs_sensitive_write",
    "dangerous_import_count",
    "typosquat_distance",
    "ioc_hits",
    "package_age_days",
    "maintainer_count",
    "has_repo_url",
    "release_count",
    "new_package",
)

_V2_FEATURES: tuple[str, ...] = (
    "attack_chain_count",
    "max_chain_confidence",
    "pth_startup_hook",
    "build_backend_hook",
    "persistence",
    "browser_credential_access",
    "suspicious_download",
    "dns_exfiltration",
    "shell_invocation",
    "reflection_abuse",
    "layered_encoding",
    "string_reconstruction",
    "secrets_count",
    "binary_executable",
    "nested_archive",
    "hash_mismatch",
    "dependency_confusion",
    "dormant_revival",
    "maintainer_changed",
    "yanked_release",
)

# Canonical feature order. Never reorder or rename; append only, bump FEATURE_SET_VERSION, retrain.
FEATURE_ORDER: list[str] = [*_V1_FEATURES, *_V2_FEATURES]

# v2 strength features: feature name -> finding code.
STRENGTH_FEATURES: dict[str, str] = {
    "pth_startup_hook": Code.PTH_STARTUP_HOOK,
    "build_backend_hook": Code.BUILD_BACKEND_HOOK,
    "persistence": Code.PERSISTENCE,
    "browser_credential_access": Code.BROWSER_CREDENTIAL_ACCESS,
    "suspicious_download": Code.SUSPICIOUS_DOWNLOAD,
    "dns_exfiltration": Code.DNS_EXFILTRATION,
    "shell_invocation": Code.SHELL_INVOCATION,
    "reflection_abuse": Code.REFLECTION_ABUSE,
    "layered_encoding": Code.LAYERED_ENCODING,
    "string_reconstruction": Code.STRING_RECONSTRUCTION,
    "binary_executable": Code.BINARY_EXECUTABLE,
    "nested_archive": Code.NESTED_ARCHIVE,
    "hash_mismatch": Code.HASH_MISMATCH,
    "dependency_confusion": Code.DEPENDENCY_CONFUSION,
    "dormant_revival": Code.DORMANT_REVIVAL,
    "maintainer_changed": Code.MAINTAINER_CHANGED,
    "yanked_release": Code.YANKED_RELEASE,
}

# Evidence contexts whose findings are discounted (multiplier applied to confidence / count).
CONTEXT_DISCOUNTS: dict[str, float] = {"test": 0.5}

MAX_DYNAMIC_EXEC = 5.0
MAX_DANGEROUS_IMPORTS = 50.0
MAX_IOC_HITS = 10.0
MAX_MAINTAINERS = 50.0
MAX_RECENT_RELEASES = 1000.0
MAX_ATTACK_CHAINS = 5.0
MAX_SECRETS = 10.0
# Bound on findings examined per scan (the orchestrator already caps findings per analyzer).
MAX_FINDINGS_CONSIDERED = 20000
AGE_HORIZON_DAYS = 365


def _strength_description(code: str) -> str:
    return f"highest confidence among {code} findings, halved in test-file context (0..1)"


FEATURE_DESCRIPTIONS: dict[str, str] = {
    "install_hook_exec": "1 if an INSTALL_HOOK_EXEC finding is present, else 0",
    "network_egress": "1 if a NETWORK_EGRESS finding is present, else 0",
    "subprocess_exec": "1 if a SUBPROCESS_EXEC finding is present, else 0",
    "dynamic_exec": "DYNAMIC_EXEC call sites: max(len(evidence.calls) of the highest-weight finding, number of "
                    "DYNAMIC_EXEC findings), capped at 5",
    "obfuscation_score": "evidence.obfuscation_score of the highest-weight OBFUSCATION finding, clamped to 0..1",
    "encoded_exec": "1 if an ENCODED_EXEC finding is present, else 0",
    "env_harvest": "1 if an ENV_HARVEST finding is present, else 0",
    "fs_sensitive_write": "1 if an FS_SENSITIVE finding is present, else 0",
    "dangerous_import_count": "len(evidence.modules) of the highest-weight DANGEROUS_IMPORT finding, capped at 50",
    "typosquat_distance": "name proximity from TYPOSQUAT evidence.distance: 1.0 for distance <= 1, 0.6 for 2, "
                          "0.4 otherwise; 0 without a TYPOSQUAT finding",
    "ioc_hits": "len(evidence.matches) of the highest-weight IOC_MATCH finding (at least 1), capped at 10",
    "package_age_days": "release recency 1 - ln(1 + age_days) / ln(366), clamped to 0..1; 1.0 when the age is unknown",
    "maintainer_count": "distinct author/maintainer names in registry metadata (unknown or 0 reads as 1), capped at 50",
    "has_repo_url": "0 if a NO_SOURCE_REPO finding is present, else 1",
    "release_count": "releases uploaded in the last 7 days (registry metadata), capped at 1000",
    "new_package": "1 if a NEW_PACKAGE finding is present, else 0",
    "attack_chain_count": "context-weighted count of ATTACK_CHAIN findings, capped at 5",
    "max_chain_confidence": _strength_description(Code.ATTACK_CHAIN),
    "secrets_count": "context-weighted count of SECRET_DETECTED findings, capped at 10",
    **{name: _strength_description(code) for name, code in STRENGTH_FEATURES.items()},
}


# --------------------------------------------------------------------------- schema identity
def feature_schema_hash(order: Sequence[str] | None = None, version: str | None = None) -> str:
    """sha256 over the feature names, their order and the feature-set version (64 hex chars)."""
    material = {
        "feature_set_version": str(FEATURE_SET_VERSION if version is None else version),
        "features": list(FEATURE_ORDER if order is None else order),
    }
    raw = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- value guards
def finite_float(value: Any, default: float = 0.0) -> float:
    """``value`` as a finite float, or ``default`` for non-numeric / NaN / infinite input."""
    if isinstance(value, bool):
        return float(value)
    try:
        out = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return out if math.isfinite(out) else default


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def age_score(age_days: Any) -> float:
    """Release recency in 0..1 (1.0 = just published or unknown age, 0.0 = a year or older)."""
    if isinstance(age_days, bool) or not isinstance(age_days, (int, float)) or not math.isfinite(age_days):
        return 1.0
    return _clamp(1.0 - math.log1p(max(float(age_days), 0.0)) / math.log1p(AGE_HORIZON_DAYS), 0.0, 1.0)


def _evidence(finding: Signal) -> Mapping[str, Any]:
    ev = finding.evidence
    return ev if isinstance(ev, Mapping) else {}


def _context_factor(finding: Signal) -> float:
    context = _evidence(finding).get("context")
    if isinstance(context, str):
        return CONTEXT_DISCOUNTS.get(context.strip().lower(), 1.0)
    return 1.0


def _is_truncation_summary(finding: Signal) -> bool:
    omitted = _evidence(finding).get("omitted")
    return isinstance(omitted, int) and not isinstance(omitted, bool)


def _seq_len(value: Any) -> int:
    return len(value) if isinstance(value, (list, tuple)) else 0


# --------------------------------------------------------------------------- feature builder
def build_features(signals: Iterable[Signal], ctx: PackageContext | None = None) -> dict[str, float]:
    """Reduce findings (and registry metadata from ``ctx``) to the v2 feature dict.

    Keys are exactly :data:`FEATURE_ORDER`, in order. Output is deterministic for a given set
    of findings; the v2 features do not depend on finding order.
    """
    findings: list[Signal] = []
    for index, s in enumerate(signals):
        if index >= MAX_FINDINGS_CONSIDERED:
            break
        if isinstance(s, Signal):
            findings.append(s)

    by_code: dict[str, Signal] = {}  # v1: highest-weight finding per code (first wins on ties)
    all_by_code: dict[str, list[Signal]] = {}
    for s in findings:
        if s.code not in by_code or s.weight > by_code[s.code].weight:
            by_code[s.code] = s
        if not _is_truncation_summary(s):
            all_by_code.setdefault(s.code, []).append(s)

    def has(code: str) -> float:
        return 1.0 if code in by_code else 0.0

    def ev(code: str, key: str) -> Any:
        s = by_code.get(code)
        return _evidence(s).get(key) if s is not None else None

    def strength(code: str) -> float:
        values = [_clamp(finite_float(f.confidence), 0.0, 1.0) * _context_factor(f) for f in all_by_code.get(code, ())]
        return round(max(values), 4) if values else 0.0

    def weighted_count(code: str, cap: float) -> float:
        return round(min(cap, sum(_context_factor(f) for f in all_by_code.get(code, ()))), 4)

    md = ctx.metadata if ctx is not None and isinstance(getattr(ctx, "metadata", None), Mapping) else {}

    typo_prox = 0.0
    if Code.TYPOSQUAT in by_code:
        dist = finite_float(ev(Code.TYPOSQUAT, "distance"), 2.0)
        typo_prox = 1.0 if dist <= 1 else (0.6 if dist == 2 else 0.4)

    ioc_hits = 0.0
    if Code.IOC_MATCH in by_code:
        ioc_hits = min(float(_seq_len(ev(Code.IOC_MATCH, "matches")) or 1), MAX_IOC_HITS)

    dynamic_exec = 0.0
    if Code.DYNAMIC_EXEC in by_code:
        calls = max(_seq_len(ev(Code.DYNAMIC_EXEC, "calls")), len(all_by_code.get(Code.DYNAMIC_EXEC, ())), 1)
        dynamic_exec = min(float(calls), MAX_DYNAMIC_EXEC)

    maintainers = finite_float(md.get("_maintainer_count", 1), 1.0)
    features = {
        "install_hook_exec": has(Code.INSTALL_HOOK_EXEC),
        "network_egress": has(Code.NETWORK_EGRESS),
        "subprocess_exec": has(Code.SUBPROCESS_EXEC),
        "dynamic_exec": dynamic_exec,
        "obfuscation_score": _clamp(finite_float(ev(Code.OBFUSCATION, "obfuscation_score")), 0.0, 1.0),
        "encoded_exec": has(Code.ENCODED_EXEC),
        "env_harvest": has(Code.ENV_HARVEST),
        "fs_sensitive_write": has(Code.FS_SENSITIVE),
        "dangerous_import_count": min(float(_seq_len(ev(Code.DANGEROUS_IMPORT, "modules"))), MAX_DANGEROUS_IMPORTS),
        "typosquat_distance": typo_prox,
        "ioc_hits": ioc_hits,
        "package_age_days": age_score(md.get("_age_days")),
        "maintainer_count": _clamp(maintainers, 1.0, MAX_MAINTAINERS) if maintainers >= 1 else 1.0,
        "has_repo_url": 0.0 if has(Code.NO_SOURCE_REPO) else 1.0,
        "release_count": _clamp(finite_float(md.get("_releases_last_7d", 0)), 0.0, MAX_RECENT_RELEASES),
        "new_package": has(Code.NEW_PACKAGE),
        # --- feature set v2 ---------------------------------------------------------------
        "attack_chain_count": weighted_count(Code.ATTACK_CHAIN, MAX_ATTACK_CHAINS),
        "max_chain_confidence": strength(Code.ATTACK_CHAIN),
        "secrets_count": weighted_count(Code.SECRET_DETECTED, MAX_SECRETS),
    }
    for name, code in STRENGTH_FEATURES.items():
        features[name] = strength(code)
    return {name: float(features[name]) for name in FEATURE_ORDER}


def to_vector(features: Mapping[str, Any]) -> list[float]:
    """Feature dict -> list in :data:`FEATURE_ORDER`; missing or non-finite values read as 0."""
    return [finite_float(features.get(name, 0.0)) for name in FEATURE_ORDER]


def matches_feature_set(vector: Any, declared_version: Any = None) -> bool:
    """True when a stored feature vector was built by this feature set.

    The key set must equal :data:`FEATURE_ORDER` (v1 rows have 16 keys, so they never match);
    when the scan recorded its feature-set version, that version must match as well.
    """
    if not isinstance(vector, Mapping) or set(vector) != set(FEATURE_ORDER):
        return False
    return declared_version is None or str(declared_version) == FEATURE_SET_VERSION


# --------------------------------------------------------------------------- drift helpers
DRIFT_QUANTILES: tuple[float, ...] = tuple(round(0.1 * i, 1) for i in range(1, 10))
PSI_EPSILON = 1e-4
PSI_MODERATE = 0.1
PSI_SIGNIFICANT = 0.25


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolation quantile (numpy's default method) of pre-sorted values."""
    position = (len(sorted_values) - 1) * q
    lower = math.floor(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (position - lower)


def bin_index(cuts: Sequence[float], value: float) -> int:
    """Bin of ``value``: bin 0 is ``x <= cuts[0]``, bin i is ``cuts[i-1] < x <= cuts[i]``, last is ``x > cuts[-1]``."""
    return bisect.bisect_left(cuts, value)


def bin_proportions(cuts: Sequence[float], values: Iterable[Any]) -> list[float]:
    """Fraction of ``values`` in each of the ``len(cuts) + 1`` bins (non-finite values read as 0)."""
    counts = [0] * (len(cuts) + 1)
    total = 0
    for value in values:
        counts[bin_index(cuts, finite_float(value))] += 1
        total += 1
    if total == 0:
        return [0.0] * len(counts)
    return [round(c / total, 6) for c in counts]


def reference_bins(values: Iterable[Any]) -> dict[str, Any]:
    """Quantile-bin summary of one feature's reference (training) distribution.

    Cut points are the distinct deciles plus the maximum, so a zero-inflated or binary feature
    still gets a bin for values above anything seen in training (a constant-zero training
    feature yields bins ``x <= 0`` and ``x > 0``).
    """
    data = sorted(finite_float(v) for v in values)
    if not data:
        raise ValueError("a reference distribution needs at least one value")
    cuts = sorted({round(_quantile(data, q), 6) for q in DRIFT_QUANTILES} | {round(data[-1], 6)})
    return {"cuts": cuts, "proportions": bin_proportions(cuts, data), "n": len(data)}


def population_stability_index(
    expected: Sequence[Any], actual: Sequence[Any], *, epsilon: float = PSI_EPSILON
) -> float:
    """PSI = sum((a - e) * ln(a / e)) over bins; empty bins are floored at ``epsilon``."""
    if len(expected) != len(actual):
        raise ValueError("expected and actual proportions must have the same number of bins")
    total = 0.0
    for e_raw, a_raw in zip(expected, actual):
        e = max(finite_float(e_raw), epsilon)
        a = max(finite_float(a_raw), epsilon)
        total += (a - e) * math.log(a / e)
    return round(max(total, 0.0), 6)


def psi_status(psi: float) -> str:
    """Conventional PSI reading: < 0.1 stable, < 0.25 moderate, otherwise significant (rules of thumb)."""
    if psi < PSI_MODERATE:
        return "stable"
    if psi < PSI_SIGNIFICANT:
        return "moderate"
    return "significant"


__all__ = [
    "FEATURE_DESCRIPTIONS",
    "FEATURE_ORDER",
    "FEATURE_SET_VERSION",
    "PSI_MODERATE",
    "PSI_SIGNIFICANT",
    "STRENGTH_FEATURES",
    "age_score",
    "bin_proportions",
    "build_features",
    "feature_schema_hash",
    "finite_float",
    "matches_feature_set",
    "population_stability_index",
    "psi_status",
    "reference_bins",
    "to_vector",
]
