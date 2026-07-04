"""Signal -> numeric feature vector.

A single, shared reduction from the list of ``Signal`` objects to a fixed-order numeric
vector. Using the *same* function at training time and serving time eliminates
train/serve skew — the model always sees features built by this exact code. See
docs/ML_MODEL.md for the feature catalogue.
"""

from __future__ import annotations

import math

from app.analysis.analyzers.base import PackageContext
from app.analysis.signals import Code, Signal

# Canonical feature order. Never reorder; append only (and retrain).
FEATURE_ORDER: list[str] = [
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
]


def build_features(signals: list[Signal], ctx: PackageContext | None = None) -> dict[str, float]:
    by_code: dict[str, Signal] = {}
    for s in signals:
        # keep the highest-weight signal per code
        if s.code not in by_code or s.weight > by_code[s.code].weight:
            by_code[s.code] = s

    def has(code: str) -> float:
        return 1.0 if code in by_code else 0.0

    def ev(code: str, key: str, default=0):
        s = by_code.get(code)
        return s.evidence.get(key, default) if s else default

    md = (ctx.metadata if ctx else {}) or {}

    # typosquat: convert distance (1..2) to an inverted 0..1 proximity score.
    ts = by_code.get(Code.TYPOSQUAT)
    typo_prox = 0.0
    if ts:
        dist = ts.evidence.get("distance", 2)
        typo_prox = {0: 1.0, 1: 1.0, 2: 0.6}.get(dist, 0.4)

    age = md.get("_age_days")
    age_scaled = 1.0
    if isinstance(age, (int, float)):
        # newer -> closer to 1 (higher risk). log-scale so 0d≈1, 365d≈~0.
        age_scaled = max(0.0, 1.0 - math.log1p(max(age, 0)) / math.log1p(365))

    ioc_hits = 0
    ioc = by_code.get(Code.IOC_MATCH)
    if ioc:
        ioc_hits = len(ioc.evidence.get("matches", [])) or 1

    features = {
        "install_hook_exec": has(Code.INSTALL_HOOK_EXEC),
        "network_egress": has(Code.NETWORK_EGRESS),
        "subprocess_exec": has(Code.SUBPROCESS_EXEC),
        "dynamic_exec": min(float(len(ev(Code.DYNAMIC_EXEC, "calls", []))) or has(Code.DYNAMIC_EXEC), 5.0),
        "obfuscation_score": float(ev(Code.OBFUSCATION, "obfuscation_score", 0.0)),
        "encoded_exec": has(Code.ENCODED_EXEC),
        "env_harvest": has(Code.ENV_HARVEST),
        "fs_sensitive_write": has(Code.FS_SENSITIVE),
        "dangerous_import_count": float(len(ev(Code.DANGEROUS_IMPORT, "modules", []))),
        "typosquat_distance": typo_prox,
        "ioc_hits": float(min(ioc_hits, 10)),
        "package_age_days": age_scaled,
        "maintainer_count": float(md.get("_maintainer_count", 1) or 1),
        "has_repo_url": 0.0 if has(Code.NO_SOURCE_REPO) else 1.0,
        "release_count": float(md.get("_releases_last_7d", 0) or 0),
        "new_package": has(Code.NEW_PACKAGE),
    }
    return features


def to_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]
