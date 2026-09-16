"""Machine-learning routes: model metadata and input drift (both require ``ml:read``).

``GET /ml/model`` returns what is known about the served model: availability (and the reason
when the store refused the artifact), content-derived version, feature-set identity, dataset
provenance and the evaluation recorded at training time with its scope label. Only JSON
primitives copied field-by-field from the artifact metadata are returned — never pickled
objects, estimator internals or file-system paths.

``GET /ml/drift`` compares the most recent scans' stored feature vectors with the training
reference distribution using the population stability index (PSI) per feature. Only rows
built by the running feature set are used (``features.matches_feature_set``). Below
:data:`DRIFT_MIN_SAMPLES` usable rows the status is ``insufficient_data`` and no PSI is
reported, because PSI on a handful of rows is noise. The PSI bands (0.1 / 0.25) are conventional
rules of thumb, and the reference is synthetic training data: drift shows that production
inputs differ from the training distribution, not that an attack took place.
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.features import (
    FEATURE_DESCRIPTIONS,
    FEATURE_ORDER,
    FEATURE_SET_VERSION,
    PSI_MODERATE,
    PSI_SIGNIFICANT,
    bin_proportions,
    feature_schema_hash,
    matches_feature_set,
    population_stability_index,
    psi_status,
)
from app.analysis.model_store import get_model_store
from app.api.deps import require_permission
from app.core.config import settings
from app.core.permissions import Permission
from app.core.redaction import sanitize_text
from app.db.models import Scan, User
from app.db.session import get_db

router = APIRouter(prefix="/ml", tags=["ml"])

DRIFT_MIN_SAMPLES = 50
DRIFT_DEFAULT_LIMIT = 500
DRIFT_MAX_LIMIT = 5000
_MAX_DEPTH = 6
_MAX_ITEMS = 64
_MAX_KEYS = 80
DRIFT_NOTE = (
    "PSI bands (0.1 moderate, 0.25 significant) are conventional rules of thumb. The reference is the synthetic "
    "training data, so drift means recent scan inputs differ from the training distribution; it is not by itself "
    "evidence of an attack."
)


# --------------------------------------------------------------------------- metadata cleaning
def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        return None
    if isinstance(value, numbers.Integral):
        return int(value)
    out = float(value)
    return out if math.isfinite(out) else None


def _clean(value: Any, depth: int = 0) -> Any:
    """JSON primitives only (bounded); any other object type is dropped."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, numbers.Real):
        return _number(value)
    if isinstance(value, str):
        return sanitize_text(value, max_len=300)
    if depth >= _MAX_DEPTH:
        return None
    if isinstance(value, Mapping):
        # Keys are not redacted: feature names such as "secrets_count" are metadata, not secrets.
        return {
            sanitize_text(str(k), max_len=80, redact=False): _clean(v, depth + 1)
            for k, v in list(value.items())[:_MAX_KEYS]
        }
    if isinstance(value, (list, tuple)):
        return [_clean(v, depth + 1) for v in list(value)[:_MAX_ITEMS]]
    return None


def _flat_numbers(value: Any) -> dict[str, float | int]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, float | int] = {}
    for key, raw in value.items():
        number = _number(raw)
        if number is not None:
            out[sanitize_text(str(key), max_len=80, redact=False)] = number
    return out


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def model_payload(store: Any) -> dict[str, Any]:
    available = bool(getattr(store, "available", False))
    artifact_meta = _mapping(getattr(store, "metadata", None))
    meta = artifact_meta if available else {}
    evaluation = _mapping(meta.get("evaluation"))
    detail = getattr(store, "unavailable_detail", None)
    references = _mapping(meta.get("reference_distribution"))
    return {
        "available": available,
        "unavailable_reason": None if available else getattr(store, "unavailable_reason", None),
        "unavailable_detail": sanitize_text(detail, max_len=300) if detail and not available else None,
        "version": getattr(store, "model_version", None),
        "model_version": getattr(store, "model_version", None),
        "artifact_sha256": getattr(store, "artifact_sha256", None) if available else None,
        "artifact_pinned": bool((settings.MODEL_ARTIFACT_SHA256 or "").strip()),
        "trained_at": _clean(getattr(store, "trained_at", None)),
        "algorithm": _clean(meta.get("algorithm")),
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_schema_hash": feature_schema_hash(),
        "artifact_feature_set_version": _clean(artifact_meta.get("feature_set_version")),
        "artifact_feature_schema_hash": _clean(artifact_meta.get("feature_schema_hash")),
        "features": list(FEATURE_ORDER),
        "feature_descriptions": dict(FEATURE_DESCRIPTIONS),
        "evaluation_label": _clean(evaluation.get("label")),
        "metrics": _flat_numbers(evaluation.get("metrics")),
        "confusion_matrix": _clean(evaluation.get("confusion_matrix")),
        "calibration": _clean(evaluation.get("calibration")),
        "threshold_table": _clean(evaluation.get("threshold_table")),
        "per_group": _clean(evaluation.get("per_group")),
        "feature_importances": _clean(meta.get("feature_importances")),
        "dataset": _clean(meta.get("dataset")),
        "split": _clean(meta.get("split")),
        "hyperparameters": _clean(meta.get("hyperparameters")),
        "libraries": _clean(meta.get("libraries")),
        "score_semantics": _clean(meta.get("score_semantics")),
        "drift_reference_populations": sorted(str(k) for k in references),
    }


@router.get("/model")
def model_info(_: User = Depends(require_permission(Permission.ML_READ))) -> dict[str, Any]:
    """Served model metadata (no pickled objects, no file paths)."""
    return model_payload(get_model_store())


# --------------------------------------------------------------------------- drift
def _valid_bins(entry: Any) -> tuple[list[float], list[float]] | None:
    if not isinstance(entry, Mapping):
        return None
    cuts, proportions = entry.get("cuts"), entry.get("proportions")
    if not isinstance(cuts, Sequence) or not isinstance(proportions, Sequence) or isinstance(cuts, str):
        return None
    cut_values = [_number(c) for c in cuts]
    prop_values = [_number(p) for p in proportions]
    if any(v is None for v in cut_values) or any(v is None for v in prop_values):
        return None
    if len(prop_values) != len(cut_values) + 1 or cut_values != sorted(cut_values):
        return None
    return [float(c) for c in cut_values], [float(p) for p in prop_values]  # type: ignore[arg-type]


def _declared_feature_set(explanation: Any) -> Any:
    ml = explanation.get("ml") if isinstance(explanation, Mapping) else None
    return ml.get("feature_set_version") if isinstance(ml, Mapping) else None


def compute_drift(
    rows: Sequence[tuple[Any, Any]], reference: Mapping[str, Any], *, min_samples: int = DRIFT_MIN_SAMPLES
) -> dict[str, Any]:
    """PSI per feature for ``(feature_vector, explanation)`` rows against reference bins."""
    bins = {name: _valid_bins(reference.get(name)) for name in FEATURE_ORDER}
    if any(b is None for b in bins.values()):
        return {"status": "no_reference", "sample_size": 0, "features": []}
    columns: list[list[float]] = [[] for _ in FEATURE_ORDER]
    other_feature_set = invalid = 0
    for vector, explanation in rows:
        if not matches_feature_set(vector, _declared_feature_set(explanation)):
            other_feature_set += 1
            continue
        values = [_number(vector.get(name)) for name in FEATURE_ORDER]
        if any(v is None for v in values):
            invalid += 1
            continue
        for column, value in zip(columns, values):
            column.append(float(value))  # type: ignore[arg-type]
    sample_size = len(columns[0])
    result: dict[str, Any] = {
        "rows_examined": len(rows),
        "sample_size": sample_size,
        "rows_excluded": {"other_feature_set": other_feature_set, "invalid_values": invalid},
    }
    if sample_size < min_samples:
        return {**result, "status": "insufficient_data", "features": [], "summary": None}

    features = []
    for name, column in zip(FEATURE_ORDER, columns):
        cuts, expected = bins[name]  # type: ignore[misc]
        actual = bin_proportions(cuts, column)
        psi = population_stability_index(expected, actual)
        features.append({
            "name": name,
            "score": psi,
            "psi": psi,
            "status": psi_status(psi),
            "drifted": psi >= PSI_SIGNIFICANT,
            "cuts": cuts,
            "expected": expected,
            "actual": actual,
        })
    features.sort(key=lambda f: (-f["score"], f["name"]))
    statuses = [f["status"] for f in features]
    summary = {
        "max_psi": features[0]["score"] if features else 0.0,
        "significant": statuses.count("significant"),
        "moderate": statuses.count("moderate"),
        "stable": statuses.count("stable"),
        "drift_detected": any(f["drifted"] for f in features),
    }
    return {**result, "status": "ok", "features": features, "summary": summary}


@router.get("/drift")
def model_drift(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.ML_READ)),
    limit: int = Query(DRIFT_DEFAULT_LIMIT, ge=1, le=DRIFT_MAX_LIMIT),
    reference: Literal["benign", "all"] = Query("benign"),
) -> dict[str, Any]:
    """Input drift of recent scans versus the training reference distribution (PSI per feature)."""
    store = get_model_store()
    base: dict[str, Any] = {
        "window": f"most recent {limit} scans",
        "limit": limit,
        "reference": reference,
        "min_samples": DRIFT_MIN_SAMPLES,
        "method": "population stability index over training quantile bins",
        "thresholds": {"moderate": PSI_MODERATE, "significant": PSI_SIGNIFICANT},
        "feature_set_version": FEATURE_SET_VERSION,
        "model_version": getattr(store, "model_version", None),
        "note": DRIFT_NOTE,
    }
    if not getattr(store, "available", False):
        return {**base, "status": "model_unavailable", "reason": getattr(store, "unavailable_reason", None),
                "sample_size": 0, "features": []}
    ref_getter = getattr(store, "reference_distribution", None)
    ref = ref_getter(reference) if callable(ref_getter) else None
    if not isinstance(ref, Mapping):
        return {**base, "status": "no_reference", "sample_size": 0, "features": []}
    rows = db.execute(
        select(Scan.feature_vector, Scan.explanation).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit)
    ).all()
    return {**base, **compute_drift([(r[0], r[1]) for r in rows], ref)}
