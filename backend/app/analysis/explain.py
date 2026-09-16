"""Per-prediction additive explanations for the random-forest behaviour model.

Method: tree-path decomposition (Saabas, "Interpreting random forests", 2014).
For one decision tree let ``p(n)`` be the positive-class fraction stored at node ``n`` (the
value sklearn normalises at a leaf to produce ``predict_proba``). Along the sample's
root → leaf path::

    p(leaf) = p(root) + Σ_{parent → child on the path} [p(child) − p(parent)]

and each step's change is credited to the feature the *parent* node split on. Averaging over
every tree of a forest, and then over the base forests of the calibrated ensemble
(``CalibratedClassifierCV`` fits one forest per CV fold), gives an exact decomposition::

    forest_probability = bias + Σ_features contribution[feature]

where ``bias`` is the mean root probability. The identity holds up to floating-point
rounding; the reported ``additivity_error`` shows the residual.

What it explains — read before using the numbers:

* The contributions explain the **uncalibrated** forest probability (the mean of the base
  forests' ``predict_proba``). The served ``ml_score`` is the *calibrated* probability, which
  applies a monotone per-fold calibration map on top, so contributions do not add up to the
  ``ml_score``; they show which features pushed the underlying forest up or down.
* Tree-path contributions depend on split order: correlated features can share credit
  arbitrarily. They are not Shapley values.
* A zero-valued feature can carry a non-zero contribution (absence of a signal is evidence).

All work is bounded: one input row, a fixed number of trees; per-tree node tables are
precomputed once per model.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash, to_vector
from app.core.logging import get_logger

log = get_logger("warden.explain")

METHOD = "tree-path-decomposition"
EXPLAINS = "uncalibrated_forest_probability"
NOTE = (
    "Contributions decompose the uncalibrated random-forest probability (mean of the calibrated ensemble's "
    "base forests) as bias + sum(contributions). The ml_score is the calibrated probability, so contributions "
    "do not sum to it. Tree-path contributions are path-dependent and are not Shapley values."
)
DEFAULT_TOP_K = 8
POSITIVE_CLASS = 1


class UnsupportedModelError(TypeError):
    """The classifier is not a (calibrated) tree ensemble this explainer can decompose."""


@dataclass(frozen=True)
class _TreeTable:
    positive: np.ndarray  # positive-class fraction per node
    feature: np.ndarray  # split feature per node (negative for leaves)
    left: np.ndarray
    right: np.ndarray


def _positive_index(model: Any) -> int:
    classes = list(getattr(model, "classes_", []))
    if POSITIVE_CLASS not in classes:
        raise UnsupportedModelError("classifier has no positive class (label 1)")
    return classes.index(POSITIVE_CLASS)


def base_forests(classifier: Any) -> list[Any]:
    """Fitted forests inside ``classifier``: one per calibration fold, or the forest itself."""
    calibrated = getattr(classifier, "calibrated_classifiers_", None)
    if calibrated is not None:
        forests = [getattr(member, "estimator", None) for member in calibrated]
    elif getattr(classifier, "estimators_", None) is not None:
        forests = [classifier]
    else:
        raise UnsupportedModelError(f"cannot decompose {type(classifier).__name__}: not a tree ensemble")
    if not forests:
        raise UnsupportedModelError("calibrated classifier has no fitted base estimators")
    for forest in forests:
        estimators = getattr(forest, "estimators_", None)
        if not estimators or not all(hasattr(est, "tree_") for est in estimators):
            raise UnsupportedModelError(f"cannot decompose {type(forest).__name__}: base estimator is not a forest")
    return forests


def _table(tree: Any, positive: int) -> _TreeTable:
    values = np.asarray(tree.value, dtype=float)[:, 0, :]
    totals = values.sum(axis=1)
    fractions = np.divide(values[:, positive], totals, out=np.zeros_like(totals), where=totals > 0)
    return _TreeTable(
        positive=fractions,
        feature=np.asarray(tree.feature, dtype=np.int64),
        left=np.asarray(tree.children_left, dtype=np.int64),
        right=np.asarray(tree.children_right, dtype=np.int64),
    )


@dataclass(frozen=True)
class Explanation:
    forest_probability: float
    bias: float
    contributions: np.ndarray
    values: tuple[float, ...]
    feature_names: tuple[str, ...]

    @property
    def additivity_error(self) -> float:
        return abs(self.bias + float(self.contributions.sum()) - self.forest_probability)

    def to_dict(self, top_k: int = DEFAULT_TOP_K) -> dict[str, Any]:
        k = max(1, min(int(top_k), len(self.feature_names)))
        order = sorted(
            range(len(self.feature_names)),
            key=lambda i: (-round(abs(float(self.contributions[i])), 12), self.feature_names[i]),
        )
        top = [i for i in order if self.contributions[i] != 0.0][:k]
        shown = float(sum(self.contributions[i] for i in top))
        return {
            "method": METHOD,
            "explains": EXPLAINS,
            "note": NOTE,
            "forest_probability": round(self.forest_probability, 6),
            "bias": round(self.bias, 6),
            "contributions": [
                {
                    "feature": self.feature_names[i],
                    "value": round(self.values[i], 6),
                    "contribution": round(float(self.contributions[i]), 6),
                }
                for i in top
            ],
            "other_features_contribution": round(float(self.contributions.sum()) - shown, 6),
            "additivity_error": float(f"{self.additivity_error:.3g}"),
        }


class ForestExplainer:
    """Exact tree-path decomposition for a RandomForest or a CalibratedClassifierCV of forests."""

    def __init__(self, classifier: Any, feature_names: Sequence[str] = FEATURE_ORDER) -> None:
        self.feature_names = tuple(feature_names)
        self._forests: list[tuple[Any, list[_TreeTable]]] = []
        for forest in base_forests(classifier):
            n_in = getattr(forest, "n_features_in_", None)
            if n_in is not None and int(n_in) != len(self.feature_names):
                raise UnsupportedModelError(f"forest expects {n_in} features, explainer has {len(self.feature_names)}")
            positive = _positive_index(forest)
            tables = [_table(est.tree_, positive) for est in forest.estimators_]
            self._forests.append((forest, tables))

    def explain_vector(self, vector: Sequence[float]) -> Explanation:
        values = tuple(float(v) for v in vector)
        if len(values) != len(self.feature_names):
            raise ValueError(f"expected {len(self.feature_names)} feature values, got {len(values)}")
        if not all(math.isfinite(v) for v in values):
            raise ValueError("feature values must be finite")
        # Trees compare float32 thresholds; predict_proba converts inputs the same way.
        x = np.asarray([values], dtype=np.float32)
        n = len(values)
        contributions = np.zeros(n, dtype=float)
        bias = prediction = 0.0
        for forest, tables in self._forests:
            f_contrib = np.zeros(n, dtype=float)
            f_bias = f_pred = 0.0
            for estimator, table in zip(forest.estimators_, tables):
                nodes = np.sort(estimator.tree_.decision_path(x).indices)
                parents, children = nodes[:-1], nodes[1:]
                if not np.all((table.left[parents] == children) | (table.right[parents] == children)):
                    raise UnsupportedModelError("decision path is not a root-to-leaf chain in node order")
                p = table.positive[nodes]
                f_bias += float(p[0])
                f_pred += float(p[-1])
                if len(nodes) > 1:
                    np.add.at(f_contrib, table.feature[parents], np.diff(p))
            count = len(tables)
            contributions += f_contrib / count
            bias += f_bias / count
            prediction += f_pred / count
        m = len(self._forests)
        return Explanation(
            forest_probability=prediction / m,
            bias=bias / m,
            contributions=contributions / m,
            values=values,
            feature_names=self.feature_names,
        )

    def explain(self, features: Mapping[str, Any], top_k: int = DEFAULT_TOP_K) -> dict[str, Any]:
        return self.explain_vector(to_vector(features)).to_dict(top_k)


def ml_explanation(features: Mapping[str, Any], *, store: Any = None, top_k: int = DEFAULT_TOP_K) -> dict[str, Any]:
    """Explanation block for a scan result. Never raises; failures are reported as a status.

    Always includes the running feature-set version and schema hash (so stored scans can be
    matched to a feature set). With an available model it adds ``model_version`` and the
    tree-path contributions.
    """
    out: dict[str, Any] = {
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_schema_hash": feature_schema_hash(),
    }
    try:
        if store is None:
            from app.analysis.model_store import get_model_store

            store = get_model_store()
        if not getattr(store, "available", False):
            out["explanation_status"] = "model_unavailable"
            return out
        out["model_version"] = getattr(store, "model_version", None)
        out.update(store.explain(features, top_k=top_k))
        out["explanation_status"] = "ok"
    except Exception as exc:  # an explanation problem must never fail a scan
        log.warning("ml_explanation_failed", error_type=type(exc).__name__)
        out["explanation_status"] = "error"
        out["error_type"] = type(exc).__name__
    return out


__all__ = [
    "DEFAULT_TOP_K",
    "EXPLAINS",
    "METHOD",
    "Explanation",
    "ForestExplainer",
    "UnsupportedModelError",
    "base_forests",
    "ml_explanation",
]
