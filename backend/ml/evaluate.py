"""Hold-out evaluation for the behaviour model.

Every report produced here carries a ``label`` stating what the numbers describe. For the
synthetic dataset that label is :data:`SYNTHETIC_LABEL` — the numbers measure how well the
model separates the generator's hand-written distributions, not real-world detection
performance. Metrics:

* threshold metrics at 0.5: accuracy, precision, recall, F1, false-positive rate, specificity;
* ranking metrics: ROC-AUC and PR-AUC (average precision) — ``None`` when only one class is
  present, never a made-up value;
* probability quality: Brier score, reliability bins (calibration curve) and expected
  calibration error;
* a threshold table (0.1 … 0.9) and, when group labels exist, per-family detection /
  false-positive rates.

CLI (evaluates the packaged artifact through :class:`app.analysis.model_store.ModelStore`, so
the feature-schema and sha256-pin checks apply)::

    python -m ml.evaluate --n 3000 --seed 2024
    python -m ml.evaluate --csv labelled.csv

A different seed gives fresh samples from the *same generator*; that checks for overfitting to
particular rows, not generalisation to real packages.
"""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

SYNTHETIC_LABEL = "synthetic hold-out evaluation - not real-world performance"
LABELLED_LABEL = "labelled-dataset hold-out evaluation - representative only of that dataset"
MIXED_LABEL = ("synthetic hold-out evaluation with measured real-world negatives - "
               "not real-world detection performance")
DEFAULT_THRESHOLD = 0.5
DEFAULT_THRESHOLDS: tuple[float, ...] = tuple(round(0.1 * i, 1) for i in range(1, 10))
CALIBRATION_BINS = 10


def label_for(synthetic: bool, *, kind: str | None = None) -> str:
    """Describe the scope of a hold-out result so no number is read as a field measurement."""
    if kind == "mixed":
        return MIXED_LABEL
    return SYNTHETIC_LABEL if synthetic else LABELLED_LABEL


def _r(value: float | None, digits: int = 4) -> float | None:
    if value is None:
        return None
    value = float(value)
    return round(value, digits) if math.isfinite(value) else None


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _as_arrays(y_true: Sequence[int], proba: Sequence[float]) -> tuple[np.ndarray, np.ndarray]:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(proba, dtype=float)
    if y.shape != p.shape or y.ndim != 1:
        raise ValueError("y_true and proba must be 1-D and the same length")
    if y.size == 0:
        raise ValueError("cannot evaluate an empty set")
    if not np.all(np.isin(y, (0, 1))):
        raise ValueError("labels must be 0 or 1")
    if not np.all(np.isfinite(p)) or p.min() < 0.0 or p.max() > 1.0:
        raise ValueError("probabilities must be finite and within [0, 1]")
    return y, p


def confusion_counts(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, int]:
    y = np.asarray(y_true, dtype=int)
    pred = np.asarray(y_pred, dtype=int)
    return {
        "tn": int(np.sum((y == 0) & (pred == 0))),
        "fp": int(np.sum((y == 0) & (pred == 1))),
        "fn": int(np.sum((y == 1) & (pred == 0))),
        "tp": int(np.sum((y == 1) & (pred == 1))),
    }


def _rates(c: dict[str, int]) -> dict[str, float | None]:
    precision = _ratio(c["tp"], c["tp"] + c["fp"])
    recall = _ratio(c["tp"], c["tp"] + c["fn"])
    f1 = None
    if precision is not None and recall is not None:
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _ratio(c["fp"], c["fp"] + c["tn"]),
        "specificity": _ratio(c["tn"], c["fp"] + c["tn"]),
    }


def classification_metrics(
    y_true: Sequence[int], proba: Sequence[float], *, threshold: float = DEFAULT_THRESHOLD
) -> dict[str, float | None]:
    """Flat metric dict. Undefined metrics (e.g. ROC-AUC with one class) are ``None``."""
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

    y, p = _as_arrays(y_true, proba)
    counts = confusion_counts(y, (p >= threshold).astype(int))
    rates = _rates(counts)
    both_classes = 0 < int(y.sum()) < y.size
    return {
        "accuracy": _r((counts["tp"] + counts["tn"]) / y.size),
        "precision": _r(rates["precision"] if rates["precision"] is not None else 0.0),
        "recall": _r(rates["recall"]),
        "f1": _r(rates["f1"] if rates["f1"] is not None else 0.0),
        "false_positive_rate": _r(rates["false_positive_rate"]),
        "specificity": _r(rates["specificity"]),
        "roc_auc": _r(roc_auc_score(y, p)) if both_classes else None,
        "pr_auc": _r(average_precision_score(y, p)) if both_classes else None,
        "brier_score": _r(brier_score_loss(y, p)),
        "threshold": float(threshold),
        "n": int(y.size),
        "positives": int(y.sum()),
        "negatives": int(y.size - y.sum()),
    }


def calibration_bins(y_true: Sequence[int], proba: Sequence[float], *, n_bins: int = CALIBRATION_BINS) -> dict:
    """Reliability diagram data over equal-width probability bins (empty bins reported as empty)."""
    y, p = _as_arrays(y_true, proba)
    index = np.minimum((p * n_bins).astype(int), n_bins - 1)
    bins: list[dict[str, Any]] = []
    ece = 0.0
    for b in range(n_bins):
        mask = index == b
        count = int(mask.sum())
        mean_predicted = float(p[mask].mean()) if count else None
        fraction_positive = float(y[mask].mean()) if count else None
        if count:
            ece += count / y.size * abs(fraction_positive - mean_predicted)
        bins.append({
            "lower": round(b / n_bins, 4),
            "upper": round((b + 1) / n_bins, 4),
            "count": count,
            "mean_predicted": _r(mean_predicted),
            "fraction_positive": _r(fraction_positive),
        })
    return {"strategy": "uniform", "bins": bins, "expected_calibration_error": _r(ece)}


def threshold_table(
    y_true: Sequence[int], proba: Sequence[float], thresholds: Sequence[float] = DEFAULT_THRESHOLDS
) -> list[dict[str, Any]]:
    y, p = _as_arrays(y_true, proba)
    table = []
    for t in thresholds:
        counts = confusion_counts(y, (p >= t).astype(int))
        rates = _rates(counts)
        table.append({"threshold": float(t), **counts, **{k: _r(v) for k, v in rates.items()}})
    return table


def per_group_report(
    y_true: Sequence[int], proba: Sequence[float], groups: Sequence[str], *, threshold: float = DEFAULT_THRESHOLD
) -> dict[str, dict[str, Any]]:
    """Per family: flagged rate at ``threshold`` (detection rate for malicious, FP rate for benign)."""
    y, p = _as_arrays(y_true, proba)
    g = np.asarray(list(groups), dtype=object)
    if g.shape != y.shape:
        raise ValueError("groups must be the same length as y_true")
    report: dict[str, dict[str, Any]] = {}
    for name in sorted({str(x) for x in g}):
        mask = g == name
        labels = y[mask]
        label = int(round(float(labels.mean())))
        flagged = float(np.mean(p[mask] >= threshold))
        report[name] = {
            "label": label,
            "n": int(mask.sum()),
            "metric": "detection_rate" if label == 1 else "false_positive_rate",
            "flagged_rate": _r(flagged),
            "mean_probability": _r(float(p[mask].mean())),
        }
    return report


def evaluate_predictions(
    y_true: Sequence[int],
    proba: Sequence[float],
    *,
    groups: Sequence[str] | None = None,
    synthetic: bool = True,
    kind: str | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    y, p = _as_arrays(y_true, proba)
    counts = confusion_counts(y, (p >= threshold).astype(int))
    return {
        "label": label_for(synthetic, kind=kind),
        "threshold": float(threshold),
        "metrics": classification_metrics(y, p, threshold=threshold),
        "confusion_matrix": {
            "labels": ["benign (0)", "malicious (1)"],
            "rows": "actual",
            "columns": "predicted",
            "matrix": [[counts["tn"], counts["fp"]], [counts["fn"], counts["tp"]]],
            **counts,
        },
        "calibration": calibration_bins(y, p),
        "threshold_table": threshold_table(y, p, thresholds),
        "per_group": per_group_report(y, p, groups, threshold=threshold) if groups is not None else None,
    }


# --------------------------------------------------------------------------- CLI
def main(argv: Sequence[str] | None = None) -> int:
    from app.analysis.model_store import ModelStore
    from ml.datasets import CSVLabeledDataset, SyntheticDataset

    ap = argparse.ArgumentParser(description="Evaluate the packaged model artifact on a hold-out dataset.")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=2024)
    ap.add_argument("--csv", type=Path, default=None, help="labelled CSV (FEATURE_ORDER + label)")
    args = ap.parse_args(argv)

    store = ModelStore()
    if not store.available:
        print(json.dumps({"available": False, "reason": store.unavailable_reason, "detail": store.unavailable_detail}))
        return 1
    dataset = CSVLabeledDataset(args.csv) if args.csv else SyntheticDataset(n=args.n, seed=args.seed)
    loaded = dataset.load()
    proba = store.predict_proba_rows(loaded.X)
    report = evaluate_predictions(loaded.y, proba, groups=loaded.groups, synthetic=dataset.synthetic)
    report["model_version"] = store.model_version
    report["dataset"] = {k: v for k, v in loaded.info.items() if k != "families"}
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
