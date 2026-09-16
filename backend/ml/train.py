"""Train, evaluate and persist the Warden behaviour model (feature set v2).

Pipeline:

1. Load a dataset: the seeded SYNTHETIC dataset by default (``--n``, ``--seed``) or a labelled
   CSV (``--csv``, validated by :class:`ml.datasets.CSVLabeledDataset`).
2. Stratified train / hold-out split (25 % hold-out).
3. Fit ``CalibratedClassifierCV`` (isotonic, 4 stratified folds) around a class-balanced
   ``RandomForestClassifier``, and an ``IsolationForest`` on benign training rows only.
4. Evaluate on the hold-out (:mod:`ml.evaluate`): accuracy, precision, recall, F1, ROC-AUC,
   PR-AUC, Brier score, confusion matrix, reliability bins, threshold table, per-family rates,
   impurity and permutation feature importances. On the synthetic dataset every number is a
   "synthetic hold-out evaluation - not real-world performance".
5. Record the training reference distribution of every feature (quantile bins, for drift) and
   the benign novelty quantiles (for the anomaly score).
6. Serialise the bundle, derive ``model_version`` = first 16 hex of the artifact's sha256, and
   write ``model.joblib``, ``metrics.json`` and ``MODEL_CARD.md`` atomically.

Reproducibility: identical data, seed, configuration and library versions give byte-identical
artifacts and therefore the same ``model_version``. Wall-clock values (``trained_at``,
``training_seconds``) are written only to ``metrics.json``, never into the artifact.

Run from ``backend/``: ``python -m ml.train [--n 6000] [--seed 1337] [--csv FILE] [--artifact-dir DIR]``.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash, reference_bins
from ml import evaluate as evaluation
from ml.datasets import (
    CSVLabeledDataset,
    Dataset,
    MeasuredBenignDataset,
    MixedDataset,
    SyntheticDataset,
)
from ml.model_card import write_model_card

ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "app" / "analysis" / "artifacts"
ARTIFACT_NAME = "model.joblib"
METRICS_NAME = "metrics.json"
MODEL_CARD_NAME = "MODEL_CARD.md"
BUNDLE_FORMAT = "warden-model/2"
METADATA_SCHEMA = "warden-model-metadata/2"
ANOMALY_QUANTILE_LEVELS = 1000

SCORE_SEMANTICS = {
    "ml_score": "round(100 x calibrated P(malicious)) from the calibrated random-forest ensemble; not blended with "
                "the anomaly score",
    "anomaly_score": "min(1, -log10(tail) / 3), tail = share of benign training rows at least as novel under the "
                     "IsolationForest (floored at 1/(n+1)); reported separately, never added to ml_score",
    "explanation": "tree-path contributions that sum (with the bias) to the uncalibrated mean forest probability",
}


@dataclass(frozen=True)
class TrainConfig:
    n_estimators: int = 200
    max_depth: int | None = 12
    min_samples_leaf: int = 3
    calibration_method: str = "isotonic"
    calibration_folds: int = 4
    test_size: float = 0.25
    isolation_estimators: int = 150
    permutation_repeats: int = 5
    permutation_scoring: str = "average_precision"
    # Threads for CV folds and permutation columns (results do not depend on it); None = os.cpu_count().
    # Estimators themselves always run with n_jobs=1: n_jobs=-1 makes joblib re-detect the CPU count on
    # every predict call (very slow on some hosts) and parallel prediction is not bit-reproducible.
    n_jobs: int | None = None


def _resolve_jobs(n_jobs: int | None) -> int:
    return max(1, int(n_jobs)) if n_jobs is not None and int(n_jobs) > 0 else max(1, os.cpu_count() or 1)


def _set_serving_jobs(clf: Any, iso: Any) -> None:
    """Single-threaded estimators in the artifact: no per-call CPU detection or thread-pool setup."""
    for member in clf.calibrated_classifiers_:
        member.estimator.set_params(n_jobs=1)
    iso.set_params(n_jobs=1)


def _zero_tree_padding(forest: Any) -> None:
    """Canonicalise each tree's node array so identical trees serialise to identical bytes.

    sklearn's node records are C structs with trailing padding that is never initialised; pickling
    copies that padding verbatim, so two identical models can hash differently. Rebuilding the node
    array field by field from a zeroed buffer and restoring it leaves every field value unchanged.
    """
    for estimator in forest.estimators_:
        state = estimator.tree_.__getstate__()
        nodes = state["nodes"]
        clean = np.zeros(nodes.shape, dtype=nodes.dtype)
        for name in nodes.dtype.names:
            clean[name] = nodes[name]
        state["nodes"] = clean
        estimator.tree_.__setstate__(state)


def _check_trainable(y: np.ndarray, config: TrainConfig) -> None:
    positives = int(y.sum())
    minority = min(positives, len(y) - positives)
    needed = max(8, int(np.ceil(config.calibration_folds / (1.0 - config.test_size))) + 2)
    if minority < needed:
        raise ValueError(
            f"each class needs at least {needed} samples for a stratified hold-out and "
            f"{config.calibration_folds}-fold calibration; the minority class has {minority}"
        )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _sorted_scores(pairs: dict[str, float]) -> dict[str, float]:
    return dict(sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0])))



def default_dataset(*, n: int, seed: int, measured: bool = True) -> Dataset:
    """Synthetic samples, mixed with measured real-world negatives when they are available."""
    synthetic = SyntheticDataset(n=n, seed=seed)
    part = MeasuredBenignDataset()
    if measured and part.available():
        return MixedDataset(synthetic, part)
    return synthetic

def train(
    n: int = 6000,
    seed: int = 1337,
    *,
    dataset: Dataset | None = None,
    artifact_dir: Path | None = None,
    config: TrainConfig | None = None,
    trained_at: str | None = None,
) -> dict[str, Any]:
    """Train, evaluate and write artifacts; returns the ``metrics.json`` content."""
    import joblib
    import sklearn
    from joblib import parallel_config
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.inspection import permutation_importance
    from sklearn.model_selection import StratifiedKFold, train_test_split

    config = config or TrainConfig()
    jobs = _resolve_jobs(config.n_jobs)
    started = time.monotonic()
    dataset = dataset if dataset is not None else default_dataset(n=n, seed=seed)
    loaded = dataset.load()
    X = np.asarray(loaded.X, dtype=float)
    y = np.asarray(loaded.y, dtype=int)
    if X.ndim != 2 or X.shape[1] != len(FEATURE_ORDER):
        raise ValueError(f"dataset must have {len(FEATURE_ORDER)} feature columns in FEATURE_ORDER")
    _check_trainable(y, config)

    train_idx, test_idx = train_test_split(
        np.arange(len(y)), test_size=config.test_size, random_state=seed, stratify=y
    )
    X_train, X_test, y_train, y_test = X[train_idx], X[test_idx], y[train_idx], y[test_idx]
    groups_test = [loaded.groups[i] for i in test_idx] if loaded.groups is not None else None
    # Measured real-world rows are few next to the synthetic ones and carry a training weight,
    # so the model cannot dismiss them as noise.
    weights_train = None
    if loaded.sample_weight is not None:
        weights_train = np.asarray(loaded.sample_weight, dtype=float)[train_idx]

    # Every estimator predicts single-threaded: a parallel forest adds per-tree probabilities in thread
    # completion order, and those last-bit differences leak into the isotonic calibrators (and so into the
    # artifact bytes). Speed comes from running the CV folds and permutation columns in parallel threads
    # instead (tree building and tree prediction release the GIL).
    forest = RandomForestClassifier(
        n_estimators=config.n_estimators, max_depth=config.max_depth, min_samples_leaf=config.min_samples_leaf,
        class_weight="balanced", random_state=seed, n_jobs=1,
    )
    clf = CalibratedClassifierCV(
        forest, method=config.calibration_method, ensemble=True, n_jobs=min(jobs, config.calibration_folds),
        cv=StratifiedKFold(n_splits=config.calibration_folds, shuffle=True, random_state=seed),
    )
    with parallel_config(backend="threading"):
        if weights_train is not None:
            clf.fit(X_train, y_train, sample_weight=weights_train)
        else:
            clf.fit(X_train, y_train)
    positive = list(clf.classes_).index(1)

    benign_train = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=config.isolation_estimators, contamination="auto", random_state=seed,
                          n_jobs=1)
    iso.fit(benign_train)
    novelty = -iso.score_samples(benign_train)
    levels = np.linspace(0.0, 1.0, ANOMALY_QUANTILE_LEVELS + 1)
    anomaly_reference = {
        "method": "quantiles of -IsolationForest.score_samples over benign training rows",
        "quantiles": [round(float(q), 6) for q in np.quantile(novelty, levels)],
        "n": int(len(benign_train)),
    }

    proba = clf.predict_proba(X_test)[:, positive]
    report = evaluation.evaluate_predictions(y_test, proba, groups=groups_test, synthetic=dataset.synthetic,
                                            kind=getattr(dataset, "kind", None))

    base_forests = [member.estimator for member in clf.calibrated_classifiers_]
    impurity = np.mean([f.feature_importances_ for f in base_forests], axis=0)
    with parallel_config(backend="threading"):
        permutation = permutation_importance(
            clf, X_test, y_test, scoring=config.permutation_scoring, n_repeats=config.permutation_repeats,
            random_state=seed, n_jobs=jobs,
        )
    importances = {
        "impurity": _sorted_scores({name: round(float(v), 6) for name, v in zip(FEATURE_ORDER, impurity)}),
        "permutation": {
            name: {"mean": round(float(m), 6), "std": round(float(s), 6)}
            for name, m, s in sorted(
                zip(FEATURE_ORDER, permutation.importances_mean, permutation.importances_std),
                key=lambda t: (-round(float(t[1]), 6), t[0]),
            )
        },
        "permutation_scoring": config.permutation_scoring,
        "permutation_repeats": config.permutation_repeats,
        "permutation_data": "hold-out",
    }
    reference = {
        "benign": {name: reference_bins(benign_train[:, j]) for j, name in enumerate(FEATURE_ORDER)},
        "all": {name: reference_bins(X_train[:, j]) for j, name in enumerate(FEATURE_ORDER)},
    }
    hyperparameters = {k: v for k, v in asdict(config).items() if k != "n_jobs"}
    metadata: dict[str, Any] = {
        "schema": METADATA_SCHEMA,
        "algorithm": (
            f"CalibratedClassifierCV({config.calibration_method}, {config.calibration_folds} stratified folds) over "
            f"RandomForestClassifier(n_estimators={config.n_estimators}, class_weight=balanced) + "
            f"IsolationForest(benign training rows)"
        ),
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_schema_hash": feature_schema_hash(),
        "feature_order": list(FEATURE_ORDER),
        "dataset": loaded.info,
        "split": {
            "method": "stratified train_test_split",
            "test_size": config.test_size,
            "random_state": seed,
            "train_n": int(len(train_idx)),
            "test_n": int(len(test_idx)),
            "train_positives": int(y_train.sum()),
            "test_positives": int(y_test.sum()),
        },
        "hyperparameters": {**hyperparameters, "class_weight": "balanced", "random_state": seed},
        "libraries": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__,
        },
        "evaluation": report,
        "feature_importances": importances,
        "reference_distribution": reference,
        "anomaly_reference": anomaly_reference,
        "score_semantics": SCORE_SEMANTICS,
    }
    _set_serving_jobs(clf, iso)
    for forest in [*base_forests, iso]:
        _zero_tree_padding(forest)
    bundle = {
        "format": BUNDLE_FORMAT,
        "classifier": clf,
        "isolation_forest": iso,
        "feature_order": list(FEATURE_ORDER),
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_schema_hash": feature_schema_hash(),
        "metadata": metadata,
    }
    buffer = io.BytesIO()
    joblib.dump(bundle, buffer)
    data = buffer.getvalue()
    digest = hashlib.sha256(data).hexdigest()

    sidecar: dict[str, Any] = {
        "model_version": digest[:16],
        "artifact_sha256": digest,
        "trained_at": trained_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "training_seconds": round(time.monotonic() - started, 2),
        **metadata,
    }
    out_dir = Path(artifact_dir) if artifact_dir is not None else ARTIFACT_DIR
    _atomic_write(out_dir / ARTIFACT_NAME, data)
    _atomic_write(out_dir / METRICS_NAME, json.dumps(sidecar, indent=2).encode("utf-8"))
    write_model_card(sidecar, out_dir / MODEL_CARD_NAME)
    return sidecar


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the Warden behaviour model (synthetic data by default).")
    ap.add_argument("--n", type=int, default=6000, help="synthetic samples to generate")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--no-measured", action="store_true",
                    help="train on synthetic samples only, ignoring ml/data/real_benign_features.csv")
    ap.add_argument("--csv", type=Path, default=None, help="labelled CSV (FEATURE_ORDER + label) instead of synthetic")
    ap.add_argument("--artifact-dir", type=Path, default=ARTIFACT_DIR)
    ap.add_argument("--n-estimators", type=int, default=TrainConfig.n_estimators)
    args = ap.parse_args()

    dataset: Dataset = (CSVLabeledDataset(args.csv) if args.csv
                        else default_dataset(n=args.n, seed=args.seed, measured=not args.no_measured))
    meta = train(n=args.n, seed=args.seed, dataset=dataset, artifact_dir=args.artifact_dir,
                 config=TrainConfig(n_estimators=args.n_estimators))
    report = meta["evaluation"]
    print(f"Evaluation scope: {report['label']}")
    print(json.dumps(report["metrics"], indent=2))
    top = list(meta["feature_importances"]["permutation"].items())[:8]
    print("Top permutation importances:", [(name, row["mean"]) for name, row in top])
    print(f"model_version {meta['model_version']} ({meta['training_seconds']} s); artifacts in {args.artifact_dir}")


if __name__ == "__main__":
    main()
