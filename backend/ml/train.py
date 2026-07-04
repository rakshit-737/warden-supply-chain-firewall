"""Train, evaluate, and persist the risk model.

Produces ``app/analysis/artifacts/model.joblib`` containing:
  * a calibrated RandomForest classifier (supervised malicious probability),
  * an IsolationForest fit on benign samples (unsupervised novelty),
  * the exact feature order and evaluation metadata.

Run: ``python -m ml.train`` (from the ``backend`` directory).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ml.generate_dataset import FEATURE_ORDER, generate

ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "app" / "analysis" / "artifacts"


def train(n: int = 6000, seed: int = 1337) -> dict:
    import joblib
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split

    X, y = generate(n=n, seed=seed)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y
    )

    base = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=seed, n_jobs=-1,
    )
    clf = CalibratedClassifierCV(base, method="isotonic", cv=4)
    clf.fit(X_train, y_train)

    # IsolationForest on benign training samples only.
    iso = IsolationForest(n_estimators=150, contamination=0.05, random_state=seed)
    iso.fit(X_train[y_train == 0])

    proba = clf.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "precision": round(float(precision_score(y_test, preds)), 4),
        "recall": round(float(recall_score(y_test, preds)), 4),
        "f1": round(float(f1_score(y_test, preds)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
    }

    # Feature importances from the underlying forest(s).
    importances = np.mean(
        [est.feature_importances_ for est in base.__dict__.get("estimators_", [])] or
        [np.zeros(len(FEATURE_ORDER))], axis=0,
    ) if hasattr(base, "estimators_") else np.zeros(len(FEATURE_ORDER))
    # base isn't fitted directly (calibration wraps a clone); refit a plain forest for importances.
    plain = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=seed, n_jobs=-1,
    ).fit(X_train, y_train)
    importances = dict(
        sorted(zip(FEATURE_ORDER, [round(float(x), 4) for x in plain.feature_importances_]),
               key=lambda kv: kv[1], reverse=True)
    )

    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": int(n),
        "seed": seed,
        "metrics": metrics,
        "feature_importances": importances,
        "model": "RandomForest(calibrated) + IsolationForest",
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"classifier": clf, "isolation_forest": iso,
         "feature_order": FEATURE_ORDER, "metadata": meta},
        ARTIFACT_DIR / "model.joblib",
    )
    (ARTIFACT_DIR / "metrics.json").write_text(json.dumps(meta, indent=2))
    return meta


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the Warden risk model.")
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    meta = train(n=args.n, seed=args.seed)
    print(json.dumps(meta["metrics"], indent=2))
    print("Top features:", list(meta["feature_importances"].items())[:6])
    print(f"Artifact written to {ARTIFACT_DIR / 'model.joblib'}")


if __name__ == "__main__":
    main()
