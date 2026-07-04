"""Model loading and inference wrapper.

Loads the persisted scikit-learn artifact once and exposes a simple ``predict`` returning a
0–100 ML risk score. If the artifact is absent or unloadable, ``available`` is False and
the scorer degrades gracefully to rules-only — the product keeps working without the model.
"""

from __future__ import annotations

from pathlib import Path

from app.analysis.features import FEATURE_ORDER, to_vector
from app.core.logging import get_logger

log = get_logger("warden.model")

_ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "model.joblib"


class ModelStore:
    def __init__(self) -> None:
        self._clf = None
        self._iso = None
        self._feature_order: list[str] = FEATURE_ORDER
        self._meta: dict = {}
        self._load()

    def _load(self) -> None:
        if not _ARTIFACT.exists():
            log.warning("model_artifact_missing", path=str(_ARTIFACT), mode="rules_only")
            return
        try:
            import joblib

            bundle = joblib.load(_ARTIFACT)
            self._clf = bundle["classifier"]
            self._iso = bundle.get("isolation_forest")
            self._feature_order = bundle.get("feature_order", FEATURE_ORDER)
            self._meta = bundle.get("metadata", {})
            log.info("model_loaded", metrics=self._meta.get("metrics", {}))
        except Exception as exc:  # pragma: no cover - depends on artifact
            log.error("model_load_failed", error=str(exc), mode="rules_only")
            self._clf = None

    @property
    def available(self) -> bool:
        return self._clf is not None

    @property
    def metadata(self) -> dict:
        return self._meta

    def predict(self, features: dict[str, float]) -> tuple[int, float]:
        """Return (ml_score 0..100, anomaly_score 0..1)."""
        if not self.available:
            return 0, 0.0
        vec = [to_vector(features)]
        proba = float(self._clf.predict_proba(vec)[0][1])
        anomaly = 0.0
        if self._iso is not None:
            # IsolationForest: lower score_samples => more anomalous. Map to 0..1.
            raw = float(self._iso.score_samples(vec)[0])
            anomaly = max(0.0, min(1.0, 0.5 - raw))
        # Blend supervised probability with the unsupervised novelty bump.
        blended = min(1.0, proba + 0.25 * anomaly)
        return round(blended * 100), round(anomaly, 3)


_model_store: ModelStore | None = None


def get_model_store() -> ModelStore:
    global _model_store
    if _model_store is None:
        _model_store = ModelStore()
    return _model_store
