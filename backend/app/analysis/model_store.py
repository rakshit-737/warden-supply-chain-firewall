"""Model artifact loading, integrity checks and inference, with a rules-only fallback.

Trust boundary
--------------
The artifact is a joblib **pickle**: deserialising it runs code embedded in the file, so a
model artifact is code, not data. Warden therefore:

* loads only the artifact packaged at ``app/analysis/artifacts/model.joblib``. No setting,
  environment variable or API parameter can point the store elsewhere (the constructor
  argument exists for tests and offline evaluation tooling only);
* reads the file once (size-capped), hashes the bytes, and — when
  ``settings.MODEL_ARTIFACT_SHA256`` is set — refuses to deserialise bytes whose sha256 differs.
  The pin is checked **before** unpickling, and the exact bytes that were hashed are the bytes
  deserialised, so there is no window to swap the file between check and use. A malformed pin
  also disables the model (fail closed). Without a pin, integrity rests on the permissions of
  the image or checkout;
* refuses an artifact whose feature schema hash (names + order + feature-set version) differs
  from :func:`app.analysis.features.feature_schema_hash` of the running code: a model trained on
  a different feature layout would silently score garbage.

Analysed package content is never unpickled — only this packaged, Warden-built artifact.

Every refusal leaves ``available = False`` with a machine-readable ``unavailable_reason``, a
path-free ``unavailable_detail`` and a log line; scoring then runs rules-only.

Versions
--------
``model_version`` is the first 16 hex characters of the artifact's sha256. It is derived from
the bytes actually loaded, not from metadata inside the file, and training deliberately keeps
wall-clock time out of the artifact so identical training inputs give an identical version.

Scores
------
``predict`` returns ``(ml_score, anomaly_score)``: ``ml_score = round(100 × calibrated
P(malicious))`` — deliberately *not* blended with the novelty score, so the number served is
the number the calibration metrics describe. ``anomaly_score`` (0..1) is reported separately:
``min(1, −log10(tail) / 3)`` where ``tail`` is the fraction of benign training samples at
least as novel under the IsolationForest (floored at ``1 / (n + 1)``). A typical benign
package scores about 0.1; 1.0 means rarer than one in a thousand benign training packages.
The v1 mapping (``0.5 − score_samples``) sat near 1.0 for ordinary packages.
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import io
import json
import math
import re
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash, to_vector
from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("warden.model")

_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
_ARTIFACT = _ARTIFACT_DIR / "model.joblib"
SIDECAR_NAME = "metrics.json"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_SIDECAR_BYTES = 16 * 1024 * 1024
ANOMALY_LOG_SCALE = 3.0
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class UnavailableReason:
    MISSING = "artifact_missing"
    UNREADABLE = "artifact_unreadable"
    TOO_LARGE = "artifact_too_large"
    PIN_INVALID = "artifact_pin_invalid"
    PIN_MISMATCH = "artifact_sha256_mismatch"
    LOAD_FAILED = "artifact_load_failed"
    INVALID = "artifact_invalid"
    SCHEMA_MISMATCH = "feature_schema_mismatch"


def normalize_sha256_pin(pin: Any) -> str | None:
    """Lower-case 64-hex digest from a pin (``sha256:`` prefix and whitespace allowed), else None."""
    if not isinstance(pin, str):
        return None
    value = pin.strip().lower()
    if value.startswith("sha256:"):
        value = value[len("sha256:"):].strip()
    return value if _SHA256_RE.match(value) else None


def novelty_to_anomaly(novelty: float, reference: Mapping[str, Any]) -> float:
    """Map an IsolationForest novelty (``-score_samples``) to 0..1 via benign training quantiles."""
    quantiles = reference.get("quantiles")
    n = reference.get("n")
    if not isinstance(quantiles, list) or len(quantiles) < 2 or not isinstance(n, int) or n < 1:
        return 0.0
    if not math.isfinite(novelty):
        return 1.0
    levels = len(quantiles) - 1
    if novelty <= quantiles[0]:
        cdf = 0.0
    elif novelty >= quantiles[-1]:
        cdf = 1.0
    else:
        i = bisect.bisect_right(quantiles, novelty) - 1
        low, high = quantiles[i], quantiles[i + 1]
        fraction = (novelty - low) / (high - low) if high > low else 1.0
        cdf = (i + fraction) / levels
    tail = max(1.0 - cdf, 1.0 / (n + 1))
    return max(0.0, min(1.0, -math.log10(tail) / ANOMALY_LOG_SCALE))


def _valid_reference(reference: Any) -> bool:
    if not isinstance(reference, Mapping):
        return False
    quantiles = reference.get("quantiles")
    return (
        isinstance(quantiles, list)
        and len(quantiles) >= 2
        and all(isinstance(q, (int, float)) and math.isfinite(q) for q in quantiles)
        and quantiles == sorted(quantiles)
        and isinstance(reference.get("n"), int)
    )


class ModelStore:
    def __init__(self, artifact_path: Path | None = None) -> None:
        self._path = Path(artifact_path) if artifact_path is not None else _ARTIFACT
        self._clf: Any = None
        self._iso: Any = None
        self._positive_index = 1
        self._metadata: dict[str, Any] = {}
        self._anomaly_reference: dict[str, Any] | None = None
        self._artifact_sha256: str | None = None
        self._trained_at: str | None = None
        self._reason: str | None = None
        self._detail: str | None = None
        self._explainer: Any = None
        self._explainer_lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------------ loading
    def _refuse(self, reason: str, detail: str, *, level: str = "warning") -> None:
        self._clf = None
        self._iso = None
        self._reason = reason
        self._detail = detail
        getattr(log, level)("model_unavailable", reason=reason, detail=detail, mode="rules_only",
                            artifact=self._path.name)

    def _read_artifact(self) -> bytes | None:
        try:
            size = self._path.stat().st_size
        except FileNotFoundError:
            self._refuse(UnavailableReason.MISSING, "no model artifact is packaged")
            return None
        except OSError as exc:
            self._refuse(UnavailableReason.UNREADABLE, f"artifact could not be read ({type(exc).__name__})")
            return None
        if not self._path.is_file():
            self._refuse(UnavailableReason.UNREADABLE, "artifact is not a regular file")
            return None
        if size > MAX_ARTIFACT_BYTES:
            self._refuse(UnavailableReason.TOO_LARGE, f"artifact is {size} bytes; limit {MAX_ARTIFACT_BYTES}")
            return None
        try:
            data = self._path.read_bytes()
        except OSError as exc:
            self._refuse(UnavailableReason.UNREADABLE, f"artifact could not be read ({type(exc).__name__})")
            return None
        if len(data) > MAX_ARTIFACT_BYTES:
            self._refuse(UnavailableReason.TOO_LARGE, f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit")
            return None
        return data

    def _load(self) -> None:
        data = self._read_artifact()
        if data is None:
            return
        digest = hashlib.sha256(data).hexdigest()
        self._artifact_sha256 = digest

        pin = settings.MODEL_ARTIFACT_SHA256
        if pin is not None and str(pin).strip():
            expected = normalize_sha256_pin(pin)
            if expected is None:
                self._refuse(UnavailableReason.PIN_INVALID,
                             "MODEL_ARTIFACT_SHA256 is not a 64-character hex sha256", level="error")
                return
            if not hmac.compare_digest(expected, digest):
                self._refuse(UnavailableReason.PIN_MISMATCH,
                             f"artifact sha256 {digest[:16]}… does not match MODEL_ARTIFACT_SHA256", level="error")
                return

        try:
            import joblib

            # Trusted, Warden-built artifact (see the module docstring's trust boundary); the bytes
            # deserialised are exactly the bytes hashed and pin-checked above.
            bundle = joblib.load(io.BytesIO(data))  # nosec B301
        except Exception as exc:
            self._refuse(UnavailableReason.LOAD_FAILED, f"artifact could not be deserialised ({type(exc).__name__})",
                         level="error")
            return
        self._accept(bundle, digest)

    def _accept(self, bundle: Any, digest: str) -> None:
        if not isinstance(bundle, dict):
            self._refuse(UnavailableReason.INVALID, "artifact is not a model bundle")
            return
        metadata = bundle.get("metadata")
        self._metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        clf = bundle.get("classifier")
        if not callable(getattr(clf, "predict_proba", None)):
            self._refuse(UnavailableReason.INVALID, "artifact has no probabilistic classifier")
            return

        running = feature_schema_hash()
        artifact_hash = bundle.get("feature_schema_hash") or self._metadata.get("feature_schema_hash")
        artifact_version = bundle.get("feature_set_version") or self._metadata.get("feature_set_version")
        order = bundle.get("feature_order")
        if artifact_hash != running or list(order or []) != FEATURE_ORDER:
            described = f"feature set {artifact_version}" if artifact_version else "a legacy artifact without a schema"
            self._refuse(
                UnavailableReason.SCHEMA_MISMATCH,
                f"artifact was trained on {described} (schema {str(artifact_hash or 'none')[:16]}); running code uses "
                f"feature set {FEATURE_SET_VERSION} (schema {running[:16]}); retrain with python -m ml.train",
                level="error",
            )
            return
        n_in = getattr(clf, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(FEATURE_ORDER):
            self._refuse(UnavailableReason.SCHEMA_MISMATCH,
                         f"classifier expects {n_in} features; running code has {len(FEATURE_ORDER)}", level="error")
            return
        classes = list(getattr(clf, "classes_", []))
        if 1 not in classes:
            self._refuse(UnavailableReason.INVALID, "classifier has no malicious class (label 1)")
            return

        iso = bundle.get("isolation_forest")
        reference = self._metadata.get("anomaly_reference")
        self._iso = iso if callable(getattr(iso, "score_samples", None)) else None
        self._anomaly_reference = dict(reference) if _valid_reference(reference) else None
        self._positive_index = classes.index(1)
        self._clf = clf
        self._reason = None
        self._detail = None
        self._trained_at = self._sidecar_trained_at(digest)
        log.info("model_loaded", model_version=self.model_version, feature_set_version=FEATURE_SET_VERSION,
                 pinned=bool(settings.MODEL_ARTIFACT_SHA256))

    def _sidecar_trained_at(self, digest: str) -> str | None:
        """``trained_at`` from metrics.json, trusted only when the sidecar names this artifact's sha256."""
        sidecar = self._path.with_name(SIDECAR_NAME)
        try:
            if not sidecar.is_file() or sidecar.stat().st_size > MAX_SIDECAR_BYTES:
                return None
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict) or payload.get("artifact_sha256") != digest:
            return None
        trained_at = payload.get("trained_at")
        return trained_at[:40] if isinstance(trained_at, str) else None

    # ------------------------------------------------------------------ state
    @property
    def available(self) -> bool:
        return self._clf is not None

    @property
    def unavailable_reason(self) -> str | None:
        return None if self.available else (self._reason or UnavailableReason.MISSING)

    @property
    def unavailable_detail(self) -> str | None:
        return None if self.available else self._detail

    @property
    def artifact_sha256(self) -> str | None:
        return self._artifact_sha256

    @property
    def model_version(self) -> str | None:
        return self._artifact_sha256[:16] if self.available and self._artifact_sha256 else None

    @property
    def trained_at(self) -> str | None:
        return self._trained_at if self.available else None

    @property
    def metadata(self) -> dict[str, Any]:
        """Artifact metadata plus identity fields. Empty unless the bundle was deserialised."""
        if not self._metadata:
            return {}
        return {
            **self._metadata,
            "model_version": self.model_version,
            "artifact_sha256": self._artifact_sha256,
            "trained_at": self.trained_at,
        }

    def reference_distribution(self, population: str = "benign") -> dict[str, Any] | None:
        refs = self._metadata.get("reference_distribution") if self.available else None
        chosen = refs.get(population) if isinstance(refs, Mapping) else None
        return dict(chosen) if isinstance(chosen, Mapping) else None

    # ------------------------------------------------------------------ inference
    def _proba(self, rows: np.ndarray) -> np.ndarray:
        return np.asarray(self._clf.predict_proba(rows), dtype=float)[:, self._positive_index]

    def predict_proba_rows(self, rows: Any) -> np.ndarray:
        """Calibrated P(malicious) for a matrix in FEATURE_ORDER (evaluation tooling)."""
        if not self.available:
            raise RuntimeError(f"model unavailable: {self.unavailable_reason}")
        matrix = np.nan_to_num(np.asarray(rows, dtype=float), nan=0.0, posinf=0.0, neginf=0.0)
        if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_ORDER):
            raise ValueError(f"expected an (n, {len(FEATURE_ORDER)}) matrix")
        return self._proba(matrix)

    def _anomaly(self, row: np.ndarray) -> float:
        if self._iso is None or self._anomaly_reference is None:
            return 0.0
        novelty = -float(self._iso.score_samples(row)[0])
        return novelty_to_anomaly(novelty, self._anomaly_reference)

    def predict(self, features: Mapping[str, Any]) -> tuple[int, float]:
        """Return ``(ml_score 0..100, anomaly_score 0..1)``; ``(0, 0.0)`` when unavailable."""
        if not self.available:
            return 0, 0.0
        row = np.asarray([to_vector(features)], dtype=float)
        proba = min(1.0, max(0.0, float(self._proba(row)[0])))
        return int(math.floor(proba * 100.0 + 0.5)), round(self._anomaly(row), 3)

    def explain(self, features: Mapping[str, Any], top_k: int = 8) -> dict[str, Any]:
        """Tree-path contributions for ``features`` (see :mod:`app.analysis.explain`)."""
        if not self.available:
            raise RuntimeError(f"model unavailable: {self.unavailable_reason}")
        if self._explainer is None:
            with self._explainer_lock:
                if self._explainer is None:
                    from app.analysis.explain import ForestExplainer

                    self._explainer = ForestExplainer(self._clf, FEATURE_ORDER)
        return self._explainer.explain(features, top_k=top_k)


_model_store: ModelStore | None = None
_store_lock = threading.Lock()


def get_model_store() -> ModelStore:
    global _model_store
    if _model_store is None:
        with _store_lock:
            if _model_store is None:
                _model_store = ModelStore()
    return _model_store


def reset_model_store() -> None:
    """Drop the cached store so the next call reloads the packaged artifact (tests, retraining)."""
    global _model_store
    with _store_lock:
        _model_store = None


__all__ = [
    "MAX_ARTIFACT_BYTES",
    "ModelStore",
    "UnavailableReason",
    "get_model_store",
    "normalize_sha256_pin",
    "novelty_to_anomaly",
    "reset_model_store",
]
