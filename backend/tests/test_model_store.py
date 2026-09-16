"""Model store: artifact integrity (sha256 pin before deserialisation), feature-schema refusal, scores.

Artifacts are produced by the real training code on the SYNTHETIC generator (tiny configuration);
tampered variants are test-owned files, never analysed package content.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
from pathlib import Path

import joblib
import numpy as np
import pytest

from app.analysis import model_store as MS
from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash
from app.core.config import settings
from ml import generate_dataset as G
from ml.train import TrainConfig, train

TINY = TrainConfig(n_estimators=12, permutation_repeats=2, isolation_estimators=25, n_jobs=2)
TRAINED_AT = "2026-01-01T00:00:00+00:00"


@pytest.fixture(scope="module")
def artifact_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("ml-store")
    train(n=700, seed=41, artifact_dir=out, config=TINY, trained_at=TRAINED_AT)
    return out


@pytest.fixture()
def artifact(artifact_dir, tmp_path) -> Path:
    """A private copy (artifact + sidecar) that a test may tamper with."""
    for name in ("model.joblib", "metrics.json"):
        shutil.copyfile(artifact_dir / name, tmp_path / name)
    return tmp_path / "model.joblib"


@pytest.fixture(autouse=True)
def _no_pin(monkeypatch):
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", None)


class _LogRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def __getattr__(self, level):
        return lambda event, **kw: self.events.append((level, event, kw))


@pytest.fixture()
def log(monkeypatch) -> _LogRecorder:
    recorder = _LogRecorder()
    monkeypatch.setattr(MS, "log", recorder)
    return recorder


@pytest.fixture()
def load_spy(monkeypatch):
    """Records every deserialisation attempt (and still performs it)."""
    calls: list[int] = []
    real = joblib.load

    def spy(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(joblib, "load", spy)
    return calls


def _rows(n: int = 300, seed: int = 5):
    return G.generate_samples(n, seed=seed)


def _rewrite_bundle(path: Path, **changes) -> None:
    bundle = joblib.load(path)
    bundle.update(changes)
    joblib.dump(bundle, path)


# =========================================================================== happy path
def test_valid_artifact_loads_with_content_derived_identity(artifact):
    store = MS.ModelStore(artifact)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert store.available and store.unavailable_reason is None and store.unavailable_detail is None
    assert store.artifact_sha256 == digest and store.model_version == digest[:16]
    assert store.trained_at == TRAINED_AT
    meta = store.metadata
    assert meta["feature_set_version"] == FEATURE_SET_VERSION
    assert meta["feature_schema_hash"] == feature_schema_hash()
    assert meta["model_version"] == store.model_version
    assert set(store.reference_distribution("benign")) == set(FEATURE_ORDER)
    assert set(store.reference_distribution("all")) == set(FEATURE_ORDER)
    assert store.reference_distribution("unknown") is None


def test_predictions_are_bounded_deterministic_and_unblended(artifact):
    store = MS.ModelStore(artifact)
    X, _, _ = _rows()
    proba = store.predict_proba_rows(X)
    for row, p in zip(X[:60], proba[:60]):
        features = dict(zip(FEATURE_ORDER, row))
        score, anomaly = store.predict(features)
        assert isinstance(score, int) and 0 <= score <= 100
        assert 0.0 <= anomaly <= 1.0
        assert (score, anomaly) == store.predict(features)
        # ml_score is exactly the calibrated probability; the anomaly score is never added to it.
        assert score == math.floor(p * 100 + 0.5)


def test_hard_negatives_score_below_malicious_archetypes_on_synthetic_data(artifact):
    """False-positive smoke test: benign families with 'suspicious' capabilities stay well below attacks."""
    store = MS.ModelStore(artifact)
    X, y, groups = _rows(3000, seed=6)
    proba = store.predict_proba_rows(X)
    hard = np.array([g in G.HARD_NEGATIVE_FAMILIES for g in groups])
    assert np.mean(proba[hard] >= 0.5) < 0.1
    assert np.median(proba[hard]) < 0.2 < np.median(proba[y == 1])


def test_anomaly_score_is_low_for_typical_benign_rows(artifact):
    """The v1 mapping (0.5 - score_samples) put ordinary packages near 1.0."""
    store = MS.ModelStore(artifact)
    X, y, _ = _rows(600, seed=7)
    anomalies = np.array([store.predict(dict(zip(FEATURE_ORDER, row)))[1] for row in X])
    assert np.median(anomalies[y == 0]) < 0.35
    assert np.median(anomalies[y == 1]) > np.median(anomalies[y == 0])


# =========================================================================== refusals
def test_missing_artifact_runs_rules_only(tmp_path, log):
    store = MS.ModelStore(tmp_path / "absent.joblib")
    assert not store.available
    assert store.unavailable_reason == MS.UnavailableReason.MISSING
    assert store.predict(dict.fromkeys(FEATURE_ORDER, 1.0)) == (0, 0.0)
    assert store.model_version is None and store.metadata == {} and store.reference_distribution() is None
    assert str(tmp_path) not in (store.unavailable_detail or "")
    assert any(e[1] == "model_unavailable" and e[2]["reason"] == "artifact_missing" for e in log.events)
    with pytest.raises(RuntimeError):
        store.predict_proba_rows(np.zeros((1, 36)))


def test_feature_schema_mismatch_disables_the_model_and_logs_the_reason(artifact, log):
    _rewrite_bundle(artifact, feature_schema_hash="0" * 64)
    store = MS.ModelStore(artifact)
    assert not store.available and store.unavailable_reason == MS.UnavailableReason.SCHEMA_MISMATCH
    assert "feature set" in store.unavailable_detail and str(artifact.parent) not in store.unavailable_detail
    assert store.predict(dict.fromkeys(FEATURE_ORDER, 1.0)) == (0, 0.0)
    events = [e for e in log.events if e[1] == "model_unavailable"]
    assert events and events[0][0] == "error" and events[0][2]["reason"] == "feature_schema_mismatch"
    assert events[0][2]["mode"] == "rules_only"


def test_legacy_v1_artifact_without_schema_is_refused(artifact):
    bundle = joblib.load(artifact)
    legacy = {"classifier": bundle["classifier"], "isolation_forest": bundle["isolation_forest"],
              "feature_order": FEATURE_ORDER[:16], "metadata": {"metrics": {"accuracy": 0.99}}}
    joblib.dump(legacy, artifact)
    store = MS.ModelStore(artifact)
    assert store.unavailable_reason == MS.UnavailableReason.SCHEMA_MISMATCH
    assert "legacy artifact" in store.unavailable_detail


def test_feature_order_tampering_is_refused_even_with_the_right_hash(artifact):
    _rewrite_bundle(artifact, feature_order=list(reversed(FEATURE_ORDER)))
    assert MS.ModelStore(artifact).unavailable_reason == MS.UnavailableReason.SCHEMA_MISMATCH


def test_sha256_pin_mismatch_disables_the_model_before_deserialisation(artifact, monkeypatch, load_spy, log):
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", "f" * 64)
    store = MS.ModelStore(artifact)
    assert not store.available and store.unavailable_reason == MS.UnavailableReason.PIN_MISMATCH
    assert load_spy == []  # the pickle was never opened
    assert store.predict(dict.fromkeys(FEATURE_ORDER, 1.0)) == (0, 0.0)
    assert any(e[2].get("reason") == "artifact_sha256_mismatch" for e in log.events)


def test_tampered_artifact_is_refused_under_a_pin(artifact, monkeypatch, load_spy):
    pin = hashlib.sha256(artifact.read_bytes()).hexdigest()
    _rewrite_bundle(artifact, format="tampered")
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", pin)
    load_spy.clear()
    assert MS.ModelStore(artifact).unavailable_reason == MS.UnavailableReason.PIN_MISMATCH
    assert load_spy == []


@pytest.mark.parametrize("transform", [str, str.upper, lambda d: f"sha256:{d}", lambda d: f"  {d}\n"])
def test_matching_pin_is_accepted_in_normalised_forms(artifact, monkeypatch, transform):
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", transform(digest))
    assert MS.ModelStore(artifact).available


def test_malformed_pin_fails_closed(artifact, monkeypatch, load_spy):
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", "not-a-sha256")
    store = MS.ModelStore(artifact)
    assert store.unavailable_reason == MS.UnavailableReason.PIN_INVALID and load_spy == []


def test_blank_pin_means_no_pin(artifact, monkeypatch):
    monkeypatch.setattr(settings, "MODEL_ARTIFACT_SHA256", "   ")
    assert MS.ModelStore(artifact).available


def test_corrupt_non_bundle_and_classifier_less_artifacts_are_refused(tmp_path):
    corrupt = tmp_path / "corrupt.joblib"
    corrupt.write_bytes(b"\x80\x04 definitely not a pickle stream")
    assert MS.ModelStore(corrupt).unavailable_reason == MS.UnavailableReason.LOAD_FAILED
    listing = tmp_path / "list.joblib"
    joblib.dump([1, 2, 3], listing)
    assert MS.ModelStore(listing).unavailable_reason == MS.UnavailableReason.INVALID
    no_classifier = tmp_path / "noclf.joblib"
    joblib.dump({"classifier": "text", "feature_order": FEATURE_ORDER,
                 "feature_schema_hash": feature_schema_hash()}, no_classifier)
    assert MS.ModelStore(no_classifier).unavailable_reason == MS.UnavailableReason.INVALID


def test_oversized_artifact_is_refused_without_reading(artifact, monkeypatch, load_spy):
    monkeypatch.setattr(MS, "MAX_ARTIFACT_BYTES", 10)
    assert MS.ModelStore(artifact).unavailable_reason == MS.UnavailableReason.TOO_LARGE
    assert load_spy == []


def test_directory_in_place_of_artifact_is_refused(tmp_path):
    (tmp_path / "model.joblib").mkdir()
    assert MS.ModelStore(tmp_path / "model.joblib").unavailable_reason == MS.UnavailableReason.UNREADABLE


def test_sidecar_trained_at_is_trusted_only_for_the_matching_artifact(artifact):
    sidecar = artifact.with_name("metrics.json")
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["artifact_sha256"] = "0" * 64
    sidecar.write_text(json.dumps(payload), encoding="utf-8")
    store = MS.ModelStore(artifact)
    assert store.available and store.trained_at is None
    sidecar.write_text("{not json", encoding="utf-8")
    assert MS.ModelStore(artifact).trained_at is None


# =========================================================================== helpers
def test_normalize_sha256_pin():
    digest = "a" * 64
    assert MS.normalize_sha256_pin(digest.upper()) == digest
    assert MS.normalize_sha256_pin(f"SHA256:{digest}") == digest
    for bad in ("", "a" * 63, "g" * 64, None, 42, "sha256:"):
        assert MS.normalize_sha256_pin(bad) is None


def test_novelty_to_anomaly_mapping():
    reference = {"quantiles": [float(q) for q in np.linspace(0.3, 0.7, 1001)], "n": 3000}
    values = [MS.novelty_to_anomaly(x, reference) for x in (0.2, 0.3, 0.5, 0.66, 0.699, 0.9)]
    assert values == sorted(values)
    assert values[0] == 0.0
    assert MS.novelty_to_anomaly(0.5, reference) == pytest.approx(-math.log10(0.5) / 3, abs=1e-3)
    assert values[-1] == 1.0 and MS.novelty_to_anomaly(float("inf"), reference) == 1.0
    assert MS.novelty_to_anomaly(0.5, {"quantiles": [0.1], "n": 3}) == 0.0
    assert MS.novelty_to_anomaly(0.5, {}) == 0.0


def test_singleton_loads_only_the_packaged_path(monkeypatch, artifact):
    assert MS._ARTIFACT == Path(MS.__file__).resolve().parent / "artifacts" / "model.joblib"
    monkeypatch.setattr(MS, "_ARTIFACT", artifact)
    monkeypatch.setattr(MS, "_model_store", None)
    first = MS.get_model_store()
    assert first is MS.get_model_store() and first.available
    MS.reset_model_store()
    assert MS._model_store is None
