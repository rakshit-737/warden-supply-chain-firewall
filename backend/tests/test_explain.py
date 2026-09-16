"""Tree-path explanations: exact additivity, determinism, scope statement and graceful failure.

Models are trained on the SYNTHETIC generator with a tiny configuration.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from app.analysis import explain as X
from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash
from app.analysis.model_store import ModelStore
from ml import generate_dataset as G
from ml.train import TrainConfig, train

TINY = TrainConfig(n_estimators=12, permutation_repeats=2, isolation_estimators=25, n_jobs=2)


@pytest.fixture(scope="module")
def store(tmp_path_factory) -> ModelStore:
    out = tmp_path_factory.mktemp("ml-explain")
    train(n=700, seed=31, artifact_dir=out, config=TINY, trained_at="2026-01-01T00:00:00+00:00")
    loaded = ModelStore(out / "model.joblib")
    assert loaded.available, loaded.unavailable_detail
    return loaded


@pytest.fixture(scope="module")
def samples():
    return G.generate_samples(400, seed=77)


def _forest_probability(classifier, row: np.ndarray) -> float:
    """Independent reference: mean of the base forests' own predict_proba (sklearn code path)."""
    forests = X.base_forests(classifier)
    return float(np.mean([f.predict_proba(row.reshape(1, -1))[0][list(f.classes_).index(1)] for f in forests]))


def test_contributions_sum_to_forest_probability_minus_bias(store, samples):
    features, _, groups = samples
    explainer = X.ForestExplainer(store._clf)
    chosen = sorted({groups.index(name) for name in set(groups)})  # one row per family
    assert len(chosen) >= 15
    for i in chosen:
        explanation = explainer.explain_vector(features[i])
        reference = _forest_probability(store._clf, features[i])
        assert explanation.forest_probability == pytest.approx(reference, abs=1e-9)
        assert float(explanation.contributions.sum()) == pytest.approx(reference - explanation.bias, abs=1e-9)
        assert explanation.additivity_error < 1e-9


def test_bias_is_the_mean_root_probability(store, samples):
    explanation = X.ForestExplainer(store._clf).explain_vector(samples[0][0])
    roots = []
    for forest in X.base_forests(store._clf):
        value = np.array([est.tree_.value[0, 0] for est in forest.estimators_])
        roots.append(np.mean(value[:, 1] / value.sum(axis=1)))
    assert explanation.bias == pytest.approx(float(np.mean(roots)), abs=1e-12)


def test_plain_random_forest_is_supported(samples):
    features, labels, _ = samples
    forest = RandomForestClassifier(n_estimators=10, max_depth=6, random_state=0, n_jobs=1).fit(features, labels)
    explainer = X.ForestExplainer(forest)
    for row in features[:25]:
        explanation = explainer.explain_vector(row)
        assert explanation.forest_probability == pytest.approx(forest.predict_proba(row.reshape(1, -1))[0][1], abs=1e-9)
        assert float(explanation.contributions.sum()) + explanation.bias == pytest.approx(
            explanation.forest_probability, abs=1e-9)


def test_dictionary_output_is_ranked_rounded_and_states_its_scope(store, samples):
    row = samples[0][5]
    explanation = X.ForestExplainer(store._clf).explain_vector(row)
    payload = explanation.to_dict(top_k=5)
    contributions = payload["contributions"]
    assert 1 <= len(contributions) <= 5
    magnitudes = [abs(c["contribution"]) for c in contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)
    assert all(c["feature"] in FEATURE_ORDER for c in contributions)
    for c in contributions:
        assert c["value"] == pytest.approx(row[FEATURE_ORDER.index(c["feature"])], abs=1e-6)
    total = sum(c["contribution"] for c in contributions) + payload["other_features_contribution"]
    assert total == pytest.approx(payload["forest_probability"] - payload["bias"], abs=1e-5)
    assert payload["explains"] == "uncalibrated_forest_probability"
    assert "uncalibrated" in payload["note"] and "not Shapley" in payload["note"]


def test_explanations_are_deterministic(store, samples):
    features = dict(zip(FEATURE_ORDER, samples[0][9]))
    first = store.explain(features, top_k=8)
    assert store.explain(features, top_k=8) == first
    assert X.ForestExplainer(store._clf).explain(features, top_k=8) == first


def test_explanations_point_in_the_direction_of_the_prediction(store, samples):
    """On this synthetic model, confidently flagged rows are pushed up and confidently benign rows down."""
    features, _, _ = samples
    explainer = X.ForestExplainer(store._clf)
    high = [row for row in features if store.predict(dict(zip(FEATURE_ORDER, row)))[0] >= 90][:5]
    low = [row for row in features if store.predict(dict(zip(FEATURE_ORDER, row)))[0] <= 5][:5]
    assert high and low
    for row in high:
        explanation = explainer.explain_vector(row)
        assert explanation.forest_probability > explanation.bias
        assert explanation.to_dict(top_k=1)["contributions"][0]["contribution"] > 0
    for row in low:
        explanation = explainer.explain_vector(row)
        assert explanation.forest_probability < explanation.bias


def test_unsupported_models_are_rejected(samples):
    features, labels, _ = samples
    with pytest.raises(X.UnsupportedModelError):
        X.ForestExplainer(LogisticRegression(max_iter=200).fit(features, labels))
    with pytest.raises(X.UnsupportedModelError):
        X.ForestExplainer(object())
    narrow = RandomForestClassifier(n_estimators=3, random_state=0).fit(features[:, :10], labels)
    with pytest.raises(X.UnsupportedModelError):
        X.ForestExplainer(narrow)
    single_class = RandomForestClassifier(n_estimators=3, random_state=0).fit(features, np.zeros(len(labels)))
    with pytest.raises(X.UnsupportedModelError):
        X.ForestExplainer(single_class)


@pytest.mark.parametrize("vector", [[0.0] * 35, [0.0] * 37, [float("nan")] + [0.0] * 35, [float("inf")] * 36])
def test_invalid_vectors_are_rejected(store, vector):
    with pytest.raises(ValueError):
        X.ForestExplainer(store._clf).explain_vector(vector)


class _UnavailableStore:
    available = False


class _BrokenStore:
    available = True
    model_version = "fixture0000000000"

    def explain(self, features, top_k=8):
        raise RuntimeError("boom with a secret-looking message AKIAIOSFODNN7EXAMPLE")


def test_ml_explanation_never_raises_and_reports_status(store, samples):
    features = dict(zip(FEATURE_ORDER, samples[0][1]))
    unavailable = X.ml_explanation(features, store=_UnavailableStore())
    assert unavailable["explanation_status"] == "model_unavailable"
    assert unavailable["feature_set_version"] == FEATURE_SET_VERSION
    assert unavailable["feature_schema_hash"] == feature_schema_hash()
    broken = X.ml_explanation(features, store=_BrokenStore())
    assert broken["explanation_status"] == "error" and broken["error_type"] == "RuntimeError"
    assert "AKIA" not in repr(broken)  # exception messages are never copied into results
    ok = X.ml_explanation(features, store=store, top_k=3)
    assert ok["explanation_status"] == "ok" and ok["model_version"] == store.model_version
    assert len(ok["contributions"]) <= 3


def test_store_explain_requires_an_available_model(tmp_path):
    missing = ModelStore(tmp_path / "absent.joblib")
    with pytest.raises(RuntimeError):
        missing.explain(dict.fromkeys(FEATURE_ORDER, 0.0))
