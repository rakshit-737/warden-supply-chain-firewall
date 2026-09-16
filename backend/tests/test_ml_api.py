"""ML API: RBAC (ml:read), model metadata hygiene, and PSI drift over stored scan feature vectors.

The served model is a tiny artifact trained on the SYNTHETIC generator; scan rows are test fixtures
inserted with future timestamps so they are the most recent rows the drift query sees.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import numpy as np
import pytest
from sqlalchemy import delete

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash
from app.analysis.model_store import ModelStore
from app.api.routers import ml as ml_routes
from app.core.permissions import Permission, Role
from app.core.security import create_access_token, hash_password
from app.db.models import Decision, Scan, Severity, User
from app.db.session import SessionLocal
from ml import generate_dataset as G
from ml.evaluate import SYNTHETIC_LABEL
from ml.train import TrainConfig, train
from tests.conftest import auth

API = "/api/v1"
TINY = TrainConfig(n_estimators=12, permutation_repeats=2, isolation_estimators=25, n_jobs=2)
_offsets = itertools.count(1)


@pytest.fixture(scope="module")
def trained_store(tmp_path_factory) -> ModelStore:
    out = tmp_path_factory.mktemp("ml-api")
    train(n=700, seed=51, artifact_dir=out, config=TINY, trained_at="2026-01-01T00:00:00+00:00")
    store = ModelStore(out / "model.joblib")
    assert store.available
    return store


@pytest.fixture(autouse=True)
def served(monkeypatch, trained_store):
    monkeypatch.setattr(ml_routes, "get_model_store", lambda: trained_store)
    return trained_store


@lru_cache(maxsize=1)
def _password_hash() -> str:
    return hash_password("Ml-Api-Test-Passw0rd!")


@pytest.fixture(scope="module")
def tokens() -> dict[Role, str]:
    out = {}
    with SessionLocal() as db:
        for role in Role:
            user = User(id=uuid.uuid4(), email=f"ml-api-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                        password_hash=_password_hash(), role=role)
            db.add(user)
            db.flush()
            out[role] = create_access_token(subject=str(user.id), role=role.value)
        db.commit()
    return out


@pytest.fixture()
def scan_rows():
    created: list[uuid.UUID] = []

    def insert(vectors, explanation=None) -> None:
        base = datetime.now(timezone.utc) + timedelta(days=3650, hours=next(_offsets))
        with SessionLocal() as db:
            for i, vector in enumerate(vectors):
                row = Scan(
                    id=uuid.uuid4(), ecosystem="pypi", package_name=f"ml-drift-{uuid.uuid4().hex[:12]}",
                    version="1.0.0", analyzer_version="ml-api-test", severity=Severity.info,
                    decision=Decision.allow, feature_vector=vector, explanation=explanation,
                    created_at=base + timedelta(seconds=i),
                )
                db.add(row)
                created.append(row.id)
            db.commit()

    yield insert
    with SessionLocal() as db:
        db.execute(delete(Scan).where(Scan.id.in_(created)))
        db.commit()


def _vectors(n: int, seed: int, **overrides: float) -> list[dict[str, float]]:
    X, y, _ = G.generate_samples(n * 3, seed=seed)
    rows = [dict(zip(FEATURE_ORDER, map(float, row))) for row, label in zip(X, y) if label == 0][:n]
    assert len(rows) == n
    for row in rows:
        row.update(overrides)
    return rows


# =========================================================================== RBAC
@pytest.mark.parametrize("role", list(Role), ids=lambda r: r.value)
@pytest.mark.parametrize("path", ["/ml/model", "/ml/drift?limit=5"])
def test_every_role_with_ml_read_can_read(client, tokens, role, path):
    resp = client.get(API + path, headers=auth(tokens[role]))
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("path", ["/ml/model", "/ml/drift"])
def test_ml_routes_reject_anonymous_and_invalid_tokens(client, path):
    assert client.get(API + path).status_code == 401
    assert client.get(API + path, headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_ml_routes_are_guarded_by_ml_read():
    routes = list(ml_routes.router.routes)
    assert {r.path for r in routes} == {"/ml/model", "/ml/drift"}
    for route in routes:
        guards = [d.call for d in route.dependant.dependencies if getattr(d.call, "required_permissions", None)]
        assert [g.required_permissions for g in guards] == [{Permission.ML_READ}], route.path


# =========================================================================== /ml/model
def test_model_payload_is_metadata_only(client, tokens, served):
    resp = client.get(API + "/ml/model", headers=auth(tokens[Role.read_only]))
    body = resp.json()
    assert body["available"] is True and body["unavailable_reason"] is None
    assert body["version"] == body["model_version"] == served.model_version
    assert body["feature_set_version"] == FEATURE_SET_VERSION == body["artifact_feature_set_version"]
    assert body["feature_schema_hash"] == feature_schema_hash()
    assert body["features"] == FEATURE_ORDER and set(body["feature_descriptions"]) == set(FEATURE_ORDER)
    assert body["evaluation_label"] == SYNTHETIC_LABEL
    metrics = body["metrics"]
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier_score"):
        assert isinstance(metrics[key], float), key
    assert all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in metrics.values())
    impurity = body["feature_importances"]["impurity"]
    assert isinstance(impurity["secrets_count"], float)  # a feature name, not a credential: never redacted
    assert body["dataset"]["synthetic"] is True and body["dataset"]["generator_hash"]
    assert body["drift_reference_populations"] == ["all", "benign"]
    text = resp.text
    assert served._path.parent.name not in text and ".joblib" not in text
    assert "object at 0x" not in text and "reference_distribution" not in text and "quantiles" not in text


def test_model_endpoint_reports_an_unavailable_model(client, tokens, monkeypatch, tmp_path):
    missing = ModelStore(tmp_path / "absent.joblib")
    monkeypatch.setattr(ml_routes, "get_model_store", lambda: missing)
    body = client.get(API + "/ml/model", headers=auth(tokens[Role.developer])).json()
    assert body["available"] is False and body["unavailable_reason"] == "artifact_missing"
    assert body["version"] is None and body["metrics"] == {} and body["artifact_sha256"] is None
    assert str(tmp_path) not in str(body)


# =========================================================================== /ml/drift
def test_drift_below_minimum_sample_is_insufficient_data(client, tokens, scan_rows):
    scan_rows(_vectors(45, seed=3))
    body = client.get(API + "/ml/drift?limit=45", headers=auth(tokens[Role.auditor])).json()
    assert body["status"] == "insufficient_data"
    assert body["sample_size"] == 45 and body["min_samples"] == 50
    assert body["features"] == [] and body["summary"] is None


def test_drift_computes_psi_and_flags_a_shifted_feature(client, tokens, scan_rows):
    scan_rows(_vectors(80, seed=4, install_hook_exec=1.0, yanked_release=0.95))
    body = client.get(API + "/ml/drift?limit=80", headers=auth(tokens[Role.security_analyst])).json()
    assert body["status"] == "ok" and body["sample_size"] == 80
    assert body["rows_excluded"] == {"other_feature_set": 0, "invalid_values": 0}
    features = body["features"]
    assert len(features) == len(FEATURE_ORDER)
    assert [f["score"] for f in features] == sorted((f["score"] for f in features), reverse=True)
    by_name = {f["name"]: f for f in features}
    for name in ("install_hook_exec", "yanked_release"):
        assert by_name[name]["drifted"] is True and by_name[name]["status"] == "significant"
        assert by_name[name]["score"] == by_name[name]["psi"] > 0.25
    for entry in features:
        assert len(entry["expected"]) == len(entry["actual"]) == len(entry["cuts"]) + 1
    assert body["summary"]["drift_detected"] is True and body["summary"]["max_psi"] == features[0]["score"]
    assert body["model_version"] == ml_routes.get_model_store().model_version


def test_drift_uses_only_rows_from_the_current_feature_set(client, tokens, scan_rows):
    v1_rows = [{name: 0.0 for name in FEATURE_ORDER[:16]} for _ in range(30)]
    scan_rows(v1_rows)
    scan_rows(_vectors(30, seed=5), explanation={"ml": {"feature_set_version": "1"}})
    scan_rows([{**row, "network_egress": "yes"} for row in _vectors(5, seed=6)])
    scan_rows(_vectors(10, seed=7), explanation={"ml": {"feature_set_version": FEATURE_SET_VERSION}})
    body = client.get(API + "/ml/drift?limit=75", headers=auth(tokens[Role.admin])).json()
    assert body["rows_examined"] == 75
    assert body["rows_excluded"] == {"other_feature_set": 60, "invalid_values": 5}
    assert body["sample_size"] == 10 and body["status"] == "insufficient_data"


def test_drift_reports_an_unavailable_model(client, tokens, monkeypatch, tmp_path):
    missing = ModelStore(tmp_path / "absent.joblib")
    monkeypatch.setattr(ml_routes, "get_model_store", lambda: missing)
    body = client.get(API + "/ml/drift", headers=auth(tokens[Role.read_only])).json()
    assert body["status"] == "model_unavailable" and body["reason"] == "artifact_missing"
    assert body["features"] == []


@pytest.mark.parametrize("query", ["limit=0", "limit=5001", "limit=abc", "reference=everything"])
def test_drift_query_validation(client, tokens, query):
    assert client.get(API + f"/ml/drift?{query}", headers=auth(tokens[Role.admin])).status_code == 422


def test_compute_drift_requires_a_complete_reference(served):
    reference = dict(served.reference_distribution("benign"))
    reference.pop("yanked_release")
    assert ml_routes.compute_drift([], reference)["status"] == "no_reference"
    broken = {**served.reference_distribution("benign"), "network_egress": {"cuts": [1, 0], "proportions": [1]}}
    assert ml_routes.compute_drift([], broken)["status"] == "no_reference"
    rows = [(dict(zip(FEATURE_ORDER, np.zeros(36).tolist())), None)] * 60
    assert ml_routes.compute_drift(rows, served.reference_distribution("all"))["status"] == "ok"
