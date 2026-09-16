"""ML pipeline v2: feature set, SYNTHETIC dataset, CSV validation, evaluation, training and drift maths.

Everything is offline. Training uses the seeded synthetic generator with a deliberately tiny
configuration; the numbers it produces are synthetic hold-out evaluations, asserted only for
shape, determinism and range - never as evidence of real-world performance.
"""

from __future__ import annotations

import hashlib
import math
import random
from pathlib import Path

import numpy as np
import pytest

from app.analysis import features as F
from app.analysis.analyzers.base import PackageContext
from app.analysis.findings import Finding, Severity
from app.analysis.signals import Code
from ml import evaluate as E
from ml import generate_dataset as G
from ml.datasets import CSVLabeledDataset, DatasetValidationError, SyntheticDataset, generator_hash, normalized_sha256
from ml.train import TrainConfig, train

V1_FEATURES = [
    "install_hook_exec", "network_egress", "subprocess_exec", "dynamic_exec", "obfuscation_score", "encoded_exec",
    "env_harvest", "fs_sensitive_write", "dangerous_import_count", "typosquat_distance", "ioc_hits",
    "package_age_days", "maintainer_count", "has_repo_url", "release_count", "new_package",
]
V2_FEATURES = [
    "attack_chain_count", "max_chain_confidence", "pth_startup_hook", "build_backend_hook", "persistence",
    "browser_credential_access", "suspicious_download", "dns_exfiltration", "shell_invocation", "reflection_abuse",
    "layered_encoding", "string_reconstruction", "secrets_count", "binary_executable", "nested_archive",
    "hash_mismatch", "dependency_confusion", "dormant_revival", "maintainer_changed", "yanked_release",
]
TINY = TrainConfig(n_estimators=12, permutation_repeats=2, isolation_estimators=25, n_jobs=2)
FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _finding(code: str, confidence: float = 0.8, weight: float = 1.0, severity: Severity = Severity.medium,
             **evidence) -> Finding:
    return Finding(code, severity, weight, f"{code} test fixture", dict(evidence), confidence=confidence)


def _ctx(**metadata) -> PackageContext:
    return PackageContext("pypi", "fixture-package", "1.0.0", metadata=metadata)


def _baseline() -> dict[str, float]:
    return F.build_features([], None)


# =========================================================================== feature set
def test_feature_order_is_append_only_with_v1_prefix():
    assert F.FEATURE_SET_VERSION == "2"
    assert F.FEATURE_ORDER[:16] == V1_FEATURES
    assert F.FEATURE_ORDER[16:] == V2_FEATURES
    assert len(set(F.FEATURE_ORDER)) == len(F.FEATURE_ORDER) == 36
    assert set(F.FEATURE_DESCRIPTIONS) == set(F.FEATURE_ORDER)


def test_feature_schema_hash_covers_names_order_and_version():
    digest = F.feature_schema_hash()
    assert len(digest) == 64 and int(digest, 16) >= 0
    assert F.feature_schema_hash() == digest
    assert F.feature_schema_hash(version="3") != digest
    swapped = list(F.FEATURE_ORDER)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert F.feature_schema_hash(order=swapped) != digest
    assert F.feature_schema_hash(order=[*F.FEATURE_ORDER, "new_feature"]) != digest


def test_no_findings_yields_documented_baseline():
    features = _baseline()
    assert list(features) == F.FEATURE_ORDER
    ones = {"package_age_days", "maintainer_count", "has_repo_url"}  # unknown age reads as new; v1 semantics
    assert {k for k, v in features.items() if v != 0.0} == ones
    assert all(features[k] == 1.0 for k in ones)


def test_v1_feature_semantics_are_preserved():
    findings = [
        _finding(Code.INSTALL_HOOK_EXEC, weight=12),
        _finding(Code.NETWORK_EGRESS),
        _finding(Code.DYNAMIC_EXEC, calls=["eval", "exec", "compile"]),
        _finding(Code.OBFUSCATION, obfuscation_score=0.7),
        _finding(Code.DANGEROUS_IMPORT, modules=["socket", "ctypes"]),
        _finding(Code.TYPOSQUAT, distance=1),
        _finding(Code.IOC_MATCH, matches=["evil.example", "1.2.3.4"]),
        _finding(Code.NO_SOURCE_REPO),
        _finding(Code.NEW_PACKAGE),
    ]
    features = F.build_features(findings, _ctx(_age_days=0, _maintainer_count=2, _releases_last_7d=3))
    assert features["install_hook_exec"] == 1.0
    assert features["network_egress"] == 1.0
    assert features["subprocess_exec"] == 0.0
    assert features["dynamic_exec"] == 3.0
    assert features["obfuscation_score"] == pytest.approx(0.7)
    assert features["dangerous_import_count"] == 2.0
    assert features["typosquat_distance"] == 1.0
    assert features["ioc_hits"] == 2.0
    assert features["package_age_days"] == 1.0
    assert features["maintainer_count"] == 2.0
    assert features["has_repo_url"] == 0.0
    assert features["release_count"] == 3.0
    assert features["new_package"] == 1.0


def test_strength_features_take_the_highest_confidence_independent_of_order():
    findings = [
        _finding(Code.PTH_STARTUP_HOOK, confidence=0.6),
        _finding(Code.PTH_STARTUP_HOOK, confidence=0.9),
        _finding(Code.DNS_EXFILTRATION, confidence=0.87),
        _finding(Code.NETWORK_EGRESS, confidence=0.5),
    ]
    expected = F.build_features(findings)
    assert expected["pth_startup_hook"] == pytest.approx(0.9)
    assert expected["dns_exfiltration"] == pytest.approx(0.87)
    for seed in range(5):
        shuffled = list(findings)
        random.Random(seed).shuffle(shuffled)
        assert F.build_features(shuffled) == expected


@pytest.mark.parametrize(
    "contexts,expected",
    [
        (["test"], 0.45),        # test-file-only behaviour counts at half strength
        (["install"], 0.9),
        (["runtime"], 0.9),
        (["TEST "], 0.45),       # normalised
        ([None], 0.9),           # no recorded context: full strength
    ],
)
def test_test_file_context_is_discounted(contexts, expected):
    findings = [_finding(Code.SHELL_INVOCATION, confidence=0.9, **({"context": c} if c else {})) for c in contexts]
    assert F.build_features(findings)["shell_invocation"] == pytest.approx(expected)


def test_attack_chain_and_secret_counts_are_weighted_and_capped():
    chains = [_finding(Code.ATTACK_CHAIN, confidence=c, severity=Severity.critical, chain=i)
              for i, c in enumerate((0.7, 0.92, 0.8))]
    secrets = [_finding(Code.SECRET_DETECTED, confidence=0.95, fingerprint=f"fp-{i}") for i in range(12)]
    test_secrets = [_finding(Code.SECRET_DETECTED, confidence=0.95, context="test", fingerprint=f"t-{i}")
                    for i in range(3)]
    features = F.build_features([*chains, *secrets])
    assert features["attack_chain_count"] == 3.0
    assert features["max_chain_confidence"] == pytest.approx(0.92)
    assert features["secrets_count"] == F.MAX_SECRETS
    assert F.build_features(test_secrets)["secrets_count"] == pytest.approx(1.5)


def test_truncation_summary_findings_do_not_inflate_strength():
    """Inventory's per-code cap emits an info summary with confidence 1.0; it is not an observation."""
    wheel_extension = _finding(Code.BINARY_EXECUTABLE, confidence=0.35, magic="elf", sha256="ab" * 32)
    summary = _finding(Code.BINARY_EXECUTABLE, confidence=1.0, weight=0.0, severity=Severity.info, omitted=40, cap=50)
    assert F.build_features([wheel_extension, summary])["binary_executable"] == pytest.approx(0.35)


def test_vulnerability_findings_are_not_model_features():
    vulns = [
        _finding(Code.KNOWN_VULNERABILITY, confidence=0.99, severity=Severity.critical,
                 vulnerability={"id": "FIXTURE-2026-0001", "cvss_score": 9.8}),
        _finding(Code.KNOWN_EXPLOITED_VULNERABILITY, confidence=1.0, severity=Severity.critical,
                 vulnerability={"id": "FIXTURE-2026-0002", "kev": True}),
    ]
    assert F.build_features(vulns) == _baseline()


@pytest.mark.parametrize(
    "finding,feature",
    [
        (_finding(Code.OBFUSCATION, obfuscation_score="NaN"), "obfuscation_score"),
        (_finding(Code.OBFUSCATION, obfuscation_score=float("inf")), "obfuscation_score"),
        (_finding(Code.OBFUSCATION, obfuscation_score=1e9), "obfuscation_score"),
        (_finding(Code.DYNAMIC_EXEC, calls=12345), "dynamic_exec"),
        (_finding(Code.DYNAMIC_EXEC, calls=["eval"] * 1000), "dynamic_exec"),
        (_finding(Code.DANGEROUS_IMPORT, modules={"os": 1}), "dangerous_import_count"),
        (_finding(Code.TYPOSQUAT, distance="abc"), "typosquat_distance"),
        (_finding(Code.IOC_MATCH, matches="not-a-list"), "ioc_hits"),
        (_finding(Code.PTH_STARTUP_HOOK, confidence=float("nan")), "pth_startup_hook"),
    ],
)
def test_hostile_evidence_values_stay_finite_and_bounded(finding, feature):
    features = F.build_features([finding])
    assert all(math.isfinite(v) for v in features.values())
    upper = {"dynamic_exec": F.MAX_DYNAMIC_EXEC, "dangerous_import_count": F.MAX_DANGEROUS_IMPORTS,
             "ioc_hits": F.MAX_IOC_HITS}.get(feature, 1.0)
    assert 0.0 <= features[feature] <= upper


@pytest.mark.parametrize(
    "metadata,expected",
    [
        ({"_age_days": True}, {"package_age_days": 1.0}),
        ({"_age_days": float("nan")}, {"package_age_days": 1.0}),
        ({"_age_days": -5}, {"package_age_days": 1.0}),
        ({"_age_days": 10_000}, {"package_age_days": 0.0}),
        ({"_maintainer_count": "lots"}, {"maintainer_count": 1.0}),
        ({"_maintainer_count": 0}, {"maintainer_count": 1.0}),
        ({"_maintainer_count": 1e308}, {"maintainer_count": F.MAX_MAINTAINERS}),
        ({"_releases_last_7d": float("inf")}, {"release_count": 0.0}),
        ({"_releases_last_7d": -4}, {"release_count": 0.0}),
    ],
)
def test_hostile_registry_metadata_is_bounded(metadata, expected):
    features = F.build_features([], _ctx(**metadata))
    for name, value in expected.items():
        assert features[name] == value
    assert all(math.isfinite(v) for v in features.values())


def test_to_vector_follows_feature_order_and_zeroes_non_finite_values():
    vector = F.to_vector({"install_hook_exec": float("nan"), "yanked_release": 1, "unknown": 5})
    assert len(vector) == 36
    assert vector[0] == 0.0 and vector[-1] == 1.0 and sum(vector) == 1.0


def test_matches_feature_set():
    full = dict.fromkeys(F.FEATURE_ORDER, 0.0)
    assert F.matches_feature_set(full)
    assert F.matches_feature_set(full, "2")
    assert not F.matches_feature_set(full, "1")
    assert not F.matches_feature_set(dict.fromkeys(V1_FEATURES, 0.0))  # v1 scan rows
    assert not F.matches_feature_set({**full, "extra": 1.0})
    assert not F.matches_feature_set([0.0] * 36)


# =========================================================================== synthetic generator
def test_generator_is_deterministic_and_seed_sensitive():
    X1, y1, g1 = G.generate_samples(300, seed=5)
    X2, y2, g2 = G.generate_samples(300, seed=5)
    X3, _, _ = G.generate_samples(300, seed=6)
    assert np.array_equal(X1, X2) and np.array_equal(y1, y2) and g1 == g2
    assert not np.array_equal(X1, X3)


def test_generator_values_stay_in_the_serving_domain():
    X, y, _ = G.generate_samples(3000, seed=21)
    col = {name: X[:, i] for i, name in enumerate(F.FEATURE_ORDER)}
    assert X.shape == (3000, 36) and np.all(np.isfinite(X))
    assert 0 < y.sum() < len(y)
    # Serving maps an unknown/zero maintainer count to 1: training data must never contain 0 (v1 skew).
    assert col["maintainer_count"].min() >= 1.0
    for name in [*F.STRENGTH_FEATURES, "max_chain_confidence", "obfuscation_score", "package_age_days",
                 "typosquat_distance"]:
        assert col[name].min() >= 0.0 and col[name].max() <= 1.0, name
    for name in ("install_hook_exec", "network_egress", "subprocess_exec", "encoded_exec", "env_harvest",
                 "fs_sensitive_write", "has_repo_url", "new_package"):
        assert set(np.unique(col[name])) <= {0.0, 1.0}, name
    assert col["attack_chain_count"].max() <= F.MAX_ATTACK_CHAINS
    assert col["secrets_count"].max() <= F.MAX_SECRETS
    assert col["dynamic_exec"].max() <= F.MAX_DYNAMIC_EXEC
    # new_package mirrors the metadata analyzer (release younger than 7 days).
    assert np.all(col["package_age_days"][col["new_package"] == 1.0] >= F.age_score(7) - 1e-9)
    # chain count and chain confidence are consistent
    assert np.all((col["attack_chain_count"] > 0) == (col["max_chain_confidence"] > 0))


def test_generator_covers_every_archetype_and_hard_negative_with_consistent_labels():
    _, y, groups = G.generate_samples(6000, seed=3)
    seen = set(groups)
    assert set(G.MALICIOUS_ARCHETYPES) <= seen
    assert set(G.BENIGN_FAMILIES) <= seen
    for label, name in zip(y, groups):
        assert label == (1 if name in G.MALICIOUS_ARCHETYPES else 0)
    assert {
        "credential_stealer", "install_time_dropper", "obfuscated_layered_loader", "pth_startup_hook",
        "build_backend_hook", "typosquat_payload", "dependency_confusion", "browser_stealer",
        "persistence_implant", "takeover_drift",
    } == set(G.MALICIOUS_ARCHETYPES)


def test_hard_negatives_carry_the_capability_they_are_named_for():
    X, _, groups = G.generate_samples(6000, seed=8)
    idx = {name: i for i, name in enumerate(F.FEATURE_ORDER)}
    rows = {name: X[[i for i, g in enumerate(groups) if g == name]] for name in G.HARD_NEGATIVE_FAMILIES}
    assert np.all(rows["benign_cli_subprocess"][:, idx["subprocess_exec"]] == 1.0)
    assert np.all(rows["benign_sdk_env_network"][:, idx["network_egress"]] == 1.0)
    assert rows["benign_sdk_env_network"][:, idx["env_harvest"]].mean() > 0.3
    assert np.all(rows["benign_namespace_pth"][:, idx["pth_startup_hook"]] > 0.0)
    assert np.all(rows["benign_compiled_extension"][:, idx["binary_executable"]] > 0.0)
    assert np.all(rows["benign_new_release"][:, idx["new_package"]] == 1.0)
    assert np.all(rows["benign_revived_project"][:, idx["dormant_revival"]] > 0.0)
    assert np.all(rows["benign_yanked_release"][:, idx["yanked_release"]] > 0.0)


def test_generator_v1_entry_point_and_argument_validation():
    X, y = G.generate(50, seed=1)
    assert X.shape == (50, 36) and y.shape == (50,)
    with pytest.raises(ValueError):
        G.generate_samples(0)
    with pytest.raises(ValueError):
        G.generate_samples(10, malicious_ratio=1.0)


# =========================================================================== datasets
def test_synthetic_dataset_identity():
    ds = SyntheticDataset(n=200, seed=9)
    info = ds.describe()
    assert info["name"] == G.DATASET_NAME and info["version"] == G.DATASET_VERSION
    assert info["synthetic"] is True and info["seed"] == 9 and info["n"] == 200
    assert info["generator_hash"] == generator_hash() == normalized_sha256(Path(G.__file__).read_bytes())
    loaded = ds.load()
    assert loaded.X.shape == (200, 36) and loaded.info["positives"] == int(loaded.y.sum())
    assert len(loaded.groups) == 200


def test_generator_hash_ignores_line_endings():
    assert normalized_sha256(b"a\r\nb\r\n") == normalized_sha256(b"a\nb\n") == hashlib.sha256(b"a\nb\n").hexdigest()


def test_csv_round_trip(tmp_path):
    X, y, _ = G.generate_samples(120, seed=4)
    path = tmp_path / "corpus.csv"
    G.write_csv(path, X, y)
    loaded = CSVLabeledDataset(path).load()
    assert np.array_equal(loaded.X, X) and np.array_equal(loaded.y, y)
    assert loaded.info["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert loaded.info["synthetic"] is False and loaded.groups is None


def _csv_text(header: list[str], rows: list[list[str]]) -> str:
    return "\n".join(",".join(r) for r in [header, *rows]) + "\n"


def _good_rows(count: int = 4) -> list[list[str]]:
    return [["0.0"] * 36 + [str(i % 2)] for i in range(count)]


HEADER = [*F.FEATURE_ORDER, "label"]


@pytest.mark.parametrize(
    "text,message",
    [
        (_csv_text(F.FEATURE_ORDER, [["0"] * 36]), "exactly one 'label' column"),
        (_csv_text([F.FEATURE_ORDER[1], F.FEATURE_ORDER[0], *F.FEATURE_ORDER[2:], "label"], _good_rows()),
         "out of order: position 1"),
        (_csv_text([*F.FEATURE_ORDER, "archetype", "label"], [r[:36] + ["x", r[36]] for r in _good_rows()]),
         "unexpected columns ['archetype']"),
        (_csv_text([*F.FEATURE_ORDER[:-1], "label"], [["0"] * 35 + ["1"], ["0"] * 35 + ["0"]]),
         "missing feature columns ['yanked_release']"),
        (_csv_text(HEADER, [*_good_rows(1), ["0.0"] * 35 + ["high", "1"]]), "line 3: column 'yanked_release' is not"),
        (_csv_text(HEADER, [*_good_rows(), ["nan"] + ["0"] * 35 + ["1"]]), "is not finite"),
        (_csv_text(HEADER, [*_good_rows(), ["inf"] + ["0"] * 35 + ["1"]]), "is not finite"),
        (_csv_text(HEADER, [*_good_rows(), ["0"] * 36 + ["2"]]), "label must be 0 or 1"),
        (_csv_text(HEADER, [*_good_rows(), ["0"] * 10]), "expected 37 fields, found 10"),
        (_csv_text(HEADER, [["0"] * 36 + ["1"]] * 3), "both classes"),
        (_csv_text(HEADER, []), "no data rows"),
        ("", "empty"),
    ],
)
def test_csv_validation_errors_are_clear(tmp_path, text, message):
    path = tmp_path / "bad.csv"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(DatasetValidationError) as info:
        CSVLabeledDataset(path).load()
    assert message in str(info.value)


def test_csv_rejects_non_utf8_oversize_and_missing_files(tmp_path):
    binary = tmp_path / "latin1.csv"
    binary.write_bytes(",".join(HEADER).encode() + b"\n\xff\xfe\n")
    with pytest.raises(DatasetValidationError, match="not valid UTF-8"):
        CSVLabeledDataset(binary).load()
    big = tmp_path / "big.csv"
    big.write_text(_csv_text(HEADER, _good_rows(50)), encoding="utf-8")
    with pytest.raises(DatasetValidationError, match="limit"):
        CSVLabeledDataset(big, max_bytes=100).load()
    with pytest.raises(DatasetValidationError, match="more than 5 data rows"):
        CSVLabeledDataset(big, max_rows=5).load()
    missing = tmp_path / "nested" / "absent.csv"
    with pytest.raises(DatasetValidationError) as info:
        CSVLabeledDataset(missing).load()
    assert "absent.csv" in str(info.value) and str(tmp_path) not in str(info.value)


def test_csv_error_report_is_bounded(tmp_path):
    path = tmp_path / "many.csv"
    path.write_text(_csv_text(HEADER, [["x"] * 37 for _ in range(500)]), encoding="utf-8")
    with pytest.raises(DatasetValidationError) as info:
        CSVLabeledDataset(path).load()
    assert len(info.value.errors) == 10


def test_csv_accepts_bom_blank_lines_and_label_first(tmp_path):
    header = ["label", *F.FEATURE_ORDER]
    rows = [[str(i % 2)] + ["0.5"] * 36 for i in range(4)]
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbf" + (_csv_text(header, rows) + "\n\n").encode("utf-8"))
    loaded = CSVLabeledDataset(path).load()
    assert loaded.X.shape == (4, 36) and list(loaded.y) == [0, 1, 0, 1]


# =========================================================================== evaluation
def _noisy_predictions(n: int = 400, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.35).astype(int)
    p = np.clip(0.65 * y + rng.normal(0.2, 0.2, n), 0.0, 1.0)
    return y, p


def test_classification_metrics_are_present_and_numeric():
    y, p = _noisy_predictions()
    metrics = E.classification_metrics(y, p)
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier_score", "false_positive_rate",
                "specificity"):
        assert isinstance(metrics[key], float) and 0.0 <= metrics[key] <= 1.0, key
    assert metrics["n"] == 400 and metrics["positives"] + metrics["negatives"] == 400


def test_perfect_and_single_class_predictions():
    perfect = E.classification_metrics([0, 0, 1, 1], [0.0, 0.1, 0.9, 1.0])
    assert perfect["accuracy"] == 1.0 and perfect["roc_auc"] == 1.0 and perfect["brier_score"] == pytest.approx(0.005)
    single = E.classification_metrics([0, 0, 0], [0.2, 0.1, 0.7])
    assert single["roc_auc"] is None and single["pr_auc"] is None  # undefined, never invented
    assert single["false_positive_rate"] == pytest.approx(1 / 3, abs=1e-4)


def test_calibration_threshold_table_and_groups():
    y, p = _noisy_predictions()
    report = E.evaluate_predictions(y, p, groups=["mal" if v else "ben" for v in y])
    assert report["label"] == E.SYNTHETIC_LABEL
    bins = report["calibration"]["bins"]
    assert len(bins) == 10 and sum(b["count"] for b in bins) == 400
    table = report["threshold_table"]
    assert [row["threshold"] for row in table] == [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    assert all(row["tp"] + row["fp"] + row["tn"] + row["fn"] == 400 for row in table)
    recalls = [row["recall"] for row in table]
    assert recalls == sorted(recalls, reverse=True)  # recall can only fall as the threshold rises
    cm = report["confusion_matrix"]
    assert cm["matrix"] == [[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]]
    assert report["per_group"]["mal"]["metric"] == "detection_rate"
    assert report["per_group"]["ben"]["metric"] == "false_positive_rate"
    assert E.evaluate_predictions(y, p, synthetic=False)["label"] == E.LABELLED_LABEL


@pytest.mark.parametrize("y,p", [([0, 1], [0.1, 1.5]), ([0, 2], [0.1, 0.2]), ([0, 1], [0.1]), ([], [])])
def test_evaluation_rejects_invalid_input(y, p):
    with pytest.raises(ValueError):
        E.classification_metrics(y, p)


# =========================================================================== training
@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    # Pinned to the synthetic dataset: these assertions are about the synthetic evaluation
    # scope. Mixing in the measured corpus is covered separately below.
    out = tmp_path_factory.mktemp("ml-train-a")
    return out, train(n=700, seed=11, artifact_dir=out, config=TINY, trained_at=FIXED_TIME,
                      dataset=SyntheticDataset(n=700, seed=11))


def test_training_is_deterministic_for_the_same_seed(trained, tmp_path):
    out_a, meta_a = trained
    meta_b = train(n=700, seed=11, artifact_dir=tmp_path, config=TINY, trained_at=FIXED_TIME,
                   dataset=SyntheticDataset(n=700, seed=11))
    assert meta_b["model_version"] == meta_a["model_version"]
    assert (tmp_path / "model.joblib").read_bytes() == (out_a / "model.joblib").read_bytes()
    for key in ("evaluation", "feature_importances", "reference_distribution", "anomaly_reference", "dataset"):
        assert meta_b[key] == meta_a[key], key


def test_training_depends_on_the_seed(trained, tmp_path):
    _, meta_a = trained
    other = train(n=700, seed=12, artifact_dir=tmp_path, config=TINY, trained_at=FIXED_TIME)
    assert other["model_version"] != meta_a["model_version"]


def test_training_writes_artifacts_with_content_derived_version(trained):
    out, meta = trained
    data = (out / "model.joblib").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert meta["artifact_sha256"] == digest and meta["model_version"] == digest[:16]
    assert (out / "metrics.json").is_file() and (out / "MODEL_CARD.md").is_file()
    assert meta["trained_at"] == FIXED_TIME
    assert FIXED_TIME.encode() not in data  # wall-clock time never enters the artifact


def test_training_metadata_is_complete(trained):
    import joblib
    import sklearn

    _, meta = trained
    metrics = meta["evaluation"]["metrics"]
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier_score"):
        assert isinstance(metrics[key], float) and 0.0 <= metrics[key] <= 1.0, key
    assert meta["evaluation"]["label"] == E.SYNTHETIC_LABEL
    cm = meta["evaluation"]["confusion_matrix"]
    assert cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"] == meta["split"]["test_n"] == 175
    assert meta["split"]["test_positives"] + meta["split"]["train_positives"] == meta["dataset"]["positives"]
    assert len(meta["evaluation"]["calibration"]["bins"]) == 10
    assert len(meta["evaluation"]["threshold_table"]) == 9
    assert set(meta["evaluation"]["per_group"]) <= set(G.MALICIOUS_ARCHETYPES) | set(G.BENIGN_FAMILIES)
    importances = meta["feature_importances"]
    assert set(importances["impurity"]) == set(F.FEATURE_ORDER)
    assert sum(importances["impurity"].values()) == pytest.approx(1.0, abs=1e-3)
    assert set(importances["permutation"]) == set(F.FEATURE_ORDER)
    assert meta["feature_set_version"] == "2" and meta["feature_schema_hash"] == F.feature_schema_hash()
    assert meta["feature_order"] == F.FEATURE_ORDER
    dataset = meta["dataset"]
    assert (dataset["name"], dataset["version"], dataset["seed"], dataset["n"]) == (
        G.DATASET_NAME, G.DATASET_VERSION, 11, 700)
    assert dataset["generator_hash"] == generator_hash()
    assert meta["libraries"]["scikit_learn"] == sklearn.__version__
    assert meta["libraries"]["numpy"] == np.__version__ and meta["libraries"]["joblib"] == joblib.__version__
    for population in ("benign", "all"):
        reference = meta["reference_distribution"][population]
        assert set(reference) == set(F.FEATURE_ORDER)
        for entry in reference.values():
            assert len(entry["proportions"]) == len(entry["cuts"]) + 1
            assert sum(entry["proportions"]) == pytest.approx(1.0, abs=1e-4)
    quantiles = meta["anomaly_reference"]["quantiles"]
    assert len(quantiles) == 1001 and quantiles == sorted(quantiles)


def test_model_card_labels_every_number(trained):
    out, meta = trained
    card = (out / "MODEL_CARD.md").read_text(encoding="utf-8")
    label = E.SYNTHETIC_LABEL
    assert "SYNTHETIC EVALUATION" in card and meta["model_version"] in card
    evaluation = card.split("## Evaluation", 1)[1].split("## Limitations", 1)[0]
    assert label in evaluation.splitlines()[0]
    metric_rows = [line for line in evaluation.splitlines() if line.startswith(("| accuracy", "| roc_auc", "| pr_auc",
                                                                                "| brier_score", "| f1"))]
    assert len(metric_rows) == 5 and all(label in row for row in metric_rows)
    for section in evaluation.split("### ")[1:]:
        assert label in section, section.splitlines()[0]


def test_training_rejects_a_dataset_too_small_to_stratify(tmp_path):
    X, y, _ = G.generate_samples(200, seed=2)
    keep = np.concatenate([np.where(y == 0)[0], np.where(y == 1)[0][:5]])
    path = tmp_path / "tiny.csv"
    G.write_csv(path, X[keep], y[keep])
    with pytest.raises(ValueError, match="minority class has 5"):
        train(dataset=CSVLabeledDataset(path), artifact_dir=tmp_path / "out", config=TINY)


# =========================================================================== drift maths
def test_psi_is_near_zero_for_the_same_distribution():
    rng = np.random.default_rng(1)
    reference = F.reference_bins((rng.random(5000) < 0.2).astype(float))
    actual = F.bin_proportions(reference["cuts"], (rng.random(3000) < 0.2).astype(float))
    psi = F.population_stability_index(reference["proportions"], actual)
    assert psi < 0.01 and F.psi_status(psi) == "stable"


def test_psi_flags_a_shifted_distribution():
    rng = np.random.default_rng(2)
    reference = F.reference_bins((rng.random(5000) < 0.05).astype(float))
    actual = F.bin_proportions(reference["cuts"], (rng.random(500) < 0.6).astype(float))
    psi = F.population_stability_index(reference["proportions"], actual)
    assert psi > F.PSI_SIGNIFICANT and F.psi_status(psi) == "significant"


def test_psi_continuous_feature_shift_and_moderate_band():
    rng = np.random.default_rng(3)
    reference = F.reference_bins(rng.normal(0.3, 0.1, 4000).clip(0, 1))
    assert len(reference["cuts"]) >= 9
    same = F.bin_proportions(reference["cuts"], rng.normal(0.3, 0.1, 4000).clip(0, 1))
    moved = F.bin_proportions(reference["cuts"], rng.normal(0.5, 0.1, 4000).clip(0, 1))
    assert F.population_stability_index(reference["proportions"], same) < F.PSI_MODERATE
    assert F.population_stability_index(reference["proportions"], moved) > F.PSI_SIGNIFICANT
    moderate = F.population_stability_index([0.5, 0.5], [0.3, 0.7])
    assert F.PSI_MODERATE <= moderate < F.PSI_SIGNIFICANT and F.psi_status(moderate) == "moderate"


def test_constant_training_feature_still_detects_new_values():
    reference = F.reference_bins([0.0] * 100)
    assert reference["cuts"] == [0.0] and reference["proportions"] == [1.0, 0.0]
    psi = F.population_stability_index(reference["proportions"], F.bin_proportions(reference["cuts"], [1.0] * 60))
    assert math.isfinite(psi) and psi > F.PSI_SIGNIFICANT


def test_bins_are_upper_inclusive_and_psi_validates_shapes():
    assert F.bin_proportions([0.0, 0.5], [0.0, 0.5, 0.51, -1.0]) == [0.5, 0.25, 0.25]
    assert F.bin_proportions([0.0], []) == [0.0, 0.0]
    with pytest.raises(ValueError):
        F.population_stability_index([0.5, 0.5], [1.0])
    with pytest.raises(ValueError):
        F.reference_bins([])


def test_measured_negatives_are_mixed_in_and_labelled_honestly(tmp_path):
    """Training with measured real-world rows must say so in the evaluation scope label."""
    import numpy as np

    from ml.datasets import LoadedDataset, MixedDataset, SyntheticDataset

    class _FakeMeasured:
        name = "measured-benign"
        synthetic = False

        def available(self) -> bool:
            return True

        def describe(self) -> dict:
            return {"name": self.name, "synthetic": False, "rows": 8}

        def load(self) -> LoadedDataset:
            rows = np.zeros((8, len(F.FEATURE_ORDER)), dtype=float)
            rows[:, F.FEATURE_ORDER.index("network_egress")] = 1.0
            return LoadedDataset(X=rows, y=np.zeros(8, dtype=int), groups=tuple(["measured_benign"] * 8),
                                 info={"name": "measured-benign", "rows": 8})

    dataset = MixedDataset(SyntheticDataset(n=400, seed=5), _FakeMeasured(), measured_weight=10.0)
    loaded = dataset.load()
    assert loaded.sample_weight is not None and loaded.sample_weight.max() == 10.0
    assert "measured_benign" in set(loaded.groups or ())

    meta = train(n=400, seed=5, artifact_dir=tmp_path, config=TINY, trained_at=FIXED_TIME, dataset=dataset)
    assert meta["evaluation"]["label"] == E.MIXED_LABEL
    assert "not real-world detection performance" in meta["evaluation"]["label"]
