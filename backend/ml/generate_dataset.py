"""Seeded SYNTHETIC dataset generator for the Warden behaviour model (dataset v2).

SYNTHETIC DATA. Every row is a feature vector sampled from hand-written distributions; no row
describes a real package, and no real malware corpus was used. Metrics measured on this data
describe how well the pipeline separates *these* distributions, not real-world detection
performance.

Why synthetic: labelled malicious-package corpora are not redistributable inside this
repository. The archetypes below are modelled on publicly documented attack *patterns*
(install-time droppers, credential and browser-store stealers, obfuscated loaders, ``.pth``
startup hooks, in-tree build backends, typosquats, dependency confusion, persistence implants,
account-takeover releases). Each archetype sets the features its pattern would produce in
Warden's own feature domain (:data:`app.analysis.features.FEATURE_DESCRIPTIONS`), and a
fraction of malicious rows are *evasive* (weaker core evidence, secondary signals missed) so the
classes overlap as detection output does in practice.

Hard negatives are benign families that legitimately produce "suspicious" capabilities:
SDKs that read credential environment variables and call the network, CLIs that shell out,
packages that ship a ``.pth`` file (namespace packages, setuptools' distutils shim),
compiled-extension packages with binaries and build steps, brand-new benign releases, revived
projects after a legitimate ownership change, and yanked-but-benign releases. Without them a
model learns shortcuts such as "new == malicious" and blocks legitimate packages.

The generator is fully seeded (``numpy.random.default_rng(seed)``): the same ``n``, ratio and
seed always produce the identical dataset. Bump :data:`DATASET_VERSION` whenever sampling
changes.
"""

from __future__ import annotations

import argparse
import csv
from collections.abc import Callable
from pathlib import Path

import numpy as np

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, age_score

DATASET_NAME = "warden-synthetic"
DATASET_VERSION = "2.0.0"
SYNTHETIC = True
MAX_SAMPLES = 1_000_000

Row = dict[str, float]
Rng = np.random.Generator


# --------------------------------------------------------------------------- sampling helpers
def _new_row() -> Row:
    return dict.fromkeys(FEATURE_ORDER, 0.0)


def _put(row: Row, name: str, value: float) -> None:
    if name not in row:  # a typo must fail loudly, never silently add a dead feature
        raise KeyError(f"unknown feature {name!r}")
    row[name] = float(value)


def _chance(rng: Rng, probability: float) -> bool:
    return bool(rng.random() < probability)


def _conf(rng: Rng, low: float, high: float) -> float:
    return round(float(rng.uniform(low, high)), 4)


def _pick(rng: Rng, values: list[float], weights: list[float]) -> float:
    return float(values[int(rng.choice(len(values), p=weights))])


def _maybe(rng: Rng, row: Row, name: str, probability: float, value: float | Callable[[], float]) -> None:
    if _chance(rng, probability):
        _put(row, name, value() if callable(value) else value)


def _reputation(rng: Rng, row: Row, *, fresh_probability: float, maintainers: str, repo_probability: float) -> None:
    """Registry-derived features, sampled in the serving domain (see features.build_features)."""
    roll = rng.random()
    if roll < fresh_probability:
        age = float(rng.uniform(0.0, 7.0))
    elif roll < fresh_probability + (1.0 - fresh_probability) / 2:
        age = float(rng.uniform(7.0, 180.0))
    else:
        age = float(rng.uniform(180.0, 3000.0))
    _put(row, "package_age_days", round(age_score(age), 4))
    _put(row, "new_package", 1.0 if age < 7.0 else 0.0)  # metadata analyzer: release age < 7 days
    if age < 7.0:
        recent = _pick(rng, [1, 2, 3, 4, 6], [0.55, 0.25, 0.1, 0.06, 0.04])
    else:
        recent = _pick(rng, [0, 1, 2], [0.8, 0.15, 0.05])
    _put(row, "release_count", recent)
    if maintainers == "benign":
        _put(row, "maintainer_count", _pick(rng, [1, 2, 3, 4, 5, 6], [0.5, 0.25, 0.1, 0.07, 0.05, 0.03]))
    else:  # serving maps an unknown / zero maintainer count to 1, so never sample 0
        _put(row, "maintainer_count", _pick(rng, [1, 2], [0.88, 0.12]))
    _put(row, "has_repo_url", 1.0 if _chance(rng, repo_probability) else 0.0)


def _benign_background(rng: Rng, row: Row) -> None:
    """Capabilities that ordinary benign libraries show at low rates."""
    _maybe(rng, row, "network_egress", 0.25, 1.0)
    _maybe(rng, row, "subprocess_exec", 0.15, 1.0)
    _maybe(rng, row, "dynamic_exec", 0.06, lambda: _pick(rng, [1, 2], [0.8, 0.2]))
    _put(row, "obfuscation_score", round(float(np.clip(abs(rng.normal(0.02, 0.03)), 0.0, 1.0)), 4))
    _maybe(rng, row, "obfuscation_score", 0.03, lambda: _conf(rng, 0.1, 0.35))  # minified / vendored code
    _put(row, "dangerous_import_count", _pick(rng, [0, 1, 2, 3], [0.45, 0.3, 0.15, 0.1]))
    _maybe(rng, row, "env_harvest", 0.04, 1.0)
    _maybe(rng, row, "typosquat_distance", 0.02, 0.6)  # legitimate names close to popular ones
    _maybe(rng, row, "shell_invocation", 0.05, lambda: _conf(rng, 0.2, 0.65))
    _maybe(rng, row, "string_reconstruction", 0.03, lambda: _conf(rng, 0.25, 0.55))
    # test fixtures (certificates, sample credentials) shipped inside the sdist
    _maybe(rng, row, "secrets_count", 0.08, lambda: _pick(rng, [0.5, 1.0, 2.0, 3.0], [0.5, 0.25, 0.15, 0.1]))
    _maybe(rng, row, "binary_executable", 0.04, lambda: _conf(rng, 0.35, 0.6))
    _maybe(rng, row, "nested_archive", 0.04, 0.5)
    _maybe(rng, row, "yanked_release", 0.02, 0.95)
    _maybe(rng, row, "dormant_revival", 0.02, lambda: _conf(rng, 0.5, 0.7))


# --------------------------------------------------------------------------- benign families
def _benign_library(rng: Rng) -> Row:
    row = _new_row()
    _reputation(rng, row, fresh_probability=0.25, maintainers="benign", repo_probability=0.85)
    _benign_background(rng, row)
    return row


def _benign_sdk(rng: Rng) -> Row:
    """Hard negative: API clients read credential env vars and call the network."""
    row = _benign_library(rng)
    _put(row, "network_egress", 1.0)
    _maybe(rng, row, "env_harvest", 0.55, 1.0)
    _put(row, "dangerous_import_count", _pick(rng, [1, 2, 3], [0.5, 0.35, 0.15]))
    _maybe(rng, row, "secrets_count", 0.25, lambda: _pick(rng, [0.5, 1.0, 2.0, 3.0], [0.4, 0.3, 0.2, 0.1]))
    _maybe(rng, row, "has_repo_url", 0.9, 1.0)
    return row


def _benign_test_fixtures(rng: Rng) -> Row:
    """Hard negative: HTTP/TLS libraries ship certificate and key fixtures in their test suite.

    Real examples (requests, urllib3, aiohttp) carry several PEM private keys under tests/,
    which secret detection reports at a test-context discount. Without this family the model
    learns "any secret means malicious" and flags those libraries as critical.
    """
    row = _benign_library(rng)
    _put(row, "network_egress", 1.0)
    _put(row, "secrets_count", _pick(rng, [2.0, 3.0, 4.0, 5.5, 7.0], [0.25, 0.3, 0.2, 0.15, 0.1]))
    _maybe(rng, row, "dangerous_import_count", 0.7, lambda: _pick(rng, [1, 2, 3], [0.5, 0.3, 0.2]))
    _maybe(rng, row, "nested_archive", 0.15, 0.5)
    return row


def _benign_cli(rng: Rng) -> Row:
    """Hard negative: command-line tools spawn processes and sometimes a shell."""
    row = _benign_library(rng)
    _put(row, "subprocess_exec", 1.0)
    _maybe(rng, row, "shell_invocation", 0.6, lambda: _conf(rng, 0.45, 0.68))
    _put(row, "dangerous_import_count", _pick(rng, [1, 2, 3, 4], [0.35, 0.35, 0.2, 0.1]))
    _maybe(rng, row, "network_egress", 0.35, 1.0)
    _maybe(rng, row, "env_harvest", 0.1, 1.0)
    return row


def _benign_namespace_pth(rng: Rng) -> Row:
    """Hard negative: legitimate .pth files (namespace packages, setuptools' distutils shim)."""
    row = _new_row()
    _reputation(rng, row, fresh_probability=0.3, maintainers="benign", repo_probability=0.95)
    _benign_background(rng, row)
    _put(row, "pth_startup_hook", _conf(rng, 0.3, 0.82))
    _put(row, "maintainer_count", max(row["maintainer_count"], _pick(rng, [2, 3, 4, 6], [0.4, 0.3, 0.2, 0.1])))
    _maybe(rng, row, "env_harvest", 0.08, 1.0)
    return row


def _benign_compiled(rng: Rng) -> Row:
    """Hard negative: compiled extensions ship binaries and run build steps."""
    row = _benign_library(rng)
    _put(row, "binary_executable", _conf(rng, 0.35, 0.72))
    _maybe(rng, row, "subprocess_exec", 0.4, 1.0)
    _maybe(rng, row, "install_hook_exec", 0.15, 1.0)  # setup.py invoking cmake / compilers
    _maybe(rng, row, "build_backend_hook", 0.1, lambda: _conf(rng, 0.3, 0.6))
    _maybe(rng, row, "nested_archive", 0.1, 0.5)
    _put(row, "dangerous_import_count", _pick(rng, [1, 2, 3], [0.4, 0.4, 0.2]))
    return row


def _benign_new_release(rng: Rng) -> Row:
    """Hard negative: a brand-new benign release (the 'new == malicious' shortcut breaker)."""
    row = _new_row()
    _reputation(rng, row, fresh_probability=1.0, maintainers="benign", repo_probability=0.65)
    _benign_background(rng, row)
    if _chance(rng, 0.45):
        _put(row, "maintainer_count", 1.0)
    return row


def _benign_revival(rng: Rng) -> Row:
    """Hard negative: a dormant project revived, sometimes after a legitimate ownership change."""
    row = _new_row()
    _reputation(rng, row, fresh_probability=0.9, maintainers="benign", repo_probability=0.9)
    _benign_background(rng, row)
    _put(row, "dormant_revival", _conf(rng, 0.5, 0.75))
    _maybe(rng, row, "maintainer_changed", 0.35, lambda: _conf(rng, 0.45, 0.7))
    return row


def _benign_yanked(rng: Rng) -> Row:
    """Hard negative: a release yanked for an ordinary bug."""
    row = _benign_library(rng)
    _put(row, "yanked_release", 0.95)
    return row


# --------------------------------------------------------------------------- malicious archetypes
def _malicious_base(rng: Rng) -> Row:
    row = _new_row()
    _reputation(rng, row, fresh_probability=0.85, maintainers="malicious", repo_probability=0.35)
    if row["new_package"] == 1.0:
        _put(row, "release_count", _pick(rng, [1, 2, 3, 5, 8, 12, 20], [0.4, 0.2, 0.12, 0.1, 0.08, 0.06, 0.04]))
    _put(row, "dangerous_import_count", _pick(rng, [0, 1, 2, 3, 4], [0.15, 0.3, 0.3, 0.15, 0.1]))
    _maybe(rng, row, "ioc_hits", 0.1, lambda: _pick(rng, [1, 2, 3, 4], [0.5, 0.25, 0.15, 0.1]))
    return row


def _chain(rng: Rng, row: Row, probability: float) -> None:
    if _chance(rng, probability):
        _put(row, "attack_chain_count", _pick(rng, [1, 2], [0.75, 0.25]))
        _put(row, "max_chain_confidence", _conf(rng, 0.75, 0.95))


def _credential_stealer(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "env_harvest", 1.0)
    _maybe(rng, row, "fs_sensitive_write", 0.7, 1.0)
    _maybe(rng, row, "network_egress", 0.9, 1.0)
    _maybe(rng, row, "string_reconstruction", 0.3, lambda: _conf(rng, 0.55, 0.85))
    _maybe(rng, row, "dns_exfiltration", 0.15, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "install_hook_exec", 0.4, 1.0)
    _chain(rng, row, 0.55)
    return row


def _install_dropper(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "install_hook_exec", 1.0)
    _maybe(rng, row, "suspicious_download", 0.85, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "network_egress", 0.95, 1.0)
    _maybe(rng, row, "subprocess_exec", 0.75, 1.0)
    _maybe(rng, row, "shell_invocation", 0.6, lambda: _conf(rng, 0.6, 0.9))
    _maybe(rng, row, "persistence", 0.2, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "binary_executable", 0.1, lambda: _conf(rng, 0.6, 0.85))
    _chain(rng, row, 0.7)
    return row


def _obfuscated_loader(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "obfuscation_score", round(float(np.clip(rng.normal(0.7, 0.15), 0.3, 1.0)), 4))
    _maybe(rng, row, "encoded_exec", 0.85, 1.0)
    _maybe(rng, row, "layered_encoding", 0.7, lambda: _conf(rng, 0.8, 0.95))
    _put(row, "dynamic_exec", _pick(rng, [1, 2, 3, 4], [0.4, 0.3, 0.2, 0.1]))
    _maybe(rng, row, "reflection_abuse", 0.4, lambda: _conf(rng, 0.7, 0.9))
    _maybe(rng, row, "string_reconstruction", 0.5, lambda: _conf(rng, 0.6, 0.85))
    _maybe(rng, row, "network_egress", 0.6, 1.0)
    _maybe(rng, row, "install_hook_exec", 0.4, 1.0)
    _chain(rng, row, 0.45)
    return row


def _pth_hook(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "pth_startup_hook", _conf(rng, 0.82, 0.95))
    _maybe(rng, row, "encoded_exec", 0.4, 1.0)
    _maybe(rng, row, "network_egress", 0.6, 1.0)
    _maybe(rng, row, "env_harvest", 0.35, 1.0)
    _maybe(rng, row, "dynamic_exec", 0.5, lambda: _pick(rng, [1, 2], [0.7, 0.3]))
    _maybe(rng, row, "layered_encoding", 0.25, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "install_hook_exec", 0.2, 1.0)
    _chain(rng, row, 0.5)
    return row


def _build_backend_hook(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "build_backend_hook", _conf(rng, 0.75, 0.95))
    _maybe(rng, row, "install_hook_exec", 0.6, 1.0)
    _maybe(rng, row, "subprocess_exec", 0.5, 1.0)
    _maybe(rng, row, "network_egress", 0.65, 1.0)
    _maybe(rng, row, "suspicious_download", 0.4, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "env_harvest", 0.3, 1.0)
    _chain(rng, row, 0.5)
    return row


def _typosquat_payload(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "typosquat_distance", _pick(rng, [1.0, 0.6], [0.7, 0.3]))
    _maybe(rng, row, "install_hook_exec", 0.55, 1.0)
    _maybe(rng, row, "network_egress", 0.7, 1.0)
    _maybe(rng, row, "env_harvest", 0.35, 1.0)
    _maybe(rng, row, "dynamic_exec", 0.3, 1.0)
    _maybe(rng, row, "ioc_hits", 0.2, lambda: _pick(rng, [1, 2], [0.7, 0.3]))
    _chain(rng, row, 0.35)
    return row


def _dependency_confusion(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "dependency_confusion", _conf(rng, 0.7, 0.95))
    _maybe(rng, row, "install_hook_exec", 0.75, 1.0)
    _maybe(rng, row, "network_egress", 0.85, 1.0)
    _maybe(rng, row, "dns_exfiltration", 0.35, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "env_harvest", 0.45, 1.0)
    _maybe(rng, row, "subprocess_exec", 0.3, 1.0)
    _put(row, "has_repo_url", 1.0 if _chance(rng, 0.15) else 0.0)
    _chain(rng, row, 0.5)
    return row


def _browser_stealer(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "browser_credential_access", _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "fs_sensitive_write", 0.6, 1.0)
    _put(row, "network_egress", 1.0)
    _maybe(rng, row, "string_reconstruction", 0.3, lambda: _conf(rng, 0.55, 0.85))
    _maybe(rng, row, "binary_executable", 0.2, lambda: _conf(rng, 0.6, 0.85))
    _maybe(rng, row, "persistence", 0.2, lambda: _conf(rng, 0.8, 0.95))
    _chain(rng, row, 0.6)
    return row


def _persistence_implant(rng: Rng) -> Row:
    row = _malicious_base(rng)
    _put(row, "persistence", _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "subprocess_exec", 0.7, 1.0)
    _maybe(rng, row, "shell_invocation", 0.5, lambda: _conf(rng, 0.6, 0.9))
    _maybe(rng, row, "suspicious_download", 0.4, lambda: _conf(rng, 0.8, 0.95))
    _maybe(rng, row, "network_egress", 0.7, 1.0)
    _maybe(rng, row, "install_hook_exec", 0.5, 1.0)
    _chain(rng, row, 0.55)
    return row


def _takeover_drift(rng: Rng) -> Row:
    """Hard positive: an established project's new release after an account takeover."""
    row = _new_row()
    _reputation(rng, row, fresh_probability=0.9, maintainers="benign", repo_probability=0.9)
    _put(row, "dangerous_import_count", _pick(rng, [0, 1, 2, 3], [0.2, 0.35, 0.3, 0.15]))
    revival, changed = _chance(rng, 0.7), _chance(rng, 0.6)
    if not (revival or changed):
        revival = True
    if revival:
        _put(row, "dormant_revival", _conf(rng, 0.6, 0.9))
    if changed:
        _put(row, "maintainer_changed", _conf(rng, 0.6, 0.9))
    behaviours = ["install_hook_exec", "env_harvest", "encoded_exec"]
    for name, probability in zip(behaviours, (0.5, 0.5, 0.3)):
        _maybe(rng, row, name, probability, 1.0)
    if not any(row[name] for name in behaviours):
        _put(row, behaviours[int(rng.integers(0, len(behaviours)))], 1.0)
    _maybe(rng, row, "network_egress", 0.75, 1.0)
    _maybe(rng, row, "obfuscation_score", 0.3, lambda: _conf(rng, 0.3, 0.8))
    _chain(rng, row, 0.4)
    return row


# name -> (label, sampler, relative weight within its class)
BENIGN_FAMILIES: dict[str, tuple[Callable[[Rng], Row], float]] = {
    "benign_library": (_benign_library, 0.26),
    "benign_sdk_env_network": (_benign_sdk, 0.12),
    "benign_test_fixtures": (_benign_test_fixtures, 0.06),
    "benign_cli_subprocess": (_benign_cli, 0.12),
    "benign_namespace_pth": (_benign_namespace_pth, 0.08),
    "benign_compiled_extension": (_benign_compiled, 0.12),
    "benign_new_release": (_benign_new_release, 0.14),
    "benign_revived_project": (_benign_revival, 0.07),
    "benign_yanked_release": (_benign_yanked, 0.03),
}
MALICIOUS_ARCHETYPES: dict[str, tuple[Callable[[Rng], Row], float]] = {
    "credential_stealer": (_credential_stealer, 0.12),
    "install_time_dropper": (_install_dropper, 0.12),
    "obfuscated_layered_loader": (_obfuscated_loader, 0.11),
    "pth_startup_hook": (_pth_hook, 0.09),
    "build_backend_hook": (_build_backend_hook, 0.08),
    "typosquat_payload": (_typosquat_payload, 0.12),
    "dependency_confusion": (_dependency_confusion, 0.1),
    "browser_stealer": (_browser_stealer, 0.08),
    "persistence_implant": (_persistence_implant, 0.08),
    "takeover_drift": (_takeover_drift, 0.1),
}
HARD_NEGATIVE_FAMILIES = tuple(name for name in BENIGN_FAMILIES if name != "benign_library")

# Features an evasive sample keeps at full strength (its archetype's defining evidence).
_CORE_FEATURES = frozenset({
    "env_harvest", "install_hook_exec", "obfuscation_score", "pth_startup_hook", "build_backend_hook",
    "typosquat_distance", "dependency_confusion", "browser_credential_access", "persistence",
    "dormant_revival", "maintainer_changed",
})
_REPUTATION_FEATURES = frozenset({
    "package_age_days", "maintainer_count", "has_repo_url", "release_count", "new_package",
})
_EVASIVE_PROBABILITY = 0.3


def _evade(rng: Rng, row: Row) -> Row:
    """Model analyzer misses: weaker core evidence, half the secondary signals dropped."""
    for name in FEATURE_ORDER:
        value = row[name]
        if value == 0.0 or name in _REPUTATION_FEATURES:
            continue
        if name in _CORE_FEATURES:
            if 0.0 < value < 1.0 and name != "typosquat_distance":
                row[name] = _conf(rng, 0.55, 0.8)
        elif _chance(rng, 0.5):
            row[name] = 0.0
    if row["attack_chain_count"] == 0.0:
        row["max_chain_confidence"] = 0.0
    elif row["max_chain_confidence"] == 0.0:
        row["attack_chain_count"] = 0.0
    return row


def _choose(rng: Rng, families: dict[str, tuple[Callable[[Rng], Row], float]]) -> str:
    names = list(families)
    weights = np.array([families[n][1] for n in names], dtype=float)
    return names[int(rng.choice(len(names), p=weights / weights.sum()))]


def generate_samples(
    n: int = 6000, malicious_ratio: float = 0.35, seed: int = 1337
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """``(X, y, groups)``: SYNTHETIC feature matrix, labels (1 = malicious) and family names."""
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= MAX_SAMPLES:
        raise ValueError(f"n must be an integer between 1 and {MAX_SAMPLES}")
    if not 0.0 < float(malicious_ratio) < 1.0:
        raise ValueError("malicious_ratio must be strictly between 0 and 1")
    rng = np.random.default_rng(seed)
    X = np.zeros((n, len(FEATURE_ORDER)), dtype=float)
    y = np.zeros(n, dtype=int)
    groups: list[str] = []
    for i in range(n):
        if rng.random() < malicious_ratio:
            name = _choose(rng, MALICIOUS_ARCHETYPES)
            row = MALICIOUS_ARCHETYPES[name][0](rng)
            if _chance(rng, _EVASIVE_PROBABILITY):
                row = _evade(rng, row)
            y[i] = 1
        else:
            name = _choose(rng, BENIGN_FAMILIES)
            row = BENIGN_FAMILIES[name][0](rng)
        X[i] = [row[f] for f in FEATURE_ORDER]
        groups.append(name)
    return X, y, groups


def generate(n: int = 6000, malicious_ratio: float = 0.35, seed: int = 1337) -> tuple[np.ndarray, np.ndarray]:
    """v1-compatible entry point: ``(X, y)`` only."""
    X, y, _ = generate_samples(n, malicious_ratio, seed)
    return X, y


def write_csv(path: Path, X: np.ndarray, y: np.ndarray, *, label_column: str = "label") -> None:
    """Write the ``FEATURE_ORDER + [label]`` CSV layout that ``ml.datasets.CSVLabeledDataset`` reads."""
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([*FEATURE_ORDER, label_column])
        for row, label in zip(X, y):
            writer.writerow([repr(float(v)) for v in row] + [int(label)])


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the SYNTHETIC training dataset (not real packages).")
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--malicious-ratio", type=float, default=0.35)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "dataset.csv")
    args = ap.parse_args()

    X, y, _ = generate_samples(args.n, args.malicious_ratio, args.seed)
    write_csv(args.out, X, y)
    print(f"Wrote {len(y)} SYNTHETIC samples ({int(y.sum())} labelled malicious) to {args.out} "
          f"(dataset {DATASET_NAME} v{DATASET_VERSION}, feature set v{FEATURE_SET_VERSION})")


if __name__ == "__main__":
    main()
