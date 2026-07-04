"""Reproducible synthetic dataset generator for the risk model.

Real labelled malicious-package corpora are not redistributable inside a public portfolio
repo, so this generator samples benign and malicious feature vectors from distributions
grounded in documented real-world attack patterns (install-time exfiltration, typosquats,
obfuscated loaders, credential harvesters). It is fully seeded: everyone who runs it gets
the identical dataset and therefore the identical model. See docs/ML_MODEL.md.

The feature order MUST match app.analysis.features.FEATURE_ORDER.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np

FEATURE_ORDER = [
    "install_hook_exec", "network_egress", "subprocess_exec", "dynamic_exec",
    "obfuscation_score", "encoded_exec", "env_harvest", "fs_sensitive_write",
    "dangerous_import_count", "typosquat_distance", "ioc_hits", "package_age_days",
    "maintainer_count", "has_repo_url", "release_count", "new_package",
]


def _benign(rng: np.random.Generator) -> list[float]:
    """Ordinary healthy packages: mostly-zero behavioural flags, mature provenance.

    Crucially, ~35% of benign samples are *recently released* (high recency / new_package)
    with otherwise clean behaviour. Without these, the model learns the spurious shortcut
    "new == malicious" and false-positives on every fresh benign release. Real benign
    packages also legitimately shell out (CLIs) and call the network (clients), so those
    capabilities appear in the benign distribution too.
    """
    recent = rng.random() < 0.35
    if recent:
        age = float(np.clip(rng.normal(0.8, 0.12), 0, 1))   # newly released
        new_pkg = 1.0
        releases = float(rng.integers(1, 6))
    else:
        age = float(np.clip(rng.normal(0.2, 0.15), 0, 1))   # mature
        new_pkg = float(rng.random() < 0.1)
        releases = float(rng.integers(0, 3))
    return [
        0.0,                                   # install_hook_exec
        float(rng.random() < 0.20),            # network_egress (clients call out)
        float(rng.random() < 0.15),            # subprocess_exec (CLIs shell out)
        float(rng.random() < 0.05) * rng.integers(0, 2),   # dynamic_exec
        max(0.0, rng.normal(0.02, 0.03)),      # obfuscation_score
        0.0,                                   # encoded_exec
        float(rng.random() < 0.05),            # env_harvest (only generic; sensitive is 0)
        0.0,                                   # fs_sensitive_write
        float(rng.integers(0, 3)),             # dangerous_import_count
        float(rng.random() < 0.02) * 0.6,      # typosquat_distance
        0.0,                                   # ioc_hits
        age,                                   # package_age_days (recency score)
        float(rng.integers(1, 6)),             # maintainer_count
        # Many legitimate packages (esp. new ones) don't declare a repo/homepage, so a
        # missing repo must NOT by itself imply malice — represent that in benign data.
        float(rng.random() < (0.6 if recent else 0.85)),   # has_repo_url
        releases,                              # release_count (7d)
        new_pkg,                               # new_package
    ]


def _malicious(rng: np.random.Generator) -> list[float]:
    """Mix of documented attack archetypes."""
    archetype = rng.choice(["installer", "typosquat", "obfuscated", "stealer"])
    f = {k: 0.0 for k in FEATURE_ORDER}
    f["package_age_days"] = float(np.clip(rng.normal(0.85, 0.12), 0, 1))  # usually brand new
    f["maintainer_count"] = float(rng.integers(0, 2))
    f["has_repo_url"] = float(rng.random() < 0.25)
    f["release_count"] = float(rng.integers(0, 12))
    f["new_package"] = float(rng.random() < 0.85)

    if archetype == "installer":
        f["install_hook_exec"] = 1.0
        f["network_egress"] = float(rng.random() < 0.8)
        f["subprocess_exec"] = float(rng.random() < 0.6)
        f["env_harvest"] = float(rng.random() < 0.5)
        f["dangerous_import_count"] = float(rng.integers(1, 4))
    elif archetype == "typosquat":
        f["typosquat_distance"] = float(rng.choice([1.0, 0.6], p=[0.7, 0.3]))
        f["network_egress"] = float(rng.random() < 0.5)
        f["install_hook_exec"] = float(rng.random() < 0.5)
        f["dynamic_exec"] = float(rng.integers(0, 2))
    elif archetype == "obfuscated":
        f["obfuscation_score"] = float(np.clip(rng.normal(0.7, 0.15), 0, 1))
        f["encoded_exec"] = float(rng.random() < 0.8)
        f["dynamic_exec"] = float(rng.integers(1, 4))
        f["network_egress"] = float(rng.random() < 0.6)
    else:  # stealer
        f["env_harvest"] = 1.0
        f["fs_sensitive_write"] = float(rng.random() < 0.8)
        f["network_egress"] = 1.0
        f["ioc_hits"] = float(rng.integers(0, 4))
        f["dangerous_import_count"] = float(rng.integers(1, 4))

    # A fraction of malicious samples carry a hard IOC hit.
    if rng.random() < 0.2:
        f["ioc_hits"] = float(rng.integers(1, 5))
    return [f[k] for k in FEATURE_ORDER]


def generate(n: int = 6000, malicious_ratio: float = 0.35, seed: int = 1337):
    rng = np.random.default_rng(seed)
    X, y = [], []
    for _ in range(n):
        if rng.random() < malicious_ratio:
            X.append(_malicious(rng))
            y.append(1)
        else:
            X.append(_benign(rng))
            y.append(0)
    return np.array(X, dtype=float), np.array(y, dtype=int)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the synthetic training dataset.")
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "dataset.csv")
    args = ap.parse_args()

    X, y = generate(args.n, seed=args.seed)
    with args.out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(FEATURE_ORDER + ["label"])
        for row, label in zip(X, y):
            w.writerow(list(row) + [label])
    print(f"Wrote {len(y)} samples ({int(y.sum())} malicious) to {args.out}")


if __name__ == "__main__":
    main()
