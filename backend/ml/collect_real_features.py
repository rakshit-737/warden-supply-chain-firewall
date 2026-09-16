"""Measure feature vectors for real, widely-used PyPI packages.

The supervised model is trained mostly on synthetic vectors. Synthetic benign samples cover
the *shape* of legitimate behaviour but not its real distribution, and a model trained only on
them scores ordinary libraries as malicious: measured on real packages, an HTTP client that
ships TLS fixtures in its test suite reached a critical score with no malicious trait at all.

This module records what real packages actually look like *to Warden's own analyzers*: it runs
the real pipeline over each project and writes the resulting feature vectors to a CSV that
:mod:`ml.datasets` mixes into training as measured negatives.

Only Warden's numeric features and the package coordinates are stored - no third-party source
code, and no finding evidence. Labels are ``0`` (benign) by construction: the list is a
curated set of established projects, which is an assumption stated in the CSV header and in
``docs/ML_MODEL.md``, not a verified fact about any particular release.

Usage (network access required)::

    python -m ml.collect_real_features --out ml/data/real_benign_features.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from app.analysis.analyzers.base import ScanOptions
from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION
from app.analysis.orchestrator import Orchestrator
from app.core.config import settings

DEFAULT_PACKAGES = Path(__file__).resolve().parent / "data" / "benign_packages.txt"
DEFAULT_OUT = Path(__file__).resolve().parent / "data" / "real_benign_features.csv"
METADATA_COLUMNS = ("package", "version", "analyzer_version", "feature_set_version", "collected_at", "rule_score")


def read_package_list(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def collect(names: list[str], *, pause: float = 1.0, orchestrator: Orchestrator | None = None) -> list[dict]:
    """Scan each package offline-of-intelligence and return one row per successful scan."""
    engine = orchestrator or Orchestrator()
    options = ScanOptions(offline=True, intel=False, provenance=False)
    rows: list[dict] = []
    for index, name in enumerate(names, start=1):
        try:
            result = engine.analyze("pypi", name, None, options)
        except Exception as exc:  # a single unavailable project must not abort a collection run
            print(f"[{index}/{len(names)}] {name}: skipped ({type(exc).__name__}: {exc})", file=sys.stderr)
            continue
        row = {
            "package": result.name,
            "version": result.version,
            "analyzer_version": result.analyzer_version,
            "feature_set_version": FEATURE_SET_VERSION,
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "rule_score": result.rule_score,
        }
        row.update({feature: float(result.features.get(feature, 0.0)) for feature in FEATURE_ORDER})
        row["label"] = 0
        rows.append(row)
        print(f"[{index}/{len(names)}] {result.name}=={result.version}: rule={result.rule_score} "
              f"risk={result.risk_score}", file=sys.stderr)
        if pause:
            time.sleep(pause)  # registry etiquette: this is a sequential, polite crawl
    return rows


def write_csv(rows: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    columns = [*METADATA_COLUMNS, *FEATURE_ORDER, "label"]
    with out.open("w", encoding="utf-8", newline="") as handle:
        handle.write(
            "# Feature vectors measured by Warden's own analyzers on established PyPI projects.\n"
            f"# analyzer_version={settings.ANALYZER_VERSION} feature_set_version={FEATURE_SET_VERSION} "
            f"rows={len(rows)}\n"
            "# label=0 assumes these established projects are benign at the measured version.\n"
        )
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packages", type=Path, default=DEFAULT_PACKAGES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--pause", type=float, default=1.0, help="seconds between registry requests")
    args = parser.parse_args(argv)

    names = read_package_list(args.packages)
    rows = collect(names, pause=args.pause)
    write_csv(rows, args.out)
    print(f"wrote {len(rows)} measured rows to {args.out}")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
