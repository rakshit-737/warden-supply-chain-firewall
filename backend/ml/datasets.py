"""Training datasets: a common protocol, the seeded synthetic dataset, and a labelled CSV loader.

* :class:`SyntheticDataset` wraps :mod:`ml.generate_dataset`. Its identity is the dataset
  version, the seed, ``n`` and a hash of the generator source, so a metrics file can always be
  traced to the exact sampling code that produced its data. It is SYNTHETIC (see the generator
  docstring); evaluation on it is not evidence of real-world performance.
* :class:`CSVLabeledDataset` reads a labelled corpus in the ``FEATURE_ORDER + [label]`` layout
  (for a future real labelled dataset). The file is validated strictly — header, numeric and
  finite values, 0/1 labels, both classes present, size and row caps — and every problem is
  reported with its line number. The CSV is parsed as text only; nothing in it is executed.
"""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import numpy as np

from app.analysis.features import FEATURE_ORDER, FEATURE_SET_VERSION, feature_schema_hash
from ml import generate_dataset

MAX_CSV_BYTES = 256 * 1024 * 1024
MAX_CSV_ROWS = 2_000_000
MAX_REPORTED_ERRORS = 10


class DatasetValidationError(ValueError):
    """A dataset file is malformed. ``errors`` lists each problem (line numbers are 1-based)."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        self.errors = list(errors or [message])
        detail = "; ".join(self.errors[:MAX_REPORTED_ERRORS])
        super().__init__(f"{message}: {detail}" if errors else message)


@dataclass(frozen=True)
class LoadedDataset:
    X: np.ndarray
    y: np.ndarray
    groups: tuple[str, ...] | None
    info: dict[str, Any] = field(default_factory=dict)
    # Per-row training weight; None means every row counts once.
    sample_weight: np.ndarray | None = None


@runtime_checkable
class Dataset(Protocol):
    name: str
    synthetic: bool

    def load(self) -> LoadedDataset:  # pragma: no cover - protocol
        ...

    def describe(self) -> dict[str, Any]:  # pragma: no cover - protocol
        ...


def normalized_sha256(raw: bytes) -> str:
    """sha256 of source bytes with CRLF normalised to LF (stable across git checkouts)."""
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def generator_hash() -> str:
    """Hash of the synthetic generator's source file."""
    return normalized_sha256(Path(generate_dataset.__file__).read_bytes())


class SyntheticDataset:
    """Seeded SYNTHETIC dataset from :mod:`ml.generate_dataset`."""

    name = generate_dataset.DATASET_NAME
    synthetic = True

    def __init__(self, n: int = 6000, seed: int = 1337, malicious_ratio: float = 0.35) -> None:
        self.n = int(n)
        self.seed = int(seed)
        self.malicious_ratio = float(malicious_ratio)

    @property
    def version(self) -> str:
        return generate_dataset.DATASET_VERSION

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "synthetic": True,
            "seed": self.seed,
            "n": self.n,
            "malicious_ratio": self.malicious_ratio,
            "generator_hash": generator_hash(),
            "feature_set_version": FEATURE_SET_VERSION,
            "families": {
                "benign": sorted(generate_dataset.BENIGN_FAMILIES),
                "hard_negative": sorted(generate_dataset.HARD_NEGATIVE_FAMILIES),
                "malicious": sorted(generate_dataset.MALICIOUS_ARCHETYPES),
            },
        }

    def load(self) -> LoadedDataset:
        X, y, groups = generate_dataset.generate_samples(self.n, self.malicious_ratio, self.seed)
        info = self.describe()
        info["positives"] = int(y.sum())
        return LoadedDataset(X=X, y=y, groups=tuple(groups), info=info)


class CSVLabeledDataset:
    """Labelled feature vectors from a CSV whose header is ``FEATURE_ORDER`` plus a label column."""

    name = "labelled-csv"
    synthetic = False

    def __init__(
        self,
        path: str | Path,
        *,
        label_column: str = "label",
        max_bytes: int = MAX_CSV_BYTES,
        max_rows: int = MAX_CSV_ROWS,
    ) -> None:
        self.path = Path(path)
        self.label_column = label_column
        self.max_bytes = int(max_bytes)
        self.max_rows = int(max_rows)
        self._info: dict[str, Any] | None = None

    def describe(self) -> dict[str, Any]:
        if self._info is None:
            self.load()
        return dict(self._info or {})

    # ------------------------------------------------------------------ parsing
    def _read_text(self) -> tuple[str, str]:
        if not self.path.is_file():
            raise DatasetValidationError(f"dataset file not found: {self.path.name}")
        size = self.path.stat().st_size
        if size > self.max_bytes:
            raise DatasetValidationError(f"dataset file is {size} bytes; the limit is {self.max_bytes}")
        raw = self.path.read_bytes()
        if len(raw) > self.max_bytes:
            raise DatasetValidationError(f"dataset file exceeds the {self.max_bytes}-byte limit")
        if not raw.strip():
            raise DatasetValidationError("dataset file is empty")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise DatasetValidationError(f"dataset file is not valid UTF-8 (byte offset {exc.start})") from exc
        return text, hashlib.sha256(raw).hexdigest()

    def _check_header(self, header: list[str]) -> list[str]:
        errors: list[str] = []
        count = header.count(self.label_column)
        if count != 1:
            errors.append(f"line 1: expected exactly one '{self.label_column}' column, found {count}")
        names = [h for h in header if h != self.label_column]
        if names != FEATURE_ORDER:
            missing = [f for f in FEATURE_ORDER if f not in names]
            unexpected = [h for h in names if h not in FEATURE_ORDER]
            duplicated = sorted({h for h in names if names.count(h) > 1})
            if missing:
                errors.append(f"line 1: missing feature columns {missing}")
            if unexpected:
                errors.append(f"line 1: unexpected columns {unexpected}")
            if duplicated:
                errors.append(f"line 1: duplicated columns {duplicated}")
            if not (missing or unexpected or duplicated):
                position = next(i for i, (a, b) in enumerate(zip(names, FEATURE_ORDER)) if a != b)
                errors.append(
                    f"line 1: feature columns are out of order: position {position + 1} is '{names[position]}', "
                    f"expected '{FEATURE_ORDER[position]}' (FEATURE_ORDER must be followed exactly)"
                )
        return errors

    def load(self) -> LoadedDataset:
        text, digest = self._read_text()
        reader = csv.reader(io.StringIO(text, newline=""))
        try:
            header = [h.strip() for h in next(reader)]
        except StopIteration as exc:  # pragma: no cover - empty text is rejected earlier
            raise DatasetValidationError("dataset file has no header row") from exc
        except csv.Error as exc:
            raise DatasetValidationError(f"line 1: malformed CSV ({exc})") from exc
        errors = self._check_header(header)
        if errors:
            raise DatasetValidationError("invalid dataset header", errors)

        label_index = header.index(self.label_column)
        feature_indices = [i for i in range(len(header)) if i != label_index]
        rows: list[list[float]] = []
        labels: list[int] = []
        try:
            for record in reader:
                line = reader.line_num
                if not record or all(not cell.strip() for cell in record):
                    continue  # blank line
                if len(rows) >= self.max_rows:
                    errors.append(f"line {line}: more than {self.max_rows} data rows")
                    break
                if len(record) != len(header):
                    errors.append(f"line {line}: expected {len(header)} fields, found {len(record)}")
                else:
                    parsed = self._parse_row(record, feature_indices, label_index, line, header, errors)
                    if parsed is not None:
                        rows.append(parsed[0])
                        labels.append(parsed[1])
                if len(errors) >= MAX_REPORTED_ERRORS:
                    break
        except csv.Error as exc:
            errors.append(f"line {reader.line_num}: malformed CSV ({exc})")
        if errors:
            raise DatasetValidationError("invalid dataset rows", errors)
        if not rows:
            raise DatasetValidationError("dataset has no data rows")
        y = np.asarray(labels, dtype=int)
        positives = int(y.sum())
        if positives in (0, len(y)):
            raise DatasetValidationError("dataset must contain both classes (label 0 and label 1)")

        self._info = {
            "name": self.name,
            "version": digest[:16],
            "sha256": digest,
            "synthetic": False,
            "n": len(rows),
            "positives": positives,
            "label_column": self.label_column,
            "feature_set_version": FEATURE_SET_VERSION,
            "feature_schema_hash": feature_schema_hash(),
        }
        return LoadedDataset(X=np.asarray(rows, dtype=float), y=y, groups=None, info=dict(self._info))

    @staticmethod
    def _parse_row(
        record: list[str], feature_indices: list[int], label_index: int, line: int, header: list[str], errors: list[str]
    ) -> tuple[list[float], int] | None:
        values: list[float] = []
        ok = True
        for index in feature_indices:
            cell = record[index].strip()
            try:
                value = float(cell)
            except ValueError:
                errors.append(f"line {line}: column '{header[index]}' is not a number")
                ok = False
                break
            if value != value or value in (float("inf"), float("-inf")):
                errors.append(f"line {line}: column '{header[index]}' is not finite")
                ok = False
                break
            values.append(value)
        if not ok:
            return None
        raw_label = record[label_index].strip()
        try:
            label_value = float(raw_label)
        except ValueError:
            label_value = -1.0
        if label_value not in (0.0, 1.0):
            errors.append(f"line {line}: label must be 0 or 1")
            return None
        return values, int(label_value)


__all__ = [
    "CSVLabeledDataset",
    "Dataset",
    "DatasetValidationError",
    "LoadedDataset",
    "SyntheticDataset",
    "generator_hash",
    "normalized_sha256",
]


DEFAULT_MEASURED_PATH = Path(__file__).resolve().parent / "data" / "real_benign_features.csv"
MEASURED_GROUP = "measured_benign"
DEFAULT_MEASURED_WEIGHT = 25.0


class MeasuredBenignDataset:
    """Feature vectors measured by Warden's analyzers on established PyPI projects.

    Produced by ``python -m ml.collect_real_features``. Rows are labelled benign because the
    list is a curated set of long-established projects - an assumption, not a verified fact
    about a particular release, and stated as such in the CSV header and docs/ML_MODEL.md.
    """

    name = "measured-benign"
    synthetic = False

    def __init__(self, path: Path | str = DEFAULT_MEASURED_PATH) -> None:
        self.path = Path(path)

    def available(self) -> bool:
        return self.path.is_file()

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "synthetic": False, "path": self.path.name,
                "feature_set_version": FEATURE_SET_VERSION}

    def load(self) -> LoadedDataset:
        raw = self.path.read_bytes()
        if len(raw) > MAX_CSV_BYTES:
            raise DatasetValidationError(f"{self.path.name} exceeds {MAX_CSV_BYTES} bytes")
        lines = [ln for ln in raw.decode("utf-8").splitlines() if not ln.startswith("#")]
        reader = csv.DictReader(lines)
        missing = [c for c in (*FEATURE_ORDER, "label") if c not in (reader.fieldnames or [])]
        if missing:
            raise DatasetValidationError(f"{self.path.name} is missing columns: {', '.join(missing)}")
        rows, packages, errors = [], [], []
        for number, row in enumerate(reader, start=2):
            try:
                values = [float(row[name]) for name in FEATURE_ORDER]
                label = int(float(row["label"]))
            except (TypeError, ValueError) as exc:
                errors.append(f"line {number}: {exc}")
                if len(errors) >= MAX_REPORTED_ERRORS:
                    break
                continue
            if label != 0:
                errors.append(f"line {number}: measured rows must be labelled benign (0)")
                continue
            rows.append(values)
            packages.append(str(row.get("package", "")))
        if errors:
            raise DatasetValidationError("; ".join(errors))
        if not rows:
            raise DatasetValidationError(f"{self.path.name} contains no usable rows")
        X = np.asarray(rows, dtype=float)
        info = self.describe()
        info.update({"rows": len(rows), "packages": packages, "sha256": normalized_sha256(raw)})
        return LoadedDataset(X=X, y=np.zeros(len(rows), dtype=int), groups=tuple([MEASURED_GROUP] * len(rows)),
                             info=info)


class MixedDataset:
    """Synthetic samples plus measured real-world negatives.

    The measured rows are few (tens) next to thousands of synthetic ones, so training weights
    them with ``measured_weight``; without that, a handful of real vectors cannot correct a
    model that has learned a synthetic-only notion of "benign".
    """

    name = "synthetic+measured"
    synthetic = False  # partly synthetic: evaluation labels the scope from the parts
    kind = "mixed"

    def __init__(self, synthetic_part: Any, measured_part: Any,
                 measured_weight: float = DEFAULT_MEASURED_WEIGHT) -> None:
        self.synthetic_part = synthetic_part
        self.measured_part = measured_part
        self.measured_weight = float(measured_weight)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "synthetic": False,
            "parts": [self.synthetic_part.describe(), self.measured_part.describe()],
            "measured_weight": self.measured_weight,
        }

    def load(self) -> LoadedDataset:
        first, second = self.synthetic_part.load(), self.measured_part.load()
        X = np.vstack([first.X, second.X])
        y = np.concatenate([first.y, second.y])
        groups = tuple([*(first.groups or ("synthetic",) * len(first.y)), *(second.groups or ())])
        weights = np.concatenate([np.ones(len(first.y)), np.full(len(second.y), self.measured_weight)])
        info = self.describe()
        info.update({"rows": int(len(y)), "positives": int(y.sum()), "measured_rows": int(len(second.y)),
                     "synthetic_info": first.info, "measured_info": second.info})
        return LoadedDataset(X=X, y=y, groups=groups, info=info, sample_weight=weights)
