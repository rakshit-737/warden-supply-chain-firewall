"""Refresh the ranked popular-package snapshot used by the typosquat analyzer.

Downloads the monthly "Top PyPI Packages" dataset published by Hugo van Kemenade et al.
(https://github.com/hugovk/top-pypi-packages) and writes:

* ``app/analysis/data/popular_packages.txt`` -- ranks 1..TOP (default 5000), the analyzer's
  comparison targets, one PEP 503 canonical name per line in download-rank order;
* ``tests/data/typosquat/legit_next5000.txt`` -- ranks TOP+1..TOP+NEXT (default 5000), a test
  fixture of (assumed) legitimate names used to measure the analyzer's false-positive rate.

Usage, from ``backend/``::

    ../.venv/Scripts/python.exe scripts/refresh_popular_packages.py            # download + write
    ../.venv/Scripts/python.exe scripts/refresh_popular_packages.py --dry-run  # download + validate only
    ../.venv/Scripts/python.exe scripts/refresh_popular_packages.py --input-json top.json \
        --source-url https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json

All network access goes through :class:`app.core.http.SafeHttpClient` (HTTPS only, per-hop host
allowlist, response size cap, bounded retries). The historical ``hugovk.github.io`` URLs answer
with a 301 redirect to ``hugovk.dev``, so both hosts are allowlisted; nothing else is reachable.

The downloaded JSON is untrusted input: it is parsed with :mod:`json` (never evaluated), every row
is validated (PEP 508 project-name syntax, ASCII only, bounded length, non-negative integer
download count), rows are re-sorted by download count, canonical duplicates are dropped, and the
row count is capped. On any download or validation failure the existing files are left untouched
and the script exits with status 1.

The licence note written into the file header records what was verified by hand when this script
was last reviewed (see ``LICENCE_NOTE``); re-verify it when refreshing, because the dataset's
Zenodo record changes with every monthly release.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:  # allow ``python scripts/refresh_popular_packages.py``
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.http import OutboundHTTPError, SafeHttpClient  # noqa: E402

DATASET_URLS: tuple[str, ...] = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
    "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json",
)
# hugovk.github.io 301-redirects to hugovk.dev (observed 2026-09-15); SafeHttpClient re-checks every hop.
ALLOWED_HOSTS: frozenset[str] = frozenset({"hugovk.github.io", "hugovk.dev"})
MAX_DATASET_BYTES = 8 * 1024 * 1024  # the 15,000-row minified file is ~0.8 MiB
MAX_ROWS = 50_000
MAX_NAME_LENGTH = 214
DEFAULT_TOP = 5000
DEFAULT_NEXT = 5000

POPULAR_OUT = BACKEND_ROOT / "app" / "analysis" / "data" / "popular_packages.txt"
FIXTURE_OUT = BACKEND_ROOT / "tests" / "data" / "typosquat" / "legit_next5000.txt"

DATASET_TITLE = "hugovk/top-pypi-packages (Top PyPI Packages, Hugo van Kemenade et al.)"
LICENCE_NOTE = (
    "CC-BY-4.0, as declared on the dataset's Zenodo release record "
    "(Release 2026.09, https://doi.org/10.5281/zenodo.22225583, checked 2026-09-15 UTC); "
    "the GitHub repository itself carries no LICENSE file. Attribution: Hugo van Kemenade et al."
)

# PEP 508 project name (ASCII letters/digits, inner ``._-``).
_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_SEP_RE = re.compile(r"[-_.]+")


class DatasetError(ValueError):
    """The downloaded dataset is missing, malformed or fails validation."""


@dataclass(frozen=True)
class Dataset:
    names: tuple[str, ...]  # PEP 503 canonical names, most-downloaded first, unique
    last_update: str | None
    source: str | None
    raw_rows: int
    rejected_rows: int


def canonical(name: str) -> str:
    return _SEP_RE.sub("-", name).lower()


def parse_dataset(payload: Any, *, max_rows: int = MAX_ROWS) -> Dataset:
    """Validate the dataset JSON and return canonical names ordered by download count."""
    if not isinstance(payload, dict):
        raise DatasetError("dataset root is not a JSON object")
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        raise DatasetError("dataset has no 'rows' list")
    if len(rows) > max_rows:
        raise DatasetError(f"dataset has {len(rows)} rows; refusing more than {max_rows}")
    valid: list[tuple[int, int, str]] = []
    rejected = 0
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            rejected += 1
            continue
        project, count = row.get("project"), row.get("download_count")
        if (
            not isinstance(project, str)
            or not project.isascii()
            or len(project) > MAX_NAME_LENGTH
            or not _NAME_RE.fullmatch(project)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            rejected += 1
            continue
        valid.append((-count, position, canonical(project)))
    valid.sort()  # by download count (desc), then original position: deterministic
    seen: set[str] = set()
    names: list[str] = []
    for _neg_count, _position, name in valid:
        if name in seen:
            rejected += 1
            continue
        seen.add(name)
        names.append(name)
    if not names:
        raise DatasetError("dataset has no valid rows")
    last_update = payload.get("last_update")
    source = payload.get("source")
    return Dataset(
        names=tuple(names),
        last_update=_short_text(last_update),
        source=_short_text(source),
        raw_rows=len(rows),
        rejected_rows=rejected,
    )


def _short_text(value: Any, limit: int = 64) -> str | None:
    """A header-safe single-line string (printable ASCII only) or None."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if 32 <= ord(ch) < 127)[:limit].strip()
    return cleaned or None


def render_list(
    names: Sequence[str],
    *,
    title: str,
    start_rank: int,
    source_url: str,
    final_url: str | None,
    dataset: Dataset,
    retrieved: str,
    purpose: str,
) -> str:
    """File body: a ``# key: value`` header, then one name per line in rank order."""
    end_rank = start_rank + len(names) - 1
    served = f" (served from {final_url})" if final_url and final_url != source_url else ""
    header = [
        f"# {title}",
        f"# {purpose}",
        "# One PEP 503 canonical project name per line, most-downloaded first.",
        f"# source: {source_url}{served}",
        f"# dataset: {DATASET_TITLE}",
        f"# dataset-last-update: {dataset.last_update or 'unknown'} UTC (upstream source: "
        f"{dataset.source or 'unknown'}; monthly download counts)",
        f"# retrieved: {retrieved}",
        f"# licence: {LICENCE_NOTE}",
        f"# ranks: {start_rank}-{end_rank} of {len(dataset.names)} valid rows",
        f"# rows: {len(names)}",
        "# generated-by: backend/scripts/refresh_popular_packages.py",
    ]
    return "\n".join(header + list(names)) + "\n"


def fetch_dataset(
    client: SafeHttpClient, urls: Sequence[str] = DATASET_URLS, *, log: Callable[[str], None] = print
) -> tuple[Any, str, str]:
    """Return ``(payload, requested_url, final_url)`` from the first URL that yields valid JSON."""
    errors: list[str] = []
    for url in urls:
        try:
            result = client.request("GET", url, max_bytes=MAX_DATASET_BYTES)
            if result.status != 200:
                raise OutboundHTTPError(f"HTTP {result.status}", kind="status", status=result.status, url=url)
            return result.json(), url, result.url
        except OutboundHTTPError as exc:
            errors.append(f"{url}: {exc} ({exc.kind})")
            log(f"download failed: {url}: {exc} ({exc.kind})")
    raise DatasetError("all dataset URLs failed: " + "; ".join(errors))


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def build_client() -> SafeHttpClient:
    return SafeHttpClient(
        name="top-pypi-packages",
        allowed_hosts=ALLOWED_HOSTS,
        max_response_bytes=MAX_DATASET_BYTES,
        timeout=30.0,
        retries=2,
        total_timeout=120.0,
    )


def main(argv: Sequence[str] | None = None, *, client: SafeHttpClient | None = None,
         today: dt.date | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=DEFAULT_TOP, help="ranks written to the popular list")
    parser.add_argument("--next", dest="next_count", type=int, default=DEFAULT_NEXT,
                        help="following ranks written to the false-positive fixture")
    parser.add_argument("--popular-out", type=Path, default=POPULAR_OUT)
    parser.add_argument("--fixture-out", type=Path, default=FIXTURE_OUT)
    parser.add_argument("--input-json", type=Path, help="use a previously downloaded dataset file (offline)")
    parser.add_argument("--source-url", default=DATASET_URLS[0], help="source URL recorded with --input-json")
    parser.add_argument("--dry-run", action="store_true", help="validate and report without writing files")
    args = parser.parse_args(argv)
    if args.top < 1 or args.next_count < 0:
        parser.error("--top must be >= 1 and --next >= 0")

    retrieved = (today or dt.datetime.now(dt.timezone.utc).date()).isoformat()
    final_url: str | None = None
    try:
        if args.input_json:
            raw = args.input_json.read_bytes()
            if len(raw) > MAX_DATASET_BYTES:
                raise DatasetError(f"input file exceeds {MAX_DATASET_BYTES} bytes")
            try:
                payload = json.loads(raw)
            except (ValueError, RecursionError) as exc:
                raise DatasetError("input file is not valid JSON") from exc
            source_url = args.source_url
        else:
            owned = client is None
            http = client or build_client()
            try:
                payload, source_url, final_url = fetch_dataset(http)
            finally:
                if owned:
                    http.close()
        dataset = parse_dataset(payload)
    except (DatasetError, OSError) as exc:
        print(f"error: {exc}; existing files were left unchanged", file=sys.stderr)
        return 1

    if len(dataset.names) < args.top:
        print(f"error: dataset has only {len(dataset.names)} valid names (< --top {args.top}); "
              "existing files were left unchanged", file=sys.stderr)
        return 1
    top = dataset.names[: args.top]
    following = dataset.names[args.top: args.top + args.next_count]
    print(f"dataset: {dataset.raw_rows} rows, {len(dataset.names)} valid, {dataset.rejected_rows} rejected, "
          f"last_update={dataset.last_update}")
    print(f"popular list: ranks 1-{len(top)}; fixture: {len(following)} names")
    if args.dry_run:
        return 0

    common = dict(source_url=source_url, final_url=final_url, dataset=dataset, retrieved=retrieved)
    _atomic_write(args.popular_out, render_list(
        top, title="Warden typosquat comparison targets: most-downloaded PyPI projects",
        purpose="Line N of the name list (after this header) is download rank N.",
        start_rank=1, **common))
    if args.next_count:
        _atomic_write(args.fixture_out, render_list(
            following, title="TEST FIXTURE -- legitimate-name sample for typosquat false-positive measurement",
            purpose=(f"Real PyPI projects ranked {args.top + 1}-{args.top + len(following)} by downloads; assumed "
                     "benign (popularity is not proof of legitimacy). Not used by the analyzer at runtime."),
            start_rank=args.top + 1, **common))
    print(f"wrote {args.popular_out} and {args.fixture_out if args.next_count else '(no fixture)'}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
