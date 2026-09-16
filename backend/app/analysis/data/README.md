# Analysis data files

Data bundled with the static analyzers. Everything here is read-only at runtime and loaded with size caps.

## `popular_packages.txt` — typosquat comparison targets

Used by `app/analysis/analyzers/typosquat.py` (analyzer 2.0.0).

| Field | Value |
|---|---|
| Content | The 5,000 most-downloaded PyPI projects, one PEP 503 canonical name per line, most-downloaded first (line N after the `#` header = download rank N). |
| Dataset | "Top PyPI Packages" by Hugo van Kemenade et al., <https://github.com/hugovk/top-pypi-packages> |
| Source URL | <https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json>. It now answers with HTTP 301 to <https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json>. The older `top-pypi-packages-30-days.min.json` URL served a byte-identical file on 2026-09-15. |
| Upstream data | Monthly per-project download counts from the public ClickHouse PyPI dataset (`pypi.pypi_downloads_per_month`), queried by the project's `clickhouse.py`. The file lists the top 15,000 projects for the previous calendar month. |
| Dataset `last_update` | 2026-09-01 06:34:08 UTC (downloads for August 2026) |
| Retrieved | 2026-09-15 (UTC) |
| Licence | **CC-BY-4.0**, as declared on the dataset's Zenodo release record for Release 2026.09 (<https://doi.org/10.5281/zenodo.22225583>, checked 2026-09-15 UTC). The GitHub repository itself has no LICENSE file (the GitHub API reports `license: null`). Attribution: Hugo van Kemenade et al. Only project names and their rank order are redistributed; download counts are not. |
| Rows | 5,000 (ranks 1–5000 of 15,000 valid rows; 0 rows rejected by validation) |

### Refreshing

From `backend/`:

```
../.venv/Scripts/python.exe scripts/refresh_popular_packages.py --dry-run   # download and validate only
../.venv/Scripts/python.exe scripts/refresh_popular_packages.py             # rewrite both lists
```

The script downloads through `SafeHttpClient`: HTTPS only, the host allowlist is `hugovk.github.io` and
`hugovk.dev` (each redirect hop is re-checked), responses are capped at 8 MiB, and retries are bounded. It
validates every row (PEP 508 name syntax, ASCII, length limit, non-negative integer count), re-sorts by
download count, and drops canonical duplicates. Output files are written atomically. If anything fails, the
existing files are left unchanged and the script exits with status 1. `--input-json FILE --source-url URL`
reproduces the lists offline from a saved copy of the dataset.

After a refresh:

1. Re-verify the licence on the new Zenodo release record and update `LICENCE_NOTE` in the script if it changed.
2. Review the diff.
3. Run `tests/test_typosquat.py`, `tests/test_typosquat_v2.py` and the analyzer contract tests. The
   false-positive test re-measures noise on the new fixture; update the numbers below.

## `typosquat_allowlist.txt` — curated legitimate near-name pairs

Format: `candidate target  # one-line justification`, compared in PEP 503 form. Each entry suppresses the
typosquat finding for that exact pair only. The candidate is still compared with every other target, and
all other analyzers still run. Lines without a justification are ignored.

Add a pair only for an established, independently maintained project whose identity you have verified.
Never add one just to silence a noisy scan. The test suite checks three things for every entry: the
candidate is not itself popular, the target is popular, and the entry still suppresses a real finding.

## `tests/data/typosquat/legit_next5000.txt` — false-positive fixture (tests only)

Ranks 5001–10000 of the same dataset and retrieval, written by the same script. It is labelled `TEST FIXTURE`
and never read at runtime. The names are real PyPI projects and are **assumed** benign: download popularity
is not proof of legitimacy, so a few could be squats themselves, which would make the measured rate
pessimistic.

## Measured typosquat false-positive rate

Analyzer 2.0.0, this snapshot, all 5,000 fixture names:

| Configuration | Flagged (any confidence) | Flagged at confidence ≥ 0.7 (default policy block level) |
|---|---|---|
| Raw detector (allowlist disabled) | 61 / 5000 = **1.22 %** | 4 / 5000 = **0.08 %** (`fastai`, `identity`, `git-python`, `pydlt`) |
| With the bundled allowlist | 39 / 5000 = 0.78 % | 2 / 5000 = 0.04 % (`git-python`, `pydlt`) |

- Raw findings by kind: typo 39, combosquat 19, separator 2, plural 1. Most are medium-severity findings with
  confidence 0.5–0.65, which the default policy does not hard-block.
- The allowlist was curated partly from this measurement, so the second row is optimistic. The test suite
  asserts on the raw row: at most 2.0 % flagged and at most 0.2 % at confidence ≥ 0.7.
- Detection of documented historical squats (tested as strings only):
  - flagged as typos at confidence 0.85: `urlib3`, `colourama`, `python3-dateutil`;
  - flagged as a separator variant at 0.8: `setup-tools`;
  - flagged as a homoglyph at 0.9: `jeIlyfish` (capital I). Only a capital `I` is folded to `l`; lower-case
    `jeilyfish` is graded as a weaker look-alike typo, and an `il`/`li` transposition stays a typo.
- These numbers were re-measured on 2026-09-15 (UTC) after the capital-I homoglyph change and were unchanged.
- Performance on the development host (Windows, CPython 3.12, measured while other test suites were running):
  building the index takes 0.15–0.25 s once per process. Analysing each of the 5,000 fixture names took
  2.9 ms (median), 6.1 ms (95th percentile) and 21 ms (worst case). The test asserts a median below 20 ms.

## `iocs.json`

The bundled indicator snapshot used by the IOC analyzer. The analyzer contract tests describe it as a
synthetic demonstration snapshot, not live threat intelligence.
