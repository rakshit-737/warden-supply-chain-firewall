# Semgrep adapter test fixtures

**Everything in this directory is a test fixture.** None of it is real scan output of a real
package, and none of it is used outside the test suite (`tests/test_semgrep_analyzer.py`).

The JSON files are shaped like `semgrep scan --json` output so the normaliser in
`app/analysis/analyzers/semgrep_scan.py` is tested against realistic structure:

| File | Modelled on |
|---|---|
| `semgrep_results.json` | A successful scan (exit 0) of the synthetic sample package defined in the test module (`MALICIOUS_FILES`). Result/`paths`/`version` layout and the `Timeout` error entry follow output observed from semgrep 1.177.0 on Windows; the `PartialParsing` entry follows the list-typed `type` form of semgrep's documented output schema (semgrep-interfaces `semgrep_output_v1`). |
| `semgrep_config_error.json` | The document semgrep 1.177.0 printed (exit status 7) when a `--config` path did not exist. |

Conventions that make the fixtures impossible to mistake for real output:

- every absolute path is written as `__WORKSPACE__/...`; tests substitute the temporary
  workspace directory at run time, so no real host path appears here;
- the package, URLs (`collector.invalid`) and rule ids of the organisational rules
  (`acme.*`) are invented;
- deliberately broken entries are included on purpose: a duplicate result, a result whose path
  escapes the workspace (`__WORKSPACE__/../escape.py`), a malformed result (`check_id` is a
  number), a result without a line number and an out-of-range `CRITICAL` severity.

Line and column numbers point at the sample sources in the test module; a test asserts that
each fixture line exists in its file, so the fixture cannot silently drift from the sources.
