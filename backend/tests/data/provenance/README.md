# Provenance test fixtures (synthetic)

Used only by `tests/test_provenance_analyzer.py`. Nothing here is real PyPI or Sigstore data.

- `integrity_provenance_github.json`, `integrity_provenance_gitlab.json`: FIXTURES shaped like the provenance
  response documented at <https://docs.pypi.org/api/integrity/> (PEP 740 provenance object; publisher fields as
  in the pypa `pypi-attestations` models: GitHub `repository`/`workflow`/`environment`, GitLab
  `repository`/`workflow_filepath`/`environment`).
- Each document labels itself with a top-level `_fixture` key, which the analyzer ignores as an unknown field.
- `certificate`, `signature` and every transparency-log value are base64 placeholders (`FIXTURE-...-NOT-REAL`),
  not real Sigstore material; they cannot be cryptographically verified, and Warden does not attempt to.
- The base64 in-toto statement is a synthetic PyPI Publish Attestation v1
  (`predicateType: https://docs.pypi.org/attestations/publish/v1`). Its subject is `sampleproject-4.0.0.tar.gz`
  with sha256 `2fb62fad79eca8c0446919867a2cf5844f326aed8f79d5d56308876d00fd15e6`: the sha256 of the test's
  `FIXTURE_SDIST` bytes. A test asserts that value, so the fixtures cannot drift from the test inputs.
