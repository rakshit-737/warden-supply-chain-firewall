# SBOM parser test fixtures

Everything in this directory is **synthetic test data** for `tests/test_sbom_*.py`. Package names
and versions are only used as parser input. Hashes, index hosts and credentials are made up: the
credentials exist to prove they get redacted, and the hosts use the reserved `example` domains.

Every file ends in `.fixture` so that dependency scanners (GitHub dependency graph, Dependabot,
pip-audit) do not mistake these files for the repository's real manifests. The tests strip the
suffix when loading a directory into the in-memory `{path: content}` mapping that
`parse_project` takes.

| Directory | Covers |
|---|---|
| `requirements/` | line continuations, comments, `--hash`, index URLs with credentials, markers, extras, `-r`/`-c` includes, editable/VCS/URL requirements, constraints |
| `pep621/` | PEP 621 dependencies and optional-dependencies, PEP 735 dependency groups with an include cycle |
| `poetry/` | Poetry caret/tilde constraints, table-form dependencies, git source, named source, extras, groups, and a lock-version 2.1 lock with a dependency cycle |
| `poetry-legacy/` | lock-version 1.1 `poetry.lock` with `[metadata.files]` hashes and `category` |
| `pipenv/` | `Pipfile` and `Pipfile.lock` (default/develop, named indexes, malformed hashes) |
| `adversarial/` | include cycles and forbidden includes, weird/invalid markers, duplicate declarations, malformed TOML/JSON, wrongly typed lock values |

Very large inputs (huge lines, oversized manifests, component floods) are generated inside the
tests, not stored here.
