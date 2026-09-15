"""Dependency-hygiene findings: UNPINNED_DEPENDENCY, MISSING_HASHES and INDEX_SOURCE_AMBIGUITY.

Inputs are the synthetic manifests in ``tests/data/sbom`` or small inline manifests. Assertions pin
the contract other components rely on: severities, real declaration locations (never invented
lines), taxonomy metadata, deterministic finding ids and credential-free evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.findings import Finding, Severity
from app.analysis.signals import Code
from app.sbom import hygiene_findings, parse_project
from app.sbom.models import ProjectInventory

SBOM = Path(__file__).parent / "data" / "sbom"


def fixture_files(directory: str, only: set[str] | None = None) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for path in sorted((SBOM / directory).glob("*.fixture")):
        name = path.name.removesuffix(".fixture")
        if only is None or name in only:
            out[name] = path.read_bytes()
    return out


def line_of(content: bytes | str, needle: str) -> int:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    hits = [i for i, line in enumerate(text.splitlines(), start=1) if needle in line]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def by_code(findings: list[Finding], code: str) -> list[Finding]:
    return [f for f in findings if f.code == code]


# ------------------------------------------------------------------------------ UNPINNED_DEPENDENCY
def test_unpinned_direct_dependencies_are_located_at_their_declaration():
    files = fixture_files("requirements")
    findings = hygiene_findings(parse_project(files, "fixture"))
    unpinned = {f.evidence["package"]: f for f in by_code(findings, Code.UNPINNED_DEPENDENCY)}
    # ==, === and constraint-pinned requirements (requests, urllib3, certifi, idna) are not reported.
    assert sorted(unpinned) == ["Django", "acme-thing", "charset-normalizer", "flask", "legacy-pkg", "wheelpkg"]

    req = files["requirements.txt"]
    flask = unpinned["flask"]
    assert (flask.location.file, flask.location.line) == ("requirements.txt", line_of(req, "flask>=2.0"))
    assert (flask.severity, flask.category, flask.analyzer) == (Severity.low, "dependency_hygiene", "sbom-hygiene")
    assert flask.title == "Dependency not pinned to an exact version"
    assert flask.remediation and flask.cwe == ("CWE-1357",)
    assert flask.evidence["specifier"] == "<3,>=2.0" and flask.evidence["source"] == "registry"
    assert flask.confidence >= 0.9 and 0.5 <= flask.weight <= 2.0

    charset = unpinned["charset-normalizer"]
    assert (charset.location.file, charset.location.line) == ("base.txt", line_of(files["base.txt"], "charset"))
    assert unpinned["Django"].evidence["specifier"] == "==4.2.*"  # a wildcard is not an exact pin
    thing = unpinned["acme-thing"]
    assert thing.evidence["source"] == "url" and "direct URL/VCS/path" in thing.message
    assert thing.location.line == line_of(req, "-e git+https")


def test_unpinned_dependency_in_pyproject_without_lock_reports_real_line():
    text = '[project]\nname = "x"\ndependencies = [\n    "httpx>=0.27",\n    "pydantic==2.7.0",\n]\n'
    findings = by_code(hygiene_findings(parse_project({"pyproject.toml": text}, "p")), Code.UNPINNED_DEPENDENCY)
    assert [(f.evidence["package"], f.location.file, f.location.line) for f in findings] == \
        [("httpx", "pyproject.toml", 4)]


def test_locked_dependencies_are_never_reported_unpinned():
    for directory in ("poetry", "poetry-legacy", "pipenv"):
        inventory = parse_project(fixture_files(directory), directory)
        assert not by_code(hygiene_findings(inventory), Code.UNPINNED_DEPENDENCY), directory


def test_transitive_dependencies_are_not_reported_unpinned():
    lock = (
        '[[package]]\nname = "top"\nversion = "1.0"\nfiles = []\n\n[package.dependencies]\nleaf = ">=1"\n\n'
        '[[package]]\nname = "leaf"\nversion = "2.0"\nfiles = []\n'
    )
    pyproject = '[project]\nname = "x"\ndependencies = ["top"]\n'
    inventory = parse_project({"pyproject.toml": pyproject, "poetry.lock": lock}, "p")
    assert not by_code(hygiene_findings(inventory), Code.UNPINNED_DEPENDENCY)


# ----------------------------------------------------------------------------------- MISSING_HASHES
def test_missing_hashes_is_one_aggregated_finding_per_requirements_file():
    files = {
        "requirements.txt": "requests==2.31.0\nflask==3.0.0\n\nidna>=3\n",
        "requirements-dev.txt": "pytest==8.2.0 --hash=sha256:" + "a" * 64 + "\nruff==0.4.0\n",
        "constraints.txt": "urllib3==2.2.1\n",
    }
    findings = by_code(hygiene_findings(parse_project(files, "p")), Code.MISSING_HASHES)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.location.file, finding.location.line) == ("requirements.txt", None)  # no invented line
    assert finding.severity == Severity.low and finding.category == "dependency_hygiene"
    assert finding.evidence["entry_count"] == 3
    assert finding.evidence["examples"] == ["flask", "idna", "requests"]
    assert finding.evidence["manifest_type"] == "requirements"


def test_missing_hashes_covers_included_requirements_files():
    files = {"requirements.txt": "-r base.txt\n", "base.txt": "a==1\nb==2\n"}
    findings = by_code(hygiene_findings(parse_project(files, "p")), Code.MISSING_HASHES)
    assert [f.location.file for f in findings] == ["base.txt"]  # the top file declares nothing itself


def test_missing_hashes_for_lock_files_only_when_no_entry_has_a_hash():
    for directory in ("requirements", "poetry", "poetry-legacy", "pipenv"):
        inventory = parse_project(fixture_files(directory), directory)
        assert not by_code(hygiene_findings(inventory), Code.MISSING_HASHES), directory
    lock = ('[[package]]\nname = "a"\nversion = "1.0"\nfiles = []\n\n'
            '[[package]]\nname = "b"\nversion = "2.0"\nfiles = []\n')
    findings = by_code(hygiene_findings(parse_project({"poetry.lock": lock}, "p")), Code.MISSING_HASHES)
    assert [(f.location.file, f.evidence["entry_count"], f.evidence["manifest_type"]) for f in findings] == \
        [("poetry.lock", 2, "poetry-lock")]


# --------------------------------------------------------------------------- INDEX_SOURCE_AMBIGUITY
def test_index_source_ambiguity_for_the_fixture_extra_index_url():
    files = fixture_files("requirements")
    findings = by_code(hygiene_findings(parse_project(files, "fixture")), Code.INDEX_SOURCE_AMBIGUITY)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.severity, finding.category) == (Severity.medium, "dependency_confusion")
    assert (finding.location.file, finding.location.line) == \
        ("requirements.txt", line_of(files["requirements.txt"], "--extra-index-url"))
    assert finding.evidence["extra_index_url"] == "https://pypi.org/simple"
    assert finding.evidence["index_url"] == "https://[REDACTED]@packages.internal.example/simple"


def test_index_source_ambiguity_is_reported_per_extra_index_url_line():
    files = {
        "requirements.txt": "--extra-index-url https://a.example/simple\nx==1\n"
                            "--extra-index-url=https://tok3n@b.example/simple\n",
        "requirements-dev.txt": "--index-url https://only.example/simple\ny==1\n",
    }
    findings = by_code(hygiene_findings(parse_project(files, "p")), Code.INDEX_SOURCE_AMBIGUITY)
    assert [(f.location.file, f.location.line) for f in findings] == [("requirements.txt", 1), ("requirements.txt", 3)]
    assert findings[0].evidence["index_url"] == "https://pypi.org/simple (pip default)"
    assert findings[1].evidence["extra_index_url"] == "https://[REDACTED]@b.example/simple"


# ------------------------------------------------------------------------------------ contract
def test_findings_are_deterministic_serialisable_and_credential_free():
    files = fixture_files("requirements")
    first = hygiene_findings(parse_project(files, "fixture"))
    second = hygiene_findings(parse_project(dict(reversed(list(files.items()))), "fixture"))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert len({f.finding_id for f in first}) == len(first)
    dumped = json.dumps([f.to_dict() for f in first])
    for secret in ("fixture-token-123", "fixture-secret", "ci-user", "deploy-user"):
        assert secret not in dumped
    for finding in first:
        assert Finding.from_dict(finding.to_dict()).finding_id == finding.finding_id
        assert finding.to_dict()["compliance"]  # taxonomy mappings are attached


def test_empty_inventory_has_no_findings():
    assert hygiene_findings(ProjectInventory(project_name="empty", root_ref="warden:project/empty")) == []
