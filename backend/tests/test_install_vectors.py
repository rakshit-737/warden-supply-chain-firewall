"""Install/startup execution vectors: .pth hooks, sitecustomize, build backends, console-script shadowing."""

from __future__ import annotations

import json

import pytest

from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.analyzers.install_vectors import InstallVectorsAnalyzer


def ctx(files: dict[str, str], name: str = "demo", wheel: dict[str, str] | None = None) -> PackageContext:
    def src(items):
        return [SourceFile(relpath=p, text=t, size=len(t)) for p, t in items.items()]

    return PackageContext(ecosystem="pypi", name=name, version="1.0", files=src(files),
                          wheel_files=src(wheel or {}))


def run(files, **kw):
    return InstallVectorsAnalyzer().analyze(ctx(files, **kw))


def by_code(findings):
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.code, []).append(f)
    return out


def test_plain_package_is_clean():
    pyproject = '[build-system]\nrequires = ["setuptools>=68"]\nbuild-backend = "setuptools.build_meta"\n' \
                '[project]\nname = "demo"\n[project.scripts]\ndemo = "demo.cli:main"\n'
    assert run({"demo-1.0/pyproject.toml": pyproject, "demo-1.0/demo/__init__.py": "x = 1\n",
                "demo-1.0/demo.pth": "src\n# comment\n"}) == []


def test_import_only_pth_is_medium():
    findings = run({"demo-1.0/__editable__.demo.pth": "import __editable___demo_finder; "
                                                     "__editable___demo_finder.install()\n"})
    [finding] = findings
    assert finding.code == "PTH_STARTUP_HOOK" and finding.severity.value == "medium"
    assert finding.confidence == 0.6 and finding.location.line == 1


def test_pth_with_payload_is_critical():
    text = "some/path\nimport base64, os; exec(base64.b64decode('cHJpbnQoMSk='))\n"
    [finding] = run({"demo-1.0/zzz_hook.pth": text})
    assert finding.severity.value == "critical" and finding.location.line == 2
    assert {"exec", "b64decode"} <= set(finding.evidence["indicators"])
    assert finding.capability == "pth_startup_hook"


def test_pth_in_wheel_is_checked_too():
    findings = run({}, wheel={"hook.pth": "import subprocess; subprocess.Popen(['sh'])\n"})
    assert findings and findings[0].severity.value == "critical"


@pytest.mark.parametrize(("path", "reported"), [
    ("demo-1.0/sitecustomize.py", True),
    ("sitecustomize.py", True),
    ("demo-1.0/src/usercustomize.py", True),
    ("demo-1.0/tests/fixtures/sitecustomize.py", False),
])
def test_startup_modules(path, reported):
    findings = run({path: "print('hi')\n"})
    assert bool(findings) is reported
    if reported:
        assert findings[0].severity.value == "high"


def test_in_tree_backend_and_direct_url_requirements():
    pyproject = ('[build-system]\nrequires = ["setuptools", "helper @ https://example.invalid/helper.whl"]\n'
                 'build-backend = "backend"\nbackend-path = ["_build"]\n')
    findings = by_code(run({"demo-1.0/pyproject.toml": pyproject}))
    severities = sorted(f.severity.value for f in findings["BUILD_BACKEND_HOOK"])
    assert severities == ["high", "medium"]
    high = next(f for f in findings["BUILD_BACKEND_HOOK"] if f.severity.value == "high")
    assert high.evidence["backend_path"] == ["_build"] and high.location.line == 4


def test_uncommon_backend_is_informational():
    [finding] = run({"demo-1.0/pyproject.toml": '[build-system]\nbuild-backend = "mybuilder.api"\n'})
    assert finding.severity.value == "low" and finding.confidence == 0.4


def test_nested_and_broken_pyproject_files_are_ignored():
    assert run({"demo-1.0/examples/plugin/pyproject.toml": '[build-system]\nbackend-path=["."]\n'
                                                            'build-backend="x"\n',
                "demo-1.0/pyproject.toml": "[build-system\nnot toml"}) == []


def test_console_script_shadowing_from_every_source():
    files = {
        "demo-1.0/demo.egg-info/entry_points.txt": "[console_scripts]\npip = demo.evil:main\ndemo = demo:main\n",
        "demo-1.0/pyproject.toml": '[project]\nname="demo"\n[project.scripts]\ncurl = "demo.net:main"\n',
        "demo-1.0/setup.py": "setup(entry_points={'console_scripts': ['git = demo.g:main', 'ok-tool = demo:x']})\n",
    }
    findings = by_code(run(files))["ENTRYPOINT_SHADOWING"]
    assert {(f.evidence["script"], f.severity.value) for f in findings} == {
        ("pip", "high"), ("git", "high"), ("curl", "medium")}
    git = next(f for f in findings if f.evidence["script"] == "git")
    assert git.location.file == "demo-1.0/setup.py" and git.location.line == 1


def test_a_package_may_provide_its_own_command():
    files = {"pip-24.0/pip.egg-info/entry_points.txt": "[console_scripts]\npip = pip._internal:main\n"}
    assert run(files, name="pip") == []


def test_malformed_entry_points_do_not_crash():
    assert run({"demo-1.0/demo.egg-info/entry_points.txt": "[console_scripts\n= = =\n"}) == []


def test_hostile_text_is_sanitised():
    token = "gh" + "p_" + "Z" * 36
    findings = run({f"demo-1.0/\x1b[31m{token}.pth": "import os; os.system('id')\n"})
    dumped = json.dumps([f.to_dict() for f in findings])
    assert token not in dumped and "\\u001b[31m" not in dumped
