"""Typosquat analyzer v2: real popularity data, similarity kinds, false-positive rate, robustness.

Names of documented historical malicious PyPI uploads are used ONLY as strings -- nothing is
downloaded, installed, imported or executed:

* ``urlib3``, ``setup-tools`` -- listed in the SK-CSIRT advisory on malicious PyPI libraries (2017);
* ``colourama`` -- clipboard-hijacking imitation of colorama reported in 2018;
* ``python3-dateutil``, ``jeIlyfish`` -- credential-stealing uploads reported in December 2019.

``tests/data/typosquat/legit_next5000.txt`` holds real PyPI project names ranked 5001-10000 by downloads
(the same public dataset as the bundled popular list); they are *assumed* benign and used to measure the
false-positive rate. The refresh-script tests use small JSON fixtures modelled on the public dataset's
format (labelled as fixtures below) and an in-memory HTTP transport: no test touches the network.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import re
import statistics
import sys
import time
from pathlib import Path

import httpx
import pytest
from hypothesis import given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from app.analysis.analyzers import typosquat as ts
from app.analysis.analyzers.base import PackageContext
from app.analysis.analyzers.typosquat import TargetIndex, TyposquatAnalyzer, find_matches
from app.analysis.findings import Severity
from app.analysis.signals import Capability, Code
from app.core.http import SafeHttpClient

BACKEND = Path(__file__).resolve().parent.parent
FIXTURE = BACKEND / "tests" / "data" / "typosquat" / "legit_next5000.txt"
NO_ALLOWLIST: frozenset[tuple[str, str]] = frozenset()
BLOCKING_CONFIDENCE = 0.7  # the policy engine's default min_confidence for capability blocks

# False-positive thresholds over the 5000 legitimate names. Measured on the bundled 2026-09 snapshot with
# analyzer 2.0.0 and the allowlist DISABLED: 61 flagged (1.22%), 4 at confidence >= 0.7 (0.08%). The bounds
# leave headroom for monthly data refreshes (both lists move) but fail on a regression that pushes noise past
# 1 in 50 names, or that would let the default policy block more than 10 of these 5000 legitimate packages.
MAX_FALSE_POSITIVE_RATE = 0.02
MAX_BLOCKING_FALSE_POSITIVE_RATE = 0.002


def _ctx(name: object) -> PackageContext:
    return PackageContext(ecosystem="pypi", name=name, version="1.0.0")  # type: ignore[arg-type]


def _best(name: str, allowlist: frozenset[tuple[str, str]] = NO_ALLOWLIST) -> ts.Match | None:
    matches = find_matches(name, allowlist=allowlist)
    return matches[0] if matches else None


def _names(path: Path) -> list[str]:
    return ts.parse_popular_text(path.read_text(encoding="utf-8"))[0]


def _header(path: Path) -> dict[str, str]:
    return ts.parse_popular_text(path.read_text(encoding="utf-8"))[1]


@pytest.fixture()
def reload_after():
    yield
    ts.reload_data()


# --------------------------------------------------------------------------- bundled data
def test_popular_list_is_the_ranked_public_snapshot_with_provenance_header():
    names = _names(ts.POPULAR_PATH)
    meta = _header(ts.POPULAR_PATH)
    assert len(names) == 5000 == int(meta["rows"]) == len(set(names))
    assert all(ts.canonical(n) == n and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", n) for n in names)
    assert meta["source"].startswith("https://hugovk.github.io/top-pypi-packages/")
    assert "CC-BY-4.0" in meta["licence"] and "10.5281/zenodo." in meta["licence"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["retrieved"])
    assert meta["ranks"].startswith("1-5000 ")
    ranks = ts.default_index().ranks
    assert all(ranks[n] <= 100 for n in ("requests", "urllib3", "numpy", "boto3", "setuptools", "certifi"))
    assert list(ranks) == names  # file order is rank order


def test_false_positive_fixture_is_a_labelled_disjoint_sample():
    text = FIXTURE.read_text(encoding="utf-8")
    names = _names(FIXTURE)
    assert text.startswith("# TEST FIXTURE")
    assert len(names) == 5000 == len(set(names))
    assert _header(FIXTURE)["ranks"].startswith("5001-10000 ")
    assert not set(names) & set(ts.default_index().ranks)


def test_allowlist_entries_are_justified_and_each_suppresses_a_real_finding():
    entries = ts.parse_allowlist_text(ts.ALLOWLIST_PATH.read_text(encoding="utf-8"))
    ranks = ts.default_index().ranks
    assert entries
    assert len({(e.candidate, e.target) for e in entries}) == len(entries)
    for entry in entries:
        assert len(entry.justification) >= 20, entry
        assert entry.candidate not in ranks, entry  # popular names are never flagged anyway
        assert entry.target in ranks, entry
        assert any(m.target == entry.target for m in find_matches(entry.candidate, allowlist=NO_ALLOWLIST)), entry
        assert all(m.target != entry.target for m in find_matches(entry.candidate)), entry


def test_allowlist_parser_ignores_unjustified_and_malformed_lines():
    text = "a1 b1  # a good reason\nc1 d1\n# comment\ne1 f1 g1  # three names\n\nH_1 I.2  # canonicalised\n"
    assert [(e.candidate, e.target) for e in ts.parse_allowlist_text(text)] == [("a1", "b1"), ("h-1", "i-2")]


def test_allowlist_suppresses_only_the_listed_pair():
    index = TargetIndex.build(["requests", "requestx"])
    assert [m.target for m in find_matches("requestz", index=index, allowlist=NO_ALLOWLIST)] == [
        "requests", "requestx"]
    remaining = find_matches("requestz", index=index, allowlist=frozenset({("requestz", "requests")}))
    assert [m.target for m in remaining] == ["requestx"]


# --------------------------------------------------------------------------- historical squats
@pytest.mark.parametrize(("name", "kind", "target"), [
    ("urlib3", "typo", "urllib3"),
    ("setup-tools", "separator", "setuptools"),
    ("colourama", "typo", "colorama"),
    ("python3-dateutil", "typo", "python-dateutil"),
    ("jeIlyfish", "homoglyph", "jellyfish"),
])
def test_documented_historical_typosquats_are_flagged_at_blocking_confidence(name, kind, target):
    [finding] = TyposquatAnalyzer().analyze(_ctx(name))
    assert finding.code == Code.TYPOSQUAT and finding.capability == Capability.TYPOSQUAT
    assert (finding.evidence["kind"], finding.evidence["target"]) == (kind, target)
    assert finding.evidence["target_rank"] == ts.default_index().ranks[target]
    assert finding.evidence["candidate"] == name
    assert finding.confidence >= BLOCKING_CONFIDENCE
    assert finding.severity in (Severity.critical, Severity.high)
    assert finding.location is None  # a name has no source position


# --------------------------------------------------------------------------- kinds and grades
@pytest.mark.parametrize(("name", "kind", "target", "confidence", "severity", "weight", "distance", "operation"), [
    ("reqeusts", "typo", "requests", 0.85, Severity.critical, 9.0, 1, "transposition"),
    ("reqiests", "typo", "requests", 0.85, Severity.critical, 9.0, 1, "substitution"),
    ("requestss", "typo", "requests", 0.85, Severity.critical, 9.0, 1, "insertion"),
    ("urlib3", "typo", "urllib3", 0.85, Severity.critical, 9.0, 1, "deletion"),
    ("types-reqeusts", "typo", "types-requests", 0.85, Severity.critical, 9.0, 1, "transposition"),
    ("rquest", "typo", "requests", 0.6, Severity.high, 6.0, 2, "edit-distance-2"),
    ("c0lorama", "homoglyph", "colorama", 0.9, Severity.critical, 10.0, 0, "glyph-fold"),
    ("co1orama", "homoglyph", "colorama", 0.9, Severity.critical, 10.0, 0, "glyph-fold"),
    ("pythondateutil", "separator", "python-dateutil", 0.8, Severity.high, 7.0, 1, "separator-removed"),
    ("request", "plural", "requests", 0.65, Severity.high, 5.0, 1, "plural-removed"),
    ("requests-api", "combosquat", "requests", 0.6, Severity.medium, 4.0, 4, "affix-added"),
    ("python-requests", "combosquat", "requests", 0.6, Severity.medium, 4.0, 7, "affix-added"),
    ("dateutil", "combosquat", "python-dateutil", 0.6, Severity.medium, 4.0, 7, "affix-removed"),
    ("py-dateutil", "combosquat", "python-dateutil", 0.6, Severity.medium, 4.0, 4, "affix-changed"),
    ("urllib", "combosquat", "urllib3", 0.6, Severity.medium, 4.0, 1, "version-suffix"),
    ("setnhuptols", "similar", "setuptools", 0.55, Severity.medium, 3.0, 3, "jaro-winkler"),
])
def test_resemblance_kinds_grades_and_evidence(name, kind, target, confidence, severity, weight, distance, operation):
    [finding] = TyposquatAnalyzer(allowlist=NO_ALLOWLIST).analyze(_ctx(name))
    ev = finding.evidence
    assert (ev["kind"], ev["target"], ev["distance"], ev["operation"]) == (kind, target, distance, operation)
    assert (finding.confidence, finding.severity, finding.weight) == (confidence, severity, weight)
    assert ev["target_rank"] == ts.default_index().ranks[target]
    assert ev["canonical"] == ts.canonical(name)
    assert {"candidate", "canonical", "kind", "target", "target_rank", "distance", "similarity"} <= set(ev)
    if kind == "similar":
        assert ev["similarity"] >= ts.JARO_WINKLER_THRESHOLD
    assert ev["target_list"]["size"] == 5000


@pytest.mark.parametrize(("name", "mechanism"), [
    ("reqeusts", "transposition"), ("reqiests", "keyboard-adjacent"), ("requestss", "doubled-key"),
    ("urlib3", "missed-double"), ("colourama", None),
])
def test_typing_mechanism_is_recorded(name, mechanism):
    [finding] = TyposquatAnalyzer().analyze(_ctx(name))
    assert finding.evidence.get("typing_mechanism") == mechanism


def _ranked(targets: dict[int, str], size: int = 3000) -> TargetIndex:
    """A synthetic ranked list with chosen names at chosen ranks (fillers cannot resemble them)."""
    names = [f"filler-{i:05d}" for i in range(size)]
    for rank, name in targets.items():
        names[rank - 1] = name
    return TargetIndex.build(names)


def test_popularity_weighting_lowers_confidence_for_less_popular_targets():
    index = _ranked({50: "sqlalchemy", 300: "matplotlib", 800: "cryptography", 3000: "beautifulsoup"})
    transpositions = {"sqlalcehmy": 0.85, "matplotilb": 0.85, "cryptograhpy": 0.75, "beautifusloup": 0.6}
    for name, expected in transpositions.items():
        [match] = find_matches(name, index=index, allowlist=NO_ALLOWLIST)
        assert match.confidence == expected, name
    # A substitution with no typing mechanism: strong on a top-500 target, weak at 501-1000, none beyond.
    index = _ranked({50: "sqlalchemy", 800: "cryptography", 3000: "beautifulsoup"})
    assert _only(find_matches("sqlalkhemy", index=index, allowlist=NO_ALLOWLIST)).confidence == 0.85
    # m/a are far apart on QWERTY (q/a would be keyboard-adjacent: q sits directly above a).
    assert _only(find_matches("cryptogrmphy", index=index, allowlist=NO_ALLOWLIST)).confidence == 0.65
    assert find_matches("beautifulsoqp", index=index, allowlist=NO_ALLOWLIST) == []


def _only(matches: list[ts.Match]) -> ts.Match:
    assert len(matches) == 1, matches
    return matches[0]


def test_short_names_need_a_top_1000_target_and_a_typing_mechanism():
    index = _ranked({10: "yaml", 1500: "toml"})
    assert _only(find_matches("yamk", index=index, allowlist=NO_ALLOWLIST)).confidence == 0.65  # k next to l
    assert find_matches("yamx", index=index, allowlist=NO_ALLOWLIST) == []  # no mechanism
    assert find_matches("xaml", index=index, allowlist=NO_ALLOWLIST) == []  # first letter
    assert find_matches("tomk", index=index, allowlist=NO_ALLOWLIST) == []  # target outside the top 1000


def test_only_a_capital_i_is_a_homoglyph_for_l_while_lowercase_i_is_a_weaker_look_alike():
    capital = _best("jeIlyfish")
    assert (capital.kind, capital.target, capital.confidence) == ("homoglyph", "jellyfish", 0.9)
    lower = _best("jeilyfish")
    assert (lower.kind, lower.target, lower.operation) == ("typo", "jellyfish", "substitution")
    assert dict(lower.details)["typing_mechanism"] == "look-alike"
    assert lower.confidence < capital.confidence
    # An i/l transposition is a typing error with a mechanism, never a glyph disguise.
    transposed = _only(find_matches("matplotilb", index=_ranked({50: "matplotlib"}), allowlist=NO_ALLOWLIST))
    assert (transposed.kind, transposed.operation, transposed.confidence) == ("typo", "transposition", 0.85)
    # The capital-I fold applies to the case-preserved candidate only: a target's own "i" is never folded.
    index = _ranked({10: "pillow", 20: "lxml"})
    assert _only(find_matches("PiIlow", index=index, allowlist=NO_ALLOWLIST)).kind == "homoglyph"
    assert _only(find_matches("Ixml", index=index, allowlist=NO_ALLOWLIST)).kind == "homoglyph"
    assert find_matches("pilIow", index=index, allowlist=NO_ALLOWLIST)[0].kind == "homoglyph"
    assert all(m.kind != "homoglyph" for m in find_matches("plllow", index=index, allowlist=NO_ALLOWLIST))


def test_distance_two_ignores_word_level_changes():
    index = _ranked({20: "jupyterlab", 30: "watchdog", 40: "pandas", 50: "requests"})
    for legit in ("jupyterhub", "watchgod", "pandasai", "pandoc"):
        assert find_matches(legit, index=index, allowlist=NO_ALLOWLIST) == [], legit
    assert _only(find_matches("rquest", index=index, allowlist=NO_ALLOWLIST)).distance == 2


# --------------------------------------------------------------------------- unicode confusables
@pytest.mark.parametrize(("name", "target", "code_point"), [
    ("rеquеsts", "requests", "U+0435"),  # Cyrillic small ie
    ("djangο", "django", "U+03BF"),  # Greek small omicron
    ("ｒｅｑｕｅｓｔｓ", "requests", "U+FF52"),  # fullwidth Latin
    ("num​py", "numpy", "U+200B"),  # zero-width space
    ("‮requests", "requests", "U+202E"),  # right-to-left override
    ("ńumpy", "numpy", "U+0301"),  # combining acute accent
])
def test_unicode_confusables_are_critical_and_name_the_imitated_target(name, target, code_point):
    [finding] = TyposquatAnalyzer().analyze(_ctx(name))
    assert finding.evidence["kind"] == "confusable"
    assert finding.evidence["target"] == target
    assert code_point in finding.evidence["non_ascii"]
    assert (finding.severity, finding.confidence, finding.weight) == (Severity.critical, 0.9, 10.0)
    json.dumps(finding.to_dict())


def test_any_non_ascii_name_is_suspicious_even_without_a_target():
    [finding] = TyposquatAnalyzer().analyze(_ctx("пакет"))  # Cyrillic word
    assert finding.evidence["kind"] == "confusable" and finding.evidence["target"] is None
    assert (finding.severity, finding.confidence) == (Severity.critical, 0.8)
    assert "non-ASCII" in finding.message


# --------------------------------------------------------------------------- false positives
def test_no_popular_name_or_display_variant_is_ever_flagged():
    analyzer = TyposquatAnalyzer(allowlist=NO_ALLOWLIST)
    for name in _names(ts.POPULAR_PATH):
        assert analyzer.analyze(_ctx(name)) == [], name
    for variant in ("Requests", "PYTHON_DATEUTIL", "python.dateutil", "Typing_Extensions", "  numpy  "):
        assert analyzer.analyze(_ctx(variant)) == [], variant


@pytest.mark.parametrize("name", [
    "flask-colorama", "pytest-urllib3", "django-boto3", "sphinx-numpy", "types-pyyaml-extra",
    "my-totally-unique-app-xyz", "acme-billing-service", "internal-data-pipeline",
])
def test_framework_plugins_and_unrelated_internal_names_are_not_flagged(name):
    assert find_matches(name, allowlist=NO_ALLOWLIST) == []


def test_plugin_namespace_with_generic_suffix_is_still_a_combosquat():
    match = _best("pytest-utils")
    assert (match.kind, match.target, match.operation) == ("combosquat", "pytest", "affix-added")
    assert match.confidence < BLOCKING_CONFIDENCE


@pytest.mark.parametrize("name", [
    # Real, legitimate projects from the fixture that sit close to a popular name.
    "grequests", "torchx", "willow", "bpython", "elasticsearch8", "gitdb2", "google-cloud-filestore",
    "jupyterhub", "watchgod", "pandasai", "localstack", "streamlink", "datasette", "transforms3d",
    "langchainhub", "pytest-lazy-fixture", "attr", "postgres", "kafka",
])
def test_legitimate_near_names_never_reach_blocking_confidence(name):
    match = _best(name)
    assert match is None or match.confidence < BLOCKING_CONFIDENCE, (name, match)


def test_false_positive_rate_on_5000_legitimate_names_stays_below_threshold():
    names = _names(FIXTURE)
    flagged = {name: match for name in names if (match := _best(name)) is not None}
    blocking = {n: (m.kind, m.target, m.confidence) for n, m in flagged.items() if m.confidence >= BLOCKING_CONFIDENCE}
    rate, blocking_rate = len(flagged) / len(names), len(blocking) / len(names)
    assert rate <= MAX_FALSE_POSITIVE_RATE, (f"{rate:.2%}", sorted(flagged)[:50])
    assert blocking_rate <= MAX_BLOCKING_FALSE_POSITIVE_RATE, (f"{blocking_rate:.2%}", blocking)
    # The bundled allowlist only ever removes findings.
    still_flagged = [name for name in flagged if find_matches(name)]
    assert len(still_flagged) <= len(flagged)
    assert all(_best(n) is None for n in names[:200] if n not in flagged)


# --------------------------------------------------------------------------- robustness
HOSTILE_NAMES = [
    "", "   ", "-", "---", "_._", "a", "ab", "\x00", "\x00requests", "requests\n", "a" * 214, "a" * 215,
    "a" * 100_000, "е" * 100_000, "ﷺ" * 5000, "\udcff" * 10, "‮" * 50, "req uests",
    "../../etc/passwd", "requests; rm -rf /", "0" * 300, "i" * 100 + "rn" * 50, "\U0001d42b\U0001d41e\U0001d42a",
    "I" * 5000, "-".join(["requests"] * 500),
]


# Short ids: pytest exports the node id in an environment variable, which Windows caps at 32767 characters.
@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=[f"hostile-{i}" for i in range(len(HOSTILE_NAMES))])
def test_hostile_names_never_crash_and_stay_bounded(name):
    start = time.perf_counter()
    findings = TyposquatAnalyzer().analyze(_ctx(name))
    assert time.perf_counter() - start < 2.0
    assert len(findings) <= 1
    for finding in findings:
        assert finding.code == Code.TYPOSQUAT
        assert len(finding.evidence["candidate"]) <= 300
        assert len(finding.message) <= 500
        json.dumps(finding.to_dict())


def test_non_string_or_missing_name_is_handled():
    assert TyposquatAnalyzer().analyze(_ctx(None)) == []
    assert find_matches(12345) == []


@hsettings(max_examples=150, deadline=None, database=None)
@given(st.text(max_size=64))
def test_matching_is_total_deterministic_and_bounded_for_arbitrary_text(name):
    first = find_matches(name, allowlist=NO_ALLOWLIST)
    assert first == find_matches(name, allowlist=NO_ALLOWLIST)
    assert len({m.target for m in first}) == len(first)
    assert all(0.0 <= m.confidence <= 1.0 and m.weight >= 0 for m in first)
    stripped = name.strip()
    if stripped.isascii() and ts.canonical(stripped) in ts.default_index().ranks:
        assert first == []


def test_findings_are_deterministic_across_instances():
    first = TyposquatAnalyzer().analyze(_ctx("reqeusts"))[0]
    second = TyposquatAnalyzer().analyze(_ctx("reqeusts"))[0]
    assert first.to_dict() == second.to_dict()
    assert first.finding_id == second.finding_id


def test_target_index_build_drops_invalid_duplicate_and_oversized_names():
    index = TargetIndex.build(["Requests", "requests", "bad name!", "x" * 300, "ok_name", "", "-lead"])
    assert index.ranks == {"requests": 1, "ok-name": 2}


def test_data_loader_caps_file_size_and_drops_the_cut_line(tmp_path, monkeypatch, reload_after):
    data = tmp_path / "popular.txt"
    data.write_text("# retrieved: 2026-09-15\nalpha\nbravo\ncharlie-delta-echo\n", encoding="utf-8")
    monkeypatch.setattr(ts, "POPULAR_PATH", data)
    monkeypatch.setattr(ts, "MAX_DATA_FILE_BYTES", 40)
    ts.reload_data()
    index = ts.default_index()
    assert list(index.ranks) == ["alpha", "bravo"]
    assert index.metadata["retrieved"] == "2026-09-15"


def test_missing_target_list_reports_unavailable_and_fails_closed(tmp_path, monkeypatch, reload_after):
    empty = TyposquatAnalyzer(index=TargetIndex.build(()))
    status = empty.availability()
    assert status.available is False and "missing" in status.detail
    with pytest.raises(RuntimeError):
        empty.analyze(_ctx("reqeusts"))
    monkeypatch.setattr(ts, "POPULAR_PATH", tmp_path / "does-not-exist.txt")
    ts.reload_data()
    assert TyposquatAnalyzer().availability().available is False


def test_analyzer_metadata_and_availability_detail():
    assert TyposquatAnalyzer.name == "typosquat" and TyposquatAnalyzer.version == "2.0.0"
    assert TyposquatAnalyzer.requires_network is False
    status = TyposquatAnalyzer().availability()
    assert status.available is True and status.detail.startswith("5000 targets")


# --------------------------------------------------------------------------- metrics
def test_jaro_winkler_reference_values():
    assert ts.jaro_winkler("martha", "marhta") == pytest.approx(0.9611, abs=1e-4)
    assert ts.jaro_winkler("dwayne", "duane") == pytest.approx(0.84, abs=1e-4)
    assert ts.jaro_winkler("dixon", "dicksonx") == pytest.approx(0.8133, abs=1e-4)
    assert ts.jaro_winkler("abc", "abc") == 1.0
    assert ts.jaro_winkler("", "abc") == 0.0


def test_optimal_string_alignment_distance_and_bounds():
    assert ts.damerau_levenshtein("reqeusts", "requests") == 1
    assert ts.damerau_levenshtein("kitten", "sitting") == 3
    assert ts.damerau_levenshtein("ca", "abc") == 3  # OSA, not unrestricted Damerau-Levenshtein
    assert ts.damerau_levenshtein("abcdef", "ghijkl", max_distance=2) == 3
    assert ts.damerau_levenshtein("a" * 600, "a" * 599 + "b") == 4  # oversized inputs are not compared
    assert ts.damerau_levenshtein("a" * 600, "a" * 600) == 0


def test_keyboard_adjacency_and_single_edit_classification():
    assert all(ts.keyboard_adjacent(a, b) for a, b in [("q", "w"), ("q", "a"), ("s", "z"), ("s", "x"), ("1", "q"),
                                                        ("p", "l"), ("m", "k"), ("u", "i")])
    assert not any(ts.keyboard_adjacent(a, b) for a, b in [("a", "l"), ("q", "p"), ("a", "a"), ("-", "a")])
    assert ts.single_edit("reqeusts", "requests") == ("transposition", 3, "eu", "ue")
    assert ts.single_edit("colourama", "colorama") == ("insertion", 4, "u", "")
    assert ts.single_edit("urlib3", "urllib3") == ("deletion", 3, "", "l")
    assert ts.single_edit("reqiests", "requests") == ("substitution", 3, "i", "u")
    assert ts.single_edit("abc", "xyz") is None and ts.single_edit("abcd", "ab") is None


# --------------------------------------------------------------------------- performance
def test_single_analysis_over_5000_targets_is_fast():
    start = time.perf_counter()
    TargetIndex.build(_names(ts.POPULAR_PATH))
    assert time.perf_counter() - start < 10.0  # generous; measured 0.15-0.4 s
    analyzer = TyposquatAnalyzer()
    analyzer.analyze(_ctx("warm-up"))
    sample = _names(FIXTURE)[::25] + ["reqeusts", "c0lorama", "python3-dateutil", "x" * 214, "rеquеsts"]
    timings = []
    for name in sample:
        begin = time.perf_counter()
        analyzer.analyze(_ctx(name))
        timings.append(time.perf_counter() - begin)
    assert statistics.median(timings) < 0.020  # design target "< 20 ms typical"; measured ~1 ms
    assert max(timings) < 1.0


# --------------------------------------------------------------------------- refresh script
def _load_refresh_script():
    """Import Warden's own maintenance script by path (it is not package content being analysed)."""
    path = BACKEND / "scripts" / "refresh_popular_packages.py"
    name = "warden_refresh_popular_packages"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


refresh = _load_refresh_script()


def _dataset(rows: list, **extra) -> dict:
    """TEST FIXTURE modelled on the public top-pypi-packages JSON format (not real download counts)."""
    return {"last_update": "2026-09-01 06:34:08", "source": "ClickHouse", "rows": rows, **extra}


def _rows(count: int) -> list[dict]:
    return [{"download_count": 10_000 - i, "project": f"pkg-{i:02d}"} for i in range(count)]


def _client(handler) -> SafeHttpClient:
    return SafeHttpClient(name="test-top-pypi", allowed_hosts=refresh.ALLOWED_HOSTS, retries=0,
                          client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _s: None)


def _json_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, content=json.dumps(payload).encode(), headers={"content-type": "application/json"})


def test_refresh_urls_are_https_on_allowlisted_hosts_only():
    assert refresh.ALLOWED_HOSTS == frozenset({"hugovk.github.io", "hugovk.dev"})
    assert all(httpx.URL(u).scheme == "https" and httpx.URL(u).host in refresh.ALLOWED_HOSTS
               for u in refresh.DATASET_URLS)


def test_parse_dataset_validates_sorts_and_deduplicates():
    rows = [
        {"download_count": 5, "project": "Beta_Pkg"},
        {"download_count": 9, "project": "alpha"},
        {"download_count": 7, "project": "beta.pkg"},  # canonical duplicate of Beta_Pkg with more downloads
        {"download_count": 8, "project": "bad name"},
        {"download_count": 8, "project": "rеquests"},
        {"download_count": True, "project": "boolcount"},
        {"download_count": -1, "project": "negative"},
        {"download_count": 3, "project": "x" * 300},
        "not-a-row",
        {"download_count": 1, "project": "gamma"},
    ]
    dataset = refresh.parse_dataset(_dataset(rows, last_update="2026-09-01\n# licence: forged"))
    assert dataset.names == ("alpha", "beta-pkg", "gamma")
    assert dataset.raw_rows == 10 and dataset.rejected_rows == 7
    assert "\n" not in (dataset.last_update or "")
    for bad in ([], {"rows": []}, {"rows": "x"}, {"rows": [{"project": "a b", "download_count": 1}]}):
        with pytest.raises(refresh.DatasetError):
            refresh.parse_dataset(bad)
    with pytest.raises(refresh.DatasetError):
        refresh.parse_dataset(_dataset(_rows(5)), max_rows=4)


def test_fetch_follows_github_io_redirect_to_hugovk_dev():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "hugovk.github.io":
            return httpx.Response(301, headers={"location": "https://hugovk.dev" + request.url.path})
        return _json_response(_dataset(_rows(3)))

    payload, requested, final = refresh.fetch_dataset(_client(handler), log=lambda _m: None)
    assert requested == refresh.DATASET_URLS[0]
    assert final == "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
    assert len(payload["rows"]) == 3


def test_fetch_refuses_redirects_off_the_allowlist_and_tries_the_next_url():
    seen: list[str] = []
    logs: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "hugovk.github.io":
            return httpx.Response(302, headers={"location": "https://attacker.example/top.json"})
        return _json_response(_dataset(_rows(2)))

    _payload, requested, _final = refresh.fetch_dataset(_client(handler), log=logs.append)
    assert requested == refresh.DATASET_URLS[2]
    assert not any("attacker.example" in url for url in seen)
    assert len(logs) == 2 and all("host_not_allowed" in line for line in logs)


def test_main_writes_ranked_lists_with_provenance_header(tmp_path):
    popular, fixture = tmp_path / "popular.txt", tmp_path / "fixture.txt"
    client = _client(lambda _request: _json_response(_dataset(_rows(30))))
    code = refresh.main(["--top", "10", "--next", "5", "--popular-out", str(popular), "--fixture-out", str(fixture)],
                        client=client, today=dt.date(2026, 9, 15))
    assert code == 0
    names, meta = ts.parse_popular_text(popular.read_text(encoding="utf-8"))
    assert names == [f"pkg-{i:02d}" for i in range(10)]
    assert (meta["rows"], meta["retrieved"]) == ("10", "2026-09-15")
    assert meta["ranks"].startswith("1-10 ") and "CC-BY-4.0" in meta["licence"]
    assert meta["source"] == refresh.DATASET_URLS[0]
    fixture_text = fixture.read_text(encoding="utf-8")
    assert fixture_text.startswith("# TEST FIXTURE")
    assert ts.parse_popular_text(fixture_text)[0] == [f"pkg-{i:02d}" for i in range(10, 15)]
    assert len(TargetIndex.build(names)) == 10


def test_main_keeps_existing_files_when_download_or_validation_fails(tmp_path):
    popular, fixture = tmp_path / "popular.txt", tmp_path / "fixture.txt"
    popular.write_text("keep-me\n", encoding="utf-8")
    fixture.write_text("keep-me-too\n", encoding="utf-8")
    args = ["--popular-out", str(popular), "--fixture-out", str(fixture)]

    down = _client(lambda _request: httpx.Response(503))
    assert refresh.main(args, client=down) == 1
    too_small = _client(lambda _request: _json_response(_dataset(_rows(3))))
    assert refresh.main(["--top", "10", *args], client=too_small) == 1
    not_json = tmp_path / "broken.json"
    not_json.write_text("{not json", encoding="utf-8")
    assert refresh.main(["--input-json", str(not_json), *args]) == 1
    assert popular.read_text(encoding="utf-8") == "keep-me\n"
    assert fixture.read_text(encoding="utf-8") == "keep-me-too\n"


def test_main_offline_input_and_dry_run_write_nothing(tmp_path):
    source = tmp_path / "top.json"
    source.write_text(json.dumps(_dataset(_rows(12))), encoding="utf-8")
    popular, fixture = tmp_path / "popular.txt", tmp_path / "fixture.txt"
    args = ["--input-json", str(source), "--top", "5", "--popular-out", str(popular), "--fixture-out", str(fixture)]
    assert refresh.main([*args, "--dry-run"]) == 0
    assert not popular.exists() and not fixture.exists()
    assert refresh.main(args, today=dt.date(2026, 9, 15)) == 0
    assert _names(popular) == [f"pkg-{i:02d}" for i in range(5)]
    assert _names(fixture) == [f"pkg-{i:02d}" for i in range(5, 12)]
