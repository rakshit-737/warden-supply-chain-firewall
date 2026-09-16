from app.analysis.analyzers.base import PackageContext
from app.analysis.analyzers.typosquat import TyposquatAnalyzer, damerau_levenshtein
from app.analysis.signals import Code

analyzer = TyposquatAnalyzer()


def _ctx(name: str) -> PackageContext:
    return PackageContext(ecosystem="pypi", name=name, version="1.0")


def test_transposition_distance():
    assert damerau_levenshtein("reqeusts", "requests") == 1


def test_flags_typosquat_of_requests():
    signals = analyzer.analyze(_ctx("reqeusts"))
    assert any(s.code == Code.TYPOSQUAT for s in signals)


def test_exact_popular_name_not_flagged():
    assert analyzer.analyze(_ctx("requests")) == []


def test_unrelated_name_not_flagged():
    assert analyzer.analyze(_ctx("my-totally-unique-app-xyz")) == []


def test_homoglyph_detection():
    # 'c0lorama' (zero-for-o) folds to 'colorama' and must be flagged as a disguise.
    signals = analyzer.analyze(_ctx("c0lorama"))
    assert any(s.code == Code.TYPOSQUAT for s in signals)


# --------------------------------------------------------------------------- v2 additions
def test_capital_i_for_l_homoglyph_is_flagged_as_disguise():
    # "jeIlyfish" (capital I for l) was a documented malicious PyPI upload in 2019; used here as a string only.
    [finding] = analyzer.analyze(_ctx("jeIlyfish"))
    assert finding.evidence["kind"] == "homoglyph"
    assert finding.evidence["target"] == "jellyfish"
    assert finding.confidence == 0.9


def test_fullwidth_unicode_name_is_a_critical_confusable():
    [finding] = analyzer.analyze(_ctx("ｒｅｑｕｅｓｔｓ"))
    assert finding.evidence["kind"] == "confusable"
    assert finding.evidence["target"] == "requests"
    assert finding.severity.value == "critical"


def test_bundled_allowlist_suppresses_documented_legitimate_near_name():
    # fastai (the fast.ai deep-learning library) is one edit away from fastapi but is legitimate.
    unlisted = TyposquatAnalyzer(allowlist=frozenset())
    [finding] = unlisted.analyze(_ctx("fastai"))
    assert finding.evidence["target"] == "fastapi" and finding.confidence >= 0.7
    # The allowlist removes only the (fastai, fastapi) pair. A weaker resemblance to another popular name
    # may remain, but it must stay below the policy engine's default blocking confidence.
    remaining = analyzer.analyze(_ctx("fastai"))
    assert all(f.evidence["target"] != "fastapi" and f.confidence < 0.7 for f in remaining)


def test_prefix_letter_naming_pattern_stays_below_policy_blocking_confidence():
    # grequests (gevent + requests) adds a first letter: a naming pattern, not a typing error.
    unlisted = TyposquatAnalyzer(allowlist=frozenset())
    [finding] = unlisted.analyze(_ctx("grequests"))
    assert finding.confidence < 0.7
