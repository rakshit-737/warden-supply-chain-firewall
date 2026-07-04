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
