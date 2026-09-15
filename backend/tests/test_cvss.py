"""CVSS v3.0 / v3.1 base-score calculator.

Named vectors were verified by hand from the FIRST specification equations, e.g. for
``AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``::

    ISS = 1 - (1-0.56)^3 = 0.914816        Impact = 6.42 * ISS = 5.873119
    Exploitability = 8.22*0.85*0.77*0.85*0.85 = 3.887043
    Roundup(min(5.873119 + 3.887043, 10)) = Roundup(9.760162) = 9.8

and ``AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N``::

    ISS = 1 - 0.78*0.78 = 0.3916            Impact = 7.52*(0.3626) - 3.25*(0.3716)^15 = 2.726751
    Exploitability = 8.22*0.85*0.77*0.85*0.62 = 2.835255
    Roundup(min(1.08 * 5.562006, 10)) = Roundup(6.006966) = 6.1

In addition, every Base metric combination (2592 per version) is cross-checked against an
independent exact-rational transcription of the specification written in this file.
"""

from __future__ import annotations

import itertools
import math
from fractions import Fraction as F

import pytest
from hypothesis import given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from app.intel import cvss

KNOWN_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
]


@pytest.mark.parametrize(("vector", "score", "rating"), KNOWN_VECTORS)
def test_known_vectors(vector, score, rating):
    result = cvss.score_vector(vector)
    assert result is not None
    assert result.base_score == score
    assert result.rating == rating
    assert result.version == vector[5:8]
    assert cvss.base_score(vector) == score


def test_metric_order_does_not_matter():
    shuffled = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
    assert cvss.base_score(shuffled) == 9.8


def test_temporal_and_environmental_metrics_are_validated_but_not_scored():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:R/CR:H/IR:X/MAV:L/MS:C/MA:N"
    assert cvss.base_score(vec) == 9.8
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z") is None


def test_surrounding_whitespace_is_tolerated():
    result = cvss.score_vector("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n")
    assert result is not None and result.base_score == 9.8
    assert result.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_v31_roundup_matches_specification_examples():
    # CVSS v3.1 Appendix A: Roundup(4.02) = 4.1, Roundup(4.00) = 4.0.
    assert cvss.roundup_v31(4.02) == 4.1
    assert cvss.roundup_v31(4.00) == 4.0
    assert cvss.roundup_v31(0.0) == 0.0
    assert cvss.roundup_v31(9.99) == 10.0


def test_v31_roundup_absorbs_floating_point_noise_that_breaks_naive_ceil():
    noisy = 4.000000000000001  # binary-float artefact of a mathematically exact 4.0
    assert math.ceil(noisy * 10) / 10 == 4.1  # the v3.0-era naive implementation bug
    assert cvss.roundup_v31(noisy) == 4.0


def test_v30_roundup_is_exact():
    assert cvss.roundup_v30_exact(F("4.02")) == 4.1
    assert cvss.roundup_v30_exact(F(4)) == 4.0
    assert cvss.roundup_v30_exact(F("4.0000000000000001")) == 4.1  # exact input above 4.0 rounds up


MALFORMED = [
    "",
    "CVSS:3.1",
    "CVSS:3.1/",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",  # trailing slash (empty component)
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate base metric
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/E:P",  # duplicate optional metric
    "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid value
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # Not Defined is not valid for base metrics
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:N",  # unknown metric
    "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h",  # lower case
    "CVSS:3.1/AV: N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # inner whitespace
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H\n/A:H",  # embedded newline
    "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown version
    "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",  # CVSS v2: carried, never scored
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # CVSS v4: carried, never scored
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" + "/E:X" * 60,  # oversized (and duplicated)
]


@pytest.mark.parametrize("vector", MALFORMED)
def test_malformed_vectors_return_none(vector):
    assert cvss.score_vector(vector) is None
    assert cvss.base_score(vector) is None
    assert cvss.parse_vector(vector) is None


@pytest.mark.parametrize("value", [None, 9.8, b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ["CVSS:3.1"], {}])
def test_non_string_input_returns_none(value):
    assert cvss.score_vector(value) is None
    assert cvss.vector_version(value) is None


def test_vector_version_recognises_carried_versions():
    assert cvss.vector_version("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.1"
    assert cvss.vector_version("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.0"
    assert cvss.vector_version("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == "4.0"
    assert cvss.vector_version("AV:N/AC:L/Au:N/C:P/I:P/A:P") == "2.0"
    assert cvss.vector_version("(AV:N/AC:L/Au:N/C:P/I:P/A:P)") == "2.0"
    assert cvss.vector_version("hello") is None


@pytest.mark.parametrize("vector", ["(AV:N/AC:L/Au:N/C:P/I:P/A:P", "AV:N/AC:L/Au:N/C:P/I:P/A:P)",
                                    "((AV:N/AC:L/Au:N/C:P/I:P/A:P))"])
def test_unbalanced_v2_parentheses_are_not_recognised(vector):
    assert cvss.vector_version(vector) is None


@pytest.mark.parametrize(("score", "rating"), [
    (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
    (-0.1, None), (10.1, None), (float("nan"), None), (float("inf"), None), (None, None), (True, None),
])
def test_severity_rating_bands(score, rating):
    assert cvss.severity_rating(score) == rating


# --------------------------------------------------------------------------- independent oracle
_AV = {"N": F(85, 100), "A": F(62, 100), "L": F(55, 100), "P": F(20, 100)}
_AC = {"L": F(77, 100), "H": F(44, 100)}
_PR_UNCHANGED = {"N": F(85, 100), "L": F(62, 100), "H": F(27, 100)}
_PR_CHANGED = {"N": F(85, 100), "L": F(68, 100), "H": F(50, 100)}
_UI = {"N": F(85, 100), "R": F(62, 100)}
_CIA = {"H": F(56, 100), "L": F(22, 100), "N": F(0)}


def _spec_roundup_31(x: F) -> F:
    int_input = math.floor(x * 100000 + F(1, 2))
    if int_input % 10000 == 0:
        return F(int_input, 100000)
    return F(int_input // 10000 + 1, 10)


def _spec_roundup_30(x: F) -> F:
    return F(math.ceil(x * 10), 10)


def _oracle(version: str, av, ac, pr, ui, s, c, i, a) -> F:
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if s == "U":
        impact, pr_weight = F(642, 100) * iss, _PR_UNCHANGED[pr]
    else:
        impact = F(752, 100) * (iss - F(29, 1000)) - F(325, 100) * (iss - F(2, 100)) ** 15
        pr_weight = _PR_CHANGED[pr]
    exploitability = F(822, 100) * _AV[av] * _AC[ac] * pr_weight * _UI[ui]
    if impact <= 0:
        return F(0)
    total = impact + exploitability if s == "U" else F(108, 100) * (impact + exploitability)
    total = min(total, F(10))
    return _spec_roundup_31(total) if version == "3.1" else _spec_roundup_30(total)


@pytest.mark.parametrize("version", ["3.0", "3.1"])
def test_every_base_vector_matches_exact_specification_oracle(version):
    mismatches = []
    for combo in itertools.product("NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"):
        av, ac, pr, ui, s, c, i, a = combo
        vector = f"CVSS:{version}/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        expected = float(_oracle(version, *combo))
        if cvss.base_score(vector) != expected:
            mismatches.append((vector, cvss.base_score(vector), expected))
    assert mismatches == []


# --------------------------------------------------------------------------- property tests
_VALID_TOKENS = ["AV:N", "AV:L", "AC:H", "AC:L", "PR:L", "PR:N", "UI:R", "UI:N", "S:C", "S:U",
                 "C:H", "C:N", "I:L", "I:H", "A:N", "A:H", "E:U", "RL:O", "MAV:X"]
_INVALID_TOKENS = ["AV:Z", "XX:N", "av:n", "", "C:X", "S:X", "A", ":", "E:Q", "AV:N:N"]
_BASE = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


@hsettings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_arbitrary_text_never_raises(text):
    result = cvss.score_vector(text)
    assert result is None or 0.0 <= result.base_score <= 10.0


@hsettings(max_examples=400, deadline=None)
@given(st.lists(st.sampled_from(_VALID_TOKENS + _INVALID_TOKENS), max_size=14))
def test_vector_validity_property(tokens):
    result = cvss.score_vector("CVSS:3.1/" + "/".join(tokens))
    names = [t.split(":")[0] for t in tokens]
    valid = (
        bool(tokens)
        and all(t in _VALID_TOKENS for t in tokens)
        and len(set(names)) == len(names)
        and _BASE <= set(names)
    )
    assert (result is not None) == valid
    if result is not None:
        assert result.rating == cvss.severity_rating(result.base_score)
