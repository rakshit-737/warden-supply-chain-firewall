"""Typosquatting analyzer (v2).

Designed to flag package names that imitate a popular PyPI project. The scanned name is compared
with a bundled, download-ranked snapshot of the most-downloaded PyPI projects
(``data/popular_packages.txt``; source, retrieval date and licence are recorded in its header and
in ``data/README.md``) and at most one ``TYPOSQUAT`` finding is reported: the strongest
resemblance found. Everything here is pure string processing over the *name*; no package content
is read, so the finding has no source location.

Normalisation
=============

* Names are compared in **PEP 503 canonical form** (lower-case, runs of ``-_.`` collapsed to
  ``-``), so ``Python_DateUtil`` is the same project as ``python-dateutil``.
* A candidate whose canonical name is **in the popular list is never flagged**, and
  ``data/typosquat_allowlist.txt`` suppresses curated legitimate (candidate, target) pairs.
* Input is hostile: at most ``MAX_RAW_NAME_CHARS`` characters are examined, names longer than
  ``MAX_NAME_CHARS`` after canonicalisation are not compared, and names shorter than
  ``MIN_NAME_CHARS`` only take part in the separator/combosquat checks.

Resemblance kinds (``evidence["kind"]``)
========================================

``confusable``
    Any **non-ASCII** name. PyPI project names are ASCII-only (PEP 508), so a non-ASCII name is
    suspicious by itself. The name is folded with Unicode NFKC, NFKD with combining marks and
    format/space characters removed, and a subset of the Unicode confusables table (Cyrillic,
    Greek, Armenian and Latin-extended look-alikes of ASCII letters); the folded skeleton is then
    compared with the popular list using the ASCII checks below. Always ``critical``.
``homoglyph``
    Visual or leetspeak disguise: after folding ``0→o``, ``1→l``, ``rn→m``, ``vv→w`` on both
    names, a capital ``I→l`` on the *case-preserved* candidate, and the one-directional leet digits
    ``3→e 4→a 5→s 7→t`` on the candidate only, the candidate equals a target (``c0lorama``,
    ``jeIlyfish``). A lower-case ``i`` is not folded: it has a dot, and folding it would turn
    ``il``/``li`` transpositions (``matplotilb``) into "disguises". A caller that lower-cases names
    before analysis therefore gets the weaker ``look-alike`` typo grade for such names instead.
``typo``
    **Damerau-Levenshtein** (optimal string alignment) distance 1 -- substitution, insertion,
    deletion or adjacent transposition -- found with a symmetric-deletion index, or distance 2
    against top-1000 targets. Each distance-1 edit is classified by typing mechanism:
    **QWERTY keyboard-adjacent** substitution or insertion, lower-case ``i``/``l`` look-alike
    substitution, doubled key, missed double letter, or transposition.
``separator``
    Same letters, different hyphenation: ``pythondateutil``, ``setup-tools``.
``plural``
    Trailing ``s``/``es`` added or removed (``request`` vs ``requests``).
``combosquat``
    A popular name combined with a **generic token** -- prefixes ``python-``, ``python3-``,
    ``py-``, ``py3-``; suffixes ``-python``, ``-python3``, ``-py``, ``-py3``, ``-dev``, ``-lib``,
    ``-sdk``, ``-api``, ``-client``, ``-utils``, ``-util``, ``-tools``, ``-tool``, ``-core``,
    ``-plus``, ``-pro``, ``-new``, ``-latest``, ``-secure``; or a trailing ``2``/``3``
    (``requests-api``, ``py-dateutil``). *Adding* any generic token counts; *removing* or
    *swapping* one counts only for language markers (``python-``, ``py-``, ``-python``, ``-py`` and
    their ``3`` forms) and version digits, because dropping a vendor affix usually names the
    umbrella project (``localstack`` vs ``localstack-client``). A trailing-digit edit (``gitdb2``,
    ``urllib`` vs ``urllib3``) or a digit-for-digit substitution is reported here with operation
    ``version-suffix`` / ``version-variant`` rather than as a typo. A name in a framework plugin
    namespace (``flask-``, ``django-``, ``pytest-``, ``sphinx-``, ``types-``, ``mypy-``, ``jupyter-``,
    ``apache-airflow-providers-``, ... see ``PLUGIN_NAMESPACES``) is never treated as a combosquat
    unless the part after the namespace is itself a generic token (``pytest-utils`` resembles
    ``pytest``; ``flask-requests`` is a plugin, not a squat).
``similar``
    **Jaro-Winkler** similarity >= 0.93 at edit distance exactly 3 from a top-500 target, for names
    of at least 8 characters that do not share a hyphen-delimited family prefix with it.

Length-aware thresholds and edit shape
======================================

The *effective length* of a pair is the shorter name's length after removing a shared
hyphen-delimited family prefix (``azure-mgmt-``, ``google-cloud-``, ``pytest-``, ...), so siblings
in a family are judged on the part that differs.

* effective length <= 4 (``SHORT_NAME_MAX``): distance 1 only against **top-1000** targets, only
  with a typing mechanism and never at the first letter; short names collide by chance.
* effective length 5: without a typing mechanism at most 0.65; 0.85 needs a mechanism.
* first-letter edits (``grequests``, ``willow``/``pillow``), and last-letter or family-member edits
  without a typing mechanism (``torchx``, ``google-cloud-filestore``), are common *naming*
  patterns rather than typing errors, so they only earn a weak grade.
* ranks 1001-5000: distance-1 edits are flagged only when they have a typing mechanism.
* distance 2: effective length >= 8 against top-1000 targets, or >= 6 against top-100 targets,
  and only for scattered edits -- names that differ in the first letter, in one contiguous block
  of at most two characters, or only in their last three characters are skipped
  (``jupyterhub``/``jupyterlab``, ``watchgod``/``watchdog``, ``pandasai``/``pandas``). The same
  shape filter applies to Jaro-Winkler.

Confidence and popularity weighting
===================================

``confidence`` expresses how likely the resemblance is to be deliberate; closer imitations of more
popular targets score higher (tiers: rank <= 100, <= 500, <= 1000, <= 5000).

================================  ============  ============  ============  ============
kind (grade)                      top-100       101-500       501-1000      1001-5000
================================  ============  ============  ============  ============
confusable, target via fold       0.90 crit 10  0.90 crit 10  0.90 crit 10  0.90 crit 10
confusable, no target             0.80 crit 9 (any non-ASCII name)
homoglyph                         0.90 crit 10  0.90 crit 10  0.90 crit 10  0.90 crit 10
typo d1, typing mechanism         0.85 crit 9   0.85 crit 9   0.75 high 7   0.60 high 5
typo d1, no mechanism             0.85 crit 9   0.85 crit 9   0.65 high 6   --
typo d1, effective length 5       0.65 high 5   0.65 high 5   0.55 med 4    --
typo d1, first/last/family edit   0.55 med 4    0.55 med 4    0.50 med 3    --
typo d1, effective length <= 4    0.65 high 5   0.60 high 5   0.55 med 4    --
typo d2                           0.60 high 6   0.55 med 4    0.50 med 3    --
separator                         0.80 high 7   0.75 high 6   0.60 med 4    --
plural                            0.65 high 5   0.60 med 4    0.55 med 4    --
combosquat, version suffix        0.60 med 4    0.55 med 4    0.50 med 3    --
similar (Jaro-Winkler)            0.55 med 3    0.50 med 3    --            --
================================  ============  ============  ============  ============

(``crit``/``high``/``med`` = severity, followed by the rule-score weight; ``--`` = not flagged.) A
confusable whose skeleton resembles a target only through a typo, separator or plural match scores
0.85. The policy engine gates capability blocks on confidence >= 0.7, so by default only
confusables, homoglyphs, distance-1 typos of top-500 targets (plus typing-mechanism typos of top-1000
targets) and hyphenation games on top-500 targets can hard-block.

Evidence: ``candidate``, ``canonical``, ``kind``, ``target``, ``target_rank``, ``distance``
(OSA distance between canonical names; 0 for homoglyph/confusable folds), ``similarity``
(Jaro-Winkler, when computed), ``operation`` and kind-specific details, plus up to three
``other_targets``.

Performance
===========

Target data is indexed once per process (symmetric-deletion neighbourhoods for distance 1, glyph
skeletons, hyphen-free forms, generic-affix cores, and length-bucketed bigram sets for the top
1000). A single analysis then does a bounded number of dictionary lookups plus at most a few
hundred bigram-set intersections, typically well under 20 ms. The bigram prefilter for distance 2
is exact (k edits remove at most 3k distinct bigrams); the Dice >= 0.5 prefilter for Jaro-Winkler
is a heuristic that can, in rare cases, skip a pair scoring >= 0.93.

Limitations
===========

Only targets in the bundled snapshot are protected; squats of less popular projects, of
non-PyPI ecosystems, or of namespace-less brand names are not detected. Download rank is a proxy
for impact, not a trust signal. Legitimate projects with near names exist (see the allowlist and
the measured false-positive rate in ``data/README.md``), which is why most kinds carry confidence
below the default policy blocking threshold.
"""

from __future__ import annotations

import os
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ToolStatus
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "2.0.0"

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
POPULAR_PATH = DATA_DIR / "popular_packages.txt"
ALLOWLIST_PATH = DATA_DIR / "typosquat_allowlist.txt"
_DATA = POPULAR_PATH  # v1 name

MAX_RAW_NAME_CHARS = 4096
MAX_NAME_CHARS = 214
MAX_TARGETS = 20_000
MAX_DATA_FILE_BYTES = 4 * 1024 * 1024
MAX_HEADER_LINES = 64
MIN_NAME_CHARS = 3
SHORT_NAME_MAX = 4
SHORT_NAME_MAX_RANK = 1000
NEAR_MAX_RANK = 1000  # distance-2 and Jaro-Winkler comparisons use only the top-1000 targets
DISTANCE2_MIN_EFFECTIVE = 8
DISTANCE2_TOP100_MIN_EFFECTIVE = 6
JARO_WINKLER_THRESHOLD = 0.93
JARO_WINKLER_MIN_LEN = 8
JARO_WINKLER_MIN_DICE = 0.5
SIMILAR_MAX_RANK = 500
MAX_COMPARE_CHARS = 512
MAX_OTHER_TARGETS = 3
MAX_NON_ASCII_EVIDENCE = 8

_SEP_RE = re.compile(r"[-_.]+")
_VALID_CANONICAL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_HEADER_RE = re.compile(r"#\s*([a-z][a-z0-9-]{0,40}):\s*(.{0,300})$")

# v1 leet folding (kept for ``fold``).
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
# Visual confusions applied to both sides (bidirectional) ...
_GLYPH_FOLD = str.maketrans({"0": "o", "1": "l"})
_GLYPH_MULTI = (("rn", "m"), ("vv", "w"))
# ... a capital I standing in for a lower-case l, which only the case-preserved candidate can show (a
# lower-case i has a dot, so "matplotilb" is a transposition, not a disguise) ...
_UPPER_GLYPH_FOLD = str.maketrans({"I": "l"})
# ... while a lower-case i/l substitution is only a weaker "look-alike" typing mechanism for the typo check.
_LOOKALIKE_PAIRS: frozenset[frozenset[str]] = frozenset({frozenset("il")})
# ... and leetspeak digits applied to the candidate only (a target's real digit is not a disguise).
_LEET_FOLD = str.maketrans({"3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

# Subset of Unicode confusables (UTS #39) mapping look-alikes of ASCII letters, lower-cased.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
    "п": "n", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ү": "y", "һ": "h", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ӏ": "l", "ɡ": "g", "г": "r",
    "А": "a", "В": "b", "Е": "e", "З": "3", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c",
    "Т": "t", "У": "y", "Х": "x", "Ѕ": "s", "І": "i", "Ј": "j", "Ү": "y", "Һ": "h", "Ԁ": "d", "Ԛ": "q",
    "Ԝ": "w", "Ӏ": "l",
    # Greek
    "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c", "ϳ": "j",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x", "Ϲ": "c",
    # Armenian
    "օ": "o", "ս": "u", "հ": "h", "ո": "n", "ց": "g", "զ": "q",
    # Latin extended / IPA
    "ı": "i", "ȷ": "j", "ɩ": "i", "ʟ": "l", "ᴏ": "o", "ɑ": "a", "ǀ": "l", "ł": "l", "ø": "o", "đ": "d",
    "ħ": "h", "ŧ": "t", "ƅ": "b",
})
_DROP_CATEGORIES = frozenset({"Mn", "Me", "Cf", "Cc", "Zs", "Zl", "Zp"})

_KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

GENERIC_PREFIXES: tuple[str, ...] = ("python3-", "python-", "py3-", "py-")
GENERIC_SUFFIXES: tuple[str, ...] = (
    "-python3", "-python", "-py3", "-py", "-dev", "-lib", "-sdk", "-api", "-client", "-utils", "-util",
    "-tools", "-tool", "-core", "-plus", "-pro", "-new", "-latest", "-secure",
)
TRAILING_DIGITS: tuple[str, ...] = ("2", "3")
# Tokens that only say "this is the Python flavour"; swapping or dropping them is a combosquat.
LANGUAGE_MARKERS: frozenset[str] = frozenset(
    {"python-", "python3-", "py-", "py3-", "-python", "-python3", "-py", "-py3"})
GENERIC_TOKENS: frozenset[str] = frozenset(
    [p.strip("-") for p in GENERIC_PREFIXES] + [s.strip("-") for s in GENERIC_SUFFIXES]
)
MIN_CORE_CHARS = 4
# Framework / vendor plugin namespaces: "<namespace><thing>" names a plugin or member of a family.
PLUGIN_NAMESPACES: tuple[str, ...] = (
    "apache-airflow-providers-", "opentelemetry-instrumentation-", "opentelemetry-exporter-", "djangorestframework-",
    "sphinxcontrib-", "jupyterlab-", "jupyter-", "mypy-boto3-", "types-aiobotocore-", "types-", "mypy-",
    "flask-", "django-", "drf-", "pytest-", "sphinx-", "pylint-", "flake8-", "mkdocs-", "napari-", "dagster-",
    "prefect-", "llama-index-", "langchain-", "azure-mgmt-", "azure-", "google-cloud-", "aws-cdk-", "backports-",
    "pyobjc-framework-", "tree-sitter-", "odoo-addon-", "xstatic-", "collective-", "plone-", "zope-",
    "pre-commit-", "poetry-", "hatch-", "setuptools-", "sentry-", "airflow-", "dbt-", "opentelemetry-",
    "ckanext-", "datasette-", "fastapi-", "pydantic-", "sqlalchemy-", "celery-", "tox-", "nox-", "streamlit-",
    "wagtail-", "pyramid-", "starlette-", "aiohttp-", "tensorflow-", "torch-", "keras-", "ansible-",
)

_KIND_ORDER = {"confusable": 0, "homoglyph": 1, "typo": 2, "separator": 3, "plural": 4, "combosquat": 5,
               "similar": 6}
_C, _H, _M = Severity.critical, Severity.high, Severity.medium
# kind -> grade per popularity tier (rank <= 100, <= 500, <= 1000, other); None = not flagged.
_GRADES: dict[str, tuple[tuple[float, Severity, float] | None, ...]] = {
    "homoglyph": ((0.9, _C, 10.0),) * 4,
    "typo": ((0.85, _C, 9.0), (0.85, _C, 9.0), (0.65, _H, 6.0), None),
    "typo-mechanism": ((0.85, _C, 9.0), (0.85, _C, 9.0), (0.75, _H, 7.0), (0.6, _H, 5.0)),
    "typo-5": ((0.65, _H, 5.0), (0.65, _H, 5.0), (0.55, _M, 4.0), None),
    "typo-edge": ((0.55, _M, 4.0), (0.55, _M, 4.0), (0.5, _M, 3.0), None),
    "typo-short": ((0.65, _H, 5.0), (0.6, _H, 5.0), (0.55, _M, 4.0), None),
    "typo2": ((0.6, _H, 6.0), (0.55, _M, 4.0), (0.5, _M, 3.0), None),
    "separator": ((0.8, _H, 7.0), (0.75, _H, 6.0), (0.6, _M, 4.0), None),
    "plural": ((0.65, _H, 5.0), (0.6, _M, 4.0), (0.55, _M, 4.0), None),
    "combosquat": ((0.6, _M, 4.0), (0.55, _M, 4.0), (0.5, _M, 3.0), None),
    "similar": ((0.55, _M, 3.0), (0.5, _M, 3.0), None, None),
}
CONFUSABLE_TARGET_GRADE = (0.9, _C, 10.0)
CONFUSABLE_WEAK_TARGET_GRADE = (0.85, _C, 10.0)
CONFUSABLE_NO_TARGET_GRADE = (0.8, _C, 9.0)
_CONFUSABLE_INNER_KINDS = frozenset({"homoglyph", "typo", "separator", "plural"})


# --------------------------------------------------------------------------- normalisation
def canonical(name: str) -> str:
    """PEP 503 canonical form (separators collapsed, lowercased) -- no homoglyph folding."""
    return _SEP_RE.sub("-", name.strip().lower())


def fold(name: str) -> str:
    """v1 helper: canonical form plus leetspeak folding."""
    return canonical(name).translate(_HOMOGLYPHS)


def glyph_skeleton(canon: str) -> str:
    """Fold visual confusions (``rn→m``, ``vv→w``, ``0→o``, ``1→l``) of a canonical name."""
    s = canon
    for seq, repl in _GLYPH_MULTI:
        s = s.replace(seq, repl)
    return s.translate(_GLYPH_FOLD)


def confusable_skeleton(name: str) -> str:
    """ASCII-ward skeleton of a (possibly non-ASCII) name: NFKC, NFKD minus marks/format, confusables."""
    s = unicodedata.normalize("NFKC", name[:MAX_RAW_NAME_CHARS])
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) not in _DROP_CATEGORIES)
    return s.translate(_CONFUSABLES)


def _keyboard_positions() -> dict[str, tuple[int, int]]:
    return {ch: (r, c) for r, row in enumerate(_KEYBOARD_ROWS) for c, ch in enumerate(row)}


_KEY_POS = _keyboard_positions()


def keyboard_adjacent(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` are neighbouring keys on a US QWERTY layout (staggered rows)."""
    pa, pb = _KEY_POS.get(a), _KEY_POS.get(b)
    if pa is None or pb is None or a == b:
        return False
    (ra, ca), (rb, cb) = pa, pb
    if ra == rb:
        return abs(ca - cb) == 1
    if rb == ra - 1:  # b is on the row above a: same column or one to the right
        return cb in (ca, ca + 1)
    if rb == ra + 1:  # b is on the row below a: same column or one to the left
        return cb in (ca - 1, ca)
    return False


# --------------------------------------------------------------------------- string metrics
def damerau_levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Optimal string alignment distance, returning ``max_distance + 1`` once it is exceeded.

    Inputs longer than ``MAX_COMPARE_CHARS`` are not compared (unless equal) to bound work.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_distance or la > MAX_COMPARE_CHARS or lb > MAX_COMPARE_CHARS:
        return max_distance + 1
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = i
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
            if v < row_min:
                row_min = v
        if row_min > max_distance:
            return max_distance + 1
        prev2, prev = prev, cur
    return min(prev[lb], max_distance + 1)


def jaro_winkler(a: str, b: str, *, prefix_scale: float = 0.1, max_prefix: int = 4) -> float:
    """Jaro-Winkler similarity in [0, 1] (standard definition, prefix bonus up to 4 characters)."""
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb or la > MAX_COMPARE_CHARS or lb > MAX_COMPARE_CHARS:
        return 0.0
    window = max(0, max(la, lb) // 2 - 1)
    used = [False] * lb
    a_chars: list[str] = []
    for i, ch in enumerate(a):
        for j in range(max(0, i - window), min(lb, i + window + 1)):
            if not used[j] and b[j] == ch:
                used[j] = True
                a_chars.append(ch)
                break
    m = len(a_chars)
    if not m:
        return 0.0
    b_chars = [b[j] for j in range(lb) if used[j]]
    transpositions = sum(1 for x, y in zip(a_chars, b_chars) if x != y) / 2
    jaro = (m / la + m / lb + (m - transpositions) / m) / 3
    prefix = 0
    for x, y in zip(a[:max_prefix], b[:max_prefix]):
        if x != y:
            break
        prefix += 1
    return jaro + prefix * prefix_scale * (1 - jaro)


def single_edit(candidate: str, target: str) -> tuple[str, int, str, str] | None:
    """Describe a distance-1 OSA edit turning ``target`` into ``candidate``, or None.

    Returns ``(operation, index, candidate_char, target_char)`` with operation one of
    ``substitution``, ``transposition``, ``insertion`` (extra char in the candidate) or
    ``deletion`` (char missing from the candidate).
    """
    lc, lt = len(candidate), len(target)
    if candidate == target or abs(lc - lt) > 1:
        return None
    i = len(os.path.commonprefix((candidate, target)))
    if lc == lt:
        if candidate[i + 1:] == target[i + 1:]:
            return ("substitution", i, candidate[i], target[i])
        if (i + 1 < lc and candidate[i] == target[i + 1] and candidate[i + 1] == target[i]
                and candidate[i + 2:] == target[i + 2:]):
            return ("transposition", i, candidate[i: i + 2], target[i: i + 2])
        return None
    if lc == lt + 1:
        return ("insertion", i, candidate[i], "") if candidate[i + 1:] == target[i:] else None
    return ("deletion", i, "", target[i]) if candidate[i:] == target[i + 1:] else None


def _typing_mechanism(op: tuple[str, int, str, str], candidate: str, target: str) -> str | None:
    kind, i, cch, tch = op
    if kind == "transposition":
        return "transposition"
    if kind == "substitution":
        if keyboard_adjacent(cch, tch):
            return "keyboard-adjacent"
        # A lower-case i/l swap still looks alike (digit look-alikes are handled by the homoglyph fold).
        return "look-alike" if frozenset((cch, tch)) in _LOOKALIKE_PAIRS else None
    if kind == "insertion":
        neighbours = [candidate[k] for k in (i - 1, i + 1) if 0 <= k < len(candidate)]
        if cch in neighbours:
            return "doubled-key"
        if any(keyboard_adjacent(cch, n) for n in neighbours):
            return "keyboard-adjacent"
        return None
    if (i > 0 and target[i - 1] == tch) or (i + 1 < len(target) and target[i + 1] == tch):
        return "missed-double"
    return None


def _bigrams(s: str) -> frozenset[str]:
    return frozenset(s[i: i + 2] for i in range(len(s) - 1))


def _family_prefix(a: str, b: str) -> str:
    """Longest shared hyphen-terminated prefix, when both names continue past it."""
    common = os.path.commonprefix((a, b))
    cut = common.rfind("-")
    if cut <= 0:
        return ""
    prefix = common[: cut + 1]
    return prefix if len(a) > len(prefix) and len(b) > len(prefix) else ""


def _edit_span(a: str, b: str) -> tuple[int, int, int]:
    """``(common_prefix, differing_span_a, differing_span_b)`` after removing common prefix and suffix."""
    prefix = len(os.path.commonprefix((a, b)))
    room = min(len(a), len(b)) - prefix
    suffix = 0
    while suffix < room and a[len(a) - 1 - suffix] == b[len(b) - 1 - suffix]:
        suffix += 1
    return prefix, len(a) - prefix - suffix, len(b) - prefix - suffix


def _typo_like(a: str, b: str) -> bool:
    """False for word-level differences typical of distinct projects rather than typing errors.

    That is: the names differ in their first character, in one contiguous block of at most two
    characters, or only in their last three characters (``jupyterhub``/``jupyterlab``,
    ``watchgod``/``watchdog``, ``pandasai``/``pandas``).
    """
    prefix, span_a, span_b = _edit_span(a, b)
    if prefix == 0 or max(span_a, span_b) <= 2:
        return False
    return prefix < min(len(a), len(b)) - 3


def _delete_keys(s: str) -> set[str]:
    return {s} | {s[:i] + s[i + 1:] for i in range(len(s))}


def plugin_namespace(canon: str) -> str | None:
    for ns in PLUGIN_NAMESPACES:
        if canon.startswith(ns) and len(canon) > len(ns):
            return ns
    return None


def _core_ok(core: str) -> bool:
    return len(core.replace("-", "")) >= MIN_CORE_CHARS and bool(_VALID_CANONICAL_RE.fullmatch(core))


def generic_decompositions(canon: str) -> list[tuple[str, str, str]]:
    """``(core, prefix, suffix)`` splits of a canonical name around generic tokens (identity first)."""
    out = [(canon, "", "")]
    prefixes = [""] + [p for p in GENERIC_PREFIXES if canon.startswith(p)]
    for prefix in prefixes:
        rest = canon[len(prefix):]
        suffixes = [""] + [s for s in GENERIC_SUFFIXES if rest.endswith(s) and len(rest) > len(s)]
        if len(rest) > 1 and rest[-1] in TRAILING_DIGITS and not rest[-2].isdigit():
            suffixes.append(rest[-1])
        for suffix in suffixes:
            if not prefix and not suffix:
                continue
            core = (rest[: len(rest) - len(suffix)] if suffix else rest).strip("-")
            if _core_ok(core) and (core, prefix, suffix) not in out:
                out.append((core, prefix, suffix))
    return out


# --------------------------------------------------------------------------- target index
@dataclass(frozen=True, eq=False)
class TargetIndex:
    """Immutable lookup structures over a ranked list of canonical target names."""

    ranks: dict[str, int]
    deletes: dict[str, tuple[str, ...]]
    skeletons: dict[str, tuple[str, ...]]
    nosep: dict[str, tuple[str, ...]]
    cores: dict[str, tuple[tuple[str, str, str], ...]]
    near: dict[int, tuple[tuple[str, int, frozenset[str]], ...]]
    metadata: dict[str, str] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.ranks)

    def rank(self, name: str) -> int | None:
        return self.ranks.get(canonical(name))

    @classmethod
    def build(cls, names: Iterable[str], metadata: dict[str, str] | None = None) -> TargetIndex:
        ranks: dict[str, int] = {}
        for raw in names:
            if len(ranks) >= MAX_TARGETS:
                break
            canon = canonical(str(raw))
            if len(canon) > MAX_NAME_CHARS or not _VALID_CANONICAL_RE.fullmatch(canon) or canon in ranks:
                continue
            ranks[canon] = len(ranks) + 1
        deletes: dict[str, list[str]] = defaultdict(list)
        skeletons: dict[str, list[str]] = defaultdict(list)
        nosep: dict[str, list[str]] = defaultdict(list)
        cores: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        near: dict[int, list[tuple[str, int, frozenset[str]]]] = defaultdict(list)
        for canon, rank in ranks.items():  # rank order, so every bucket lists better ranks first
            if len(canon) >= MIN_NAME_CHARS:
                for key in _delete_keys(canon):
                    deletes[key].append(canon)
                skeletons[glyph_skeleton(canon)].append(canon)
            nosep[canon.replace("-", "")].append(canon)
            for core, prefix, suffix in generic_decompositions(canon):
                cores[core].append((canon, prefix, suffix))
            if rank <= NEAR_MAX_RANK and len(canon) >= DISTANCE2_TOP100_MIN_EFFECTIVE:
                near[len(canon)].append((canon, rank, _bigrams(canon)))
        return cls(
            ranks=ranks,
            deletes={k: tuple(v) for k, v in deletes.items()},
            skeletons={k: tuple(v) for k, v in skeletons.items()},
            nosep={k: tuple(v) for k, v in nosep.items()},
            cores={k: tuple(v) for k, v in cores.items()},
            near={k: tuple(v) for k, v in near.items()},
            metadata=dict(metadata or {}),
        )


def _read_capped(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_DATA_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_DATA_FILE_BYTES:
        data = data[: data.rfind(b"\n", 0, MAX_DATA_FILE_BYTES) + 1]  # drop the cut-off partial line
    return data.decode("utf-8", errors="replace")


def parse_popular_text(text: str) -> tuple[list[str], dict[str, str]]:
    """Names (file order = rank order) and ``# key: value`` header metadata of a popular list."""
    names: list[str] = []
    metadata: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            match = _HEADER_RE.match(line) if lineno < MAX_HEADER_LINES else None
            if match and match.group(1) not in metadata:
                metadata[match.group(1)] = match.group(2).strip()
            continue
        names.append(line)
        if len(names) >= MAX_TARGETS:
            break
    return names, metadata


@dataclass(frozen=True)
class AllowlistEntry:
    candidate: str
    target: str
    justification: str


def parse_allowlist_text(text: str) -> list[AllowlistEntry]:
    """``candidate target  # justification`` lines; entries without a justification are ignored."""
    entries: list[AllowlistEntry] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body, _, justification = stripped.partition("#")
        parts = body.split()
        if len(parts) != 2 or not justification.strip():
            continue
        entries.append(AllowlistEntry(canonical(parts[0]), canonical(parts[1]), justification.strip()))
    return entries


@lru_cache(maxsize=1)
def default_index() -> TargetIndex:
    text = _read_capped(POPULAR_PATH)
    if text is None:
        return TargetIndex.build(())
    names, metadata = parse_popular_text(text)
    return TargetIndex.build(names, metadata)


@lru_cache(maxsize=1)
def default_allowlist() -> frozenset[tuple[str, str]]:
    text = _read_capped(ALLOWLIST_PATH)
    if text is None:
        return frozenset()
    return frozenset((e.candidate, e.target) for e in parse_allowlist_text(text))


def reload_data() -> None:
    """Drop cached target/allowlist data (after the data files change)."""
    default_index.cache_clear()
    default_allowlist.cache_clear()


def _popular() -> dict[str, str]:
    """v1 helper: ``{canonical_name: canonical_name}`` for the bundled popular list."""
    return {name: name for name in default_index().ranks}


# --------------------------------------------------------------------------- matching
@dataclass(frozen=True)
class Match:
    kind: str
    target: str | None
    target_rank: int | None
    confidence: float
    severity: Severity
    weight: float
    distance: int | None = None
    similarity: float | None = None
    operation: str | None = None
    details: tuple[tuple[str, object], ...] = ()

    def sort_key(self) -> tuple:
        return (
            -self.confidence, -self.weight, self.target_rank or 10**9,
            99 if self.distance is None else self.distance, _KIND_ORDER.get(self.kind, 99), self.target or "",
        )


def _tier(rank: int) -> int:
    return 0 if rank <= 100 else 1 if rank <= 500 else 2 if rank <= 1000 else 3


class _Collector:
    """Keeps the strongest match per target."""

    def __init__(self) -> None:
        self.best: dict[str, Match] = {}

    def offer(self, grade_key: str, kind: str, target: str, rank: int, **kw: object) -> None:
        grade = _GRADES[grade_key][_tier(rank)]
        if grade is None:
            return
        confidence, severity, weight = grade
        match = Match(kind, target, rank, confidence, severity, weight, **kw)  # type: ignore[arg-type]
        current = self.best.get(target)
        if current is None or match.sort_key() < current.sort_key():
            self.best[target] = match


def _match_homoglyph(canon: str, idx: TargetIndex, out: _Collector, raw: str | None = None) -> None:
    variants = {canon, canon.translate(_LEET_FOLD)}
    if raw is not None and "I" in raw:
        upper_folded = canonical(raw.translate(_UPPER_GLYPH_FOLD))
        if len(upper_folded) == len(canon):
            variants |= {upper_folded, upper_folded.translate(_LEET_FOLD)}
    for key in sorted({glyph_skeleton(v) for v in variants}):
        for target in idx.skeletons.get(key, ()):
            if target == canon:
                continue
            raw_distance = damerau_levenshtein(canon, target, max_distance=3)
            if raw_distance > 3:
                continue
            out.offer("homoglyph", "homoglyph", target, idx.ranks[target], distance=0, operation="glyph-fold",
                      details=(("raw_distance", raw_distance),))


def _match_distance_one(canon: str, idx: TargetIndex, out: _Collector) -> None:
    seen: set[str] = set()
    for key in sorted(_delete_keys(canon)):
        for target in idx.deletes.get(key, ()):
            if target in seen or target == canon:
                continue
            seen.add(target)
            op = single_edit(canon, target)
            if op is None:
                continue
            kind, pos, cch, tch = op
            if "-" in (cch, tch):
                continue  # hyphenation changes are the separator check's business
            rank = idx.ranks[target]
            family = _family_prefix(canon, target)
            effective = min(len(canon), len(target)) - len(family)
            mechanism = _typing_mechanism(op, canon, target)
            appended = kind == "insertion" and pos == len(target)
            dropped_last = kind == "deletion" and pos == len(canon)
            end_edit = appended or dropped_last or (kind == "substitution" and pos == len(canon) - 1)
            first_letter = pos == 0 and kind != "transposition"
            details: tuple[tuple[str, object], ...] = (
                ("edit_position", pos), ("typing_mechanism", mechanism), ("effective_length", effective))
            if family:
                details += (("family_prefix", family),)
            if (appended and cch == "s" and not target.endswith("s")) or (
                    dropped_last and tch == "s" and not canon.endswith("s")):
                operation = "plural-added" if appended else "plural-removed"
                out.offer("plural", "plural", target, rank, distance=1, operation=operation, details=details)
            elif (appended and cch.isdigit()) or (dropped_last and tch.isdigit()) or (
                    kind == "substitution" and cch.isdigit() and tch.isdigit()):
                # "name2" / "name3": version-suffixed forks and successors are a naming convention.
                operation = "version-variant" if kind == "substitution" else "version-suffix"
                out.offer("combosquat", "combosquat", target, rank, distance=1, operation=operation, details=details)
            elif effective <= SHORT_NAME_MAX:
                if rank > SHORT_NAME_MAX_RANK or mechanism is None or first_letter:
                    continue
                out.offer("typo-short", "typo", target, rank, distance=1, operation=kind, details=details)
            elif first_letter or (mechanism is None and (end_edit or family)):
                # First-letter changes, and unexplained last-letter or family-member changes, are common
                # naming patterns (grequests, torchx, google-cloud-filestore): weak evidence only.
                out.offer("typo-edge", "typo", target, rank, distance=1, operation=kind, details=details)
            elif mechanism is not None:
                out.offer("typo-mechanism", "typo", target, rank, distance=1, operation=kind, details=details)
            elif effective == SHORT_NAME_MAX + 1:
                out.offer("typo-5", "typo", target, rank, distance=1, operation=kind, details=details)
            else:
                out.offer("typo", "typo", target, rank, distance=1, operation=kind, details=details)


def _match_plural_es(canon: str, idx: TargetIndex, out: _Collector) -> None:
    pairs = []
    if canon.endswith("es") and len(canon) - 2 >= MIN_CORE_CHARS:
        pairs.append((canon[:-2], "plural-added"))
    if len(canon) >= MIN_CORE_CHARS:
        pairs.append((canon + "es", "plural-removed"))
    for target, operation in pairs:
        rank = idx.ranks.get(target)
        if rank is None or (min(len(canon), len(target)) <= SHORT_NAME_MAX and rank > SHORT_NAME_MAX_RANK):
            continue
        out.offer("plural", "plural", target, rank, distance=2, operation=operation, details=(("suffix", "es"),))


def _match_separator(canon: str, idx: TargetIndex, out: _Collector) -> None:
    key = canon.replace("-", "")
    if len(key) < MIN_CORE_CHARS:
        return
    for target in idx.nosep.get(key, ()):
        if target == canon:
            continue
        ours, theirs = canon.count("-"), target.count("-")
        operation = "separator-removed" if ours < theirs else "separator-added" if ours > theirs else "separator-moved"
        distance = damerau_levenshtein(canon, target, max_distance=6)
        out.offer("separator", "separator", target, idx.ranks[target], distance=distance, operation=operation)


def _match_combosquat(canon: str, idx: TargetIndex, out: _Collector) -> None:
    namespace = plugin_namespace(canon)
    if namespace and canon[len(namespace):] not in GENERIC_TOKENS:
        return  # a framework plugin ("flask-requests"), not a combination squat
    for core, prefix, suffix in generic_decompositions(canon):
        for target, t_prefix, t_suffix in idx.cores.get(core, ()):
            if target == canon:
                continue
            ours, theirs = bool(prefix or suffix), bool(t_prefix or t_suffix)
            if ours and not theirs:
                operation, distance = "affix-added", len(canon) - len(target)
            elif theirs and not ours:
                # Dropping a vendor affix ("localstack" vs "localstack-client") usually names the umbrella
                # project; only dropping a language marker or version digit imitates the target.
                if not all(a in LANGUAGE_MARKERS or a in TRAILING_DIGITS for a in (t_prefix, t_suffix) if a):
                    continue
                operation, distance = "affix-removed", len(target) - len(canon)
            elif ours and theirs:
                if not all(a in LANGUAGE_MARKERS for a in (prefix, suffix, t_prefix, t_suffix) if a):
                    continue
                operation, distance = "affix-changed", damerau_levenshtein(canon, target, max_distance=12)
            else:
                continue
            affix = {"added": [prefix, suffix], "removed": [t_prefix, t_suffix]}
            details = (("core", core), ("affix", {k: [a for a in v if a] for k, v in affix.items()}))
            out.offer("combosquat", "combosquat", target, idx.ranks[target], distance=distance,
                      operation=operation, details=details)


def _match_near(canon: str, idx: TargetIndex, out: _Collector) -> None:
    """Distance-2 and Jaro-Winkler comparisons against top-1000 targets of similar length."""
    length = len(canon)
    if length < DISTANCE2_TOP100_MIN_EFFECTIVE:
        return
    ours = _bigrams(canon)
    for bucket in range(length - 3, length + 4):
        for target, rank, theirs in idx.near.get(bucket, ()):
            if target == canon or target in out.best:
                continue
            if canon.startswith(target + "-") or target.startswith(canon + "-"):
                continue  # a namespace member of the target (or vice versa), not a misspelling
            family = _family_prefix(canon, target)
            effective = min(length, len(target)) - len(family)
            common = len(ours & theirs)
            distance: int | None = None
            if abs(length - len(target)) <= 2 and (
                effective >= DISTANCE2_MIN_EFFECTIVE or (effective >= DISTANCE2_TOP100_MIN_EFFECTIVE and rank <= 100)
            ) and common >= max(len(ours), len(theirs)) - 6:
                distance = damerau_levenshtein(canon, target, max_distance=2)
                if distance == 2 and not _typo_like(canon, target):
                    continue
                if distance == 2:
                    details: tuple[tuple[str, object], ...] = (("effective_length", effective),)
                    if family:
                        details += (("family_prefix", family),)
                    out.offer("typo2", "typo", target, rank, distance=2, operation="edit-distance-2", details=details)
                    continue
                if distance < 2:
                    continue
            if family or length < JARO_WINKLER_MIN_LEN or len(target) < JARO_WINKLER_MIN_LEN:
                continue
            if 2 * common < JARO_WINKLER_MIN_DICE * (len(ours) + len(theirs)):
                continue
            if rank > SIMILAR_MAX_RANK or not _typo_like(canon, target):
                continue
            similarity = jaro_winkler(canon, target)
            if similarity < JARO_WINKLER_THRESHOLD:
                continue
            distance = damerau_levenshtein(canon, target, max_distance=3)
            if distance != 3:
                continue
            out.offer("similar", "similar", target, rank, distance=distance, similarity=round(similarity, 4),
                      operation="jaro-winkler")


def _ascii_matches(canon: str, idx: TargetIndex, raw: str | None = None) -> list[Match]:
    """Resemblances of an ASCII canonical name; ``raw`` (case-preserved) enables the capital-I fold."""
    out = _Collector()
    if len(canon) >= MIN_NAME_CHARS:
        _match_homoglyph(canon, idx, out, raw)
        _match_distance_one(canon, idx, out)
        _match_plural_es(canon, idx, out)
    _match_separator(canon, idx, out)
    _match_combosquat(canon, idx, out)
    if len(canon) >= MIN_NAME_CHARS:
        _match_near(canon, idx, out)
    return sorted(out.best.values(), key=Match.sort_key)


def _confusable_match(raw: str, idx: TargetIndex) -> Match:
    non_ascii = sorted({f"U+{ord(ch):04X}" for ch in raw if ord(ch) > 127})
    skeleton = confusable_skeleton(raw)
    details: list[tuple[str, object]] = [
        ("non_ascii", non_ascii[:MAX_NON_ASCII_EVIDENCE]), ("non_ascii_count", len(non_ascii))]
    if skeleton.isascii():
        canon = canonical(skeleton)
        details.append(("skeleton", canon[:100]))
        if canon and len(canon) <= MAX_NAME_CHARS:
            if canon in idx.ranks:
                conf, sev, weight = CONFUSABLE_TARGET_GRADE
                return Match("confusable", canon, idx.ranks[canon], conf, sev, weight, distance=0,
                             operation="unicode-fold", details=tuple(details + [("resembles", "exact")]))
            inner = [m for m in _ascii_matches(canon, idx) if m.kind in _CONFUSABLE_INNER_KINDS]
            if inner:
                best = inner[0]
                strong = best.kind == "homoglyph"
                conf, sev, weight = CONFUSABLE_TARGET_GRADE if strong else CONFUSABLE_WEAK_TARGET_GRADE
                return Match("confusable", best.target, best.target_rank, conf, sev, weight,
                             distance=best.distance, similarity=best.similarity, operation="unicode-fold",
                             details=tuple(details + [("resembles", best.kind)]))
    conf, sev, weight = CONFUSABLE_NO_TARGET_GRADE
    return Match("confusable", None, None, conf, sev, weight, operation="non-ascii-name", details=tuple(details))


def find_matches(
    name: object,
    *,
    index: TargetIndex | None = None,
    allowlist: frozenset[tuple[str, str]] | None = None,
) -> list[Match]:
    """All resemblances of ``name`` to popular targets, strongest first (one per target)."""
    idx = index if index is not None else default_index()
    allowed = allowlist if allowlist is not None else default_allowlist()
    raw = name if isinstance(name, str) else ("" if name is None else str(name))
    raw = raw[:MAX_RAW_NAME_CHARS].strip()
    if not raw:
        return []
    if not raw.isascii():
        return [_confusable_match(raw, idx)]
    canon = canonical(raw)
    if not canon or len(canon) > MAX_NAME_CHARS or canon in idx.ranks:
        return []
    return [m for m in _ascii_matches(canon, idx, raw) if (canon, m.target) not in allowed]


# --------------------------------------------------------------------------- analyzer
_KIND_TEXT = {
    "homoglyph": "is a homoglyph/leetspeak disguise of",
    "typo": "is a likely misspelling of",
    "separator": "differs only in hyphenation from",
    "plural": "is a singular/plural variant of",
    "combosquat": "combines a generic token with",
    "similar": "is very similar to",
}


def _message(candidate: str, match: Match) -> str:
    if match.kind == "confusable":
        if match.target is None:
            return f"Name '{candidate}' contains non-ASCII characters, which PyPI project names cannot contain"
        return (f"Name '{candidate}' uses non-ASCII look-alike characters to imitate popular package "
                f"'{match.target}' (download rank {match.target_rank})")
    what = _KIND_TEXT.get(match.kind, "resembles")
    extra = ""
    if match.kind == "typo" and match.distance is not None:
        extra = f" (edit distance {match.distance}, {match.operation})"
    elif match.similarity is not None:
        extra = f" (Jaro-Winkler {match.similarity:.2f})"
    return f"Name '{candidate}' {what} popular package '{match.target}' (download rank {match.target_rank}){extra}"


def build_finding(candidate: str, matches: list[Match], idx: TargetIndex | None = None) -> Signal:
    best = matches[0]
    shown = candidate[:MAX_NAME_CHARS]
    evidence: dict[str, object] = {
        "candidate": shown,
        "canonical": canonical(shown) if shown.isascii() else None,
        "kind": best.kind,
        "target": best.target,
        "target_rank": best.target_rank,
        "distance": best.distance,
        "similarity": best.similarity,
        "operation": best.operation,
    }
    evidence.update({k: v for k, v in best.details if v is not None})
    others = [m.target for m in matches[1:] if m.target][:MAX_OTHER_TARGETS]
    if others:
        evidence["other_targets"] = others
    if idx is not None and idx.metadata.get("retrieved"):
        evidence["target_list"] = {"size": len(idx), "retrieved": idx.metadata["retrieved"][:32]}
    return Signal(
        Code.TYPOSQUAT, best.severity, best.weight, _message(shown, best), evidence,
        capability=Capability.TYPOSQUAT, confidence=best.confidence,
    )


class TyposquatAnalyzer(BaseAnalyzer):
    """Name-similarity analyzer over a ranked popular-package snapshot (see module docstring)."""

    name = "typosquat"
    version = ANALYZER_VERSION

    def __init__(self, index: TargetIndex | None = None,
                 allowlist: frozenset[tuple[str, str]] | None = None) -> None:
        self._index = index
        self._allowlist = allowlist

    def _targets(self) -> TargetIndex:
        return self._index if self._index is not None else default_index()

    def availability(self) -> ToolStatus:
        idx = self._targets()
        if not len(idx):
            return ToolStatus(name=self.name, available=False, version=self.version,
                              detail="popular package list is missing or empty")
        retrieved = idx.metadata.get("retrieved")
        detail = f"{len(idx)} targets" + (f", retrieved {retrieved[:32]}" if retrieved else "")
        return ToolStatus(name=self.name, available=True, version=self.version, detail=detail)

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        idx = self._targets()
        if not len(idx):
            raise RuntimeError("typosquat target list is unavailable")
        allowlist = self._allowlist if self._allowlist is not None else default_allowlist()
        raw = ctx.name if isinstance(ctx.name, str) else ("" if ctx.name is None else str(ctx.name))
        raw = raw[:MAX_RAW_NAME_CHARS].strip()
        matches = find_matches(raw, index=idx, allowlist=allowlist)
        if not matches:
            return []
        return [build_finding(raw, matches, idx)]
