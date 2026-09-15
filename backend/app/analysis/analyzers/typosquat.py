"""Typosquatting analyzer.

Designed to flag package names that are suspiciously close to a popular package, using a
combination of:

* **PEP 503 canonicalisation** so ``python-dateutil`` vs ``python_dateutil`` style
  separator tricks are compared fairly and an exact match to the real package is never
  mistaken for a squat,
* **homoglyph / leetspeak folding** so ``c0lorama`` (zero-for-o) is recognised as a
  disguised ``colorama``,
* **Damerau-Levenshtein edit distance** (handles insert/delete/substitute *and*
  transposition — ``reqeusts`` vs ``requests``).

A short edit distance to a popular name — while *not being* that popular name — is one of
the strongest single indicators of a malicious upload. A homoglyph-only difference
(distance 0 after folding) is treated as the most severe case. Comparison is limited to the
bundled popular-package list, so squats of packages outside that list are not flagged.

The finding describes the package *name*, so it has no source location.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "1.1.0"

_DATA = Path(__file__).resolve().parent.parent / "data" / "popular_packages.txt"
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})

# A homoglyph disguise is near-deterministic; larger edit distances collide more often with
# legitimately similar names (e.g. plugin families), so confidence falls with distance.
CONFIDENCE_BY_DISTANCE = {0: 0.9, 1: 0.8, 2: 0.6}


def canonical(name: str) -> str:
    """PEP 503 canonical form (separators collapsed, lowercased) — no homoglyph folding."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def fold(name: str) -> str:
    """Canonical form plus homoglyph/leet folding, for disguise-resistant comparison."""
    return canonical(name).translate(_HOMOGLYPHS)


@lru_cache(maxsize=1)
def _popular() -> dict[str, str]:
    """Return {canonical_name: original_name} for the bundled popular-package list."""
    mapping: dict[str, str] = {}
    if _DATA.exists():
        for line in _DATA.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                mapping[canonical(line)] = line
    return mapping


def damerau_levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Optimal string alignment distance with an early-exit ceiling."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        row_min = max_distance + 1
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
            row_min = min(row_min, d[i][j])
        if row_min > max_distance:
            return max_distance + 1
    return d[la][lb]


class TyposquatAnalyzer(BaseAnalyzer):
    name = "typosquat"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        popular = _popular()  # {canonical: original}
        name_canon = canonical(ctx.name)

        # An exact match to a popular package is the real thing, not a squat.
        if name_canon in popular:
            return []

        name_fold = fold(ctx.name)
        best_target = None
        best_distance = 99
        for _pcanon, original in popular.items():
            dist = damerau_levenshtein(name_fold, fold(original), max_distance=2)
            if dist < best_distance:
                best_distance, best_target = dist, original
                if dist == 0:
                    break

        if best_target is None or best_distance > 2:
            return []

        # distance 0 after folding == homoglyph/leet disguise of the real name.
        if best_distance == 0:
            return [Signal(
                Code.TYPOSQUAT, Severity.critical, 10.0,
                f"Name is a homoglyph/leetspeak disguise of popular package '{best_target}'",
                {"target": best_target, "distance": 0, "kind": "homoglyph",
                 "candidate": ctx.name},
                capability=Capability.TYPOSQUAT,
                confidence=CONFIDENCE_BY_DISTANCE[0],
            )]

        severity = Severity.critical if best_distance == 1 else Severity.high
        weight = 9.0 if best_distance == 1 else 6.0
        return [Signal(
            Code.TYPOSQUAT, severity, weight,
            f"Name is edit-distance {best_distance} from popular package '{best_target}'",
            {"target": best_target, "distance": best_distance, "candidate": ctx.name},
            capability=Capability.TYPOSQUAT,
            confidence=CONFIDENCE_BY_DISTANCE[best_distance],
        )]
